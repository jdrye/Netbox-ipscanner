import socket
import ipaddress
import urllib3
import pynetbox
import networkscan

from extras.scripts import Script

# TODO: Do not keep the API token hardcoded in production.
# Use an environment variable or a NetBox Script input variable instead.
TOKEN = ""
NETBOXURL = ""

# Disable SSL warnings because we explicitly disable certificate verification below.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class IpScan(Script):
    class Meta:
        name = "IP Scanner"
        description = (
            "Scans prefixes, updates alive IPs, "
            "and frees non-responding IPs (deprecated then deleted)"
        )

    # NetBox Scripts require the (data, commit) signature.
    # We keep it, but we intentionally ignore `commit` to always apply changes.
    def run(self, data, commit):

        def reverse_lookup(ip: str) -> str:
            """
            Perform a DNS reverse lookup (PTR).
            Returns an empty string if no DNS name is found or if lookup fails.
            """
            try:
                host, _, _ = socket.gethostbyaddr(ip)
                return host or ""
            except Exception:
                return ""

        def norm_ip(ip_str: str) -> str:
            """
            Normalize an IP string to a canonical form (e.g., removes spaces,
            ensures proper formatting).
            Returns empty string if invalid.
            """
            try:
                return str(ipaddress.ip_address(ip_str.strip()))
            except Exception:
                return ""

        # Create NetBox API client
        nb = pynetbox.api(NETBOXURL, token=TOKEN)

        # Disable TLS certificate verification (internal NetBox with custom cert)
        nb.http_session.verify = False

        # Retrieve all prefixes from NetBox
        subnets = nb.ipam.prefixes.all()

        # Iterate over every prefix
        for subnet in subnets:
            prefix_str = str(subnet.prefix)

            # Skip prefixes marked as "reserved"
            try:
                if subnet.status and subnet.status.value == "reserved":
                    self.log_warning(f"Scan of {prefix_str} NOT done (reserved)")
                    continue
            except Exception:
                # If status is missing or non-standard, don't block the scan
                pass

            # Only handle valid IPv4 prefixes
            try:
                ipv4_network = ipaddress.IPv4Network(prefix_str)
            except ValueError:
                self.log_warning(f"Prefix {prefix_str} ignored (not valid IPv4)")
                continue

            # Mask to reattach when creating IP objects (e.g. "/24")
            mask = f"/{ipv4_network.prefixlen}"

            # Run ICMP sweep on the prefix
            scan = networkscan.Networkscan(prefix_str)
            scan.run()
            self.log_info(f"Scan of {prefix_str} completed.")

            # Normalize alive hosts list returned by networkscan
            raw_alive = scan.list_of_hosts_found or []
            alive_hosts = set(filter(None, (norm_ip(h) for h in raw_alive)))

            # Build a dict of NetBox IP objects in this prefix.
            # IMPORTANT: key is IP WITHOUT mask to avoid /32 vs /24 mismatches.
            netbox_addresses = {}
            for ip in nb.ipam.ip_addresses.filter(parent=prefix_str):
                ip_no_mask = norm_ip(str(ip.address).split("/")[0])
                if ip_no_mask:
                    netbox_addresses[ip_no_mask] = ip

            # Debug stats
            self.log_debug(
                f"{prefix_str}: NetBox={len(netbox_addresses)} IPs, Alive={len(alive_hosts)} IPs"
            )

            # ---- FREE NON-RESPONDING IPs ----
            # For every IP that exists in NetBox but is not alive:
            #   1) set status to deprecated (traceability)
            #   2) delete it (actually free the address for utilization metrics)
            deprecated_then_deleted = 0

            for address in ipv4_network.hosts():
                address_str = str(address)
                nb_ip = netbox_addresses.get(address_str)

                if nb_ip is not None and address_str not in alive_hosts:
                    self.log_failure(
                        f"{prefix_str}: {nb_ip.address} not responding -> DEPRECATED then DELETED"
                    )

                    # Step 1: mark deprecated
                    try:
                        nb.ipam.ip_addresses.update(
                            [{"id": nb_ip.id, "status": "deprecated"}]
                        )
                    except Exception as e:
                        self.log_error(
                            f"Error setting deprecated for {nb_ip.address}: {e}"
                        )

                    # Step 2: delete the IP object to free it
                    try:
                        nb_ip.delete()
                        deprecated_then_deleted += 1
                    except Exception as e:
                        self.log_error(f"Error deleting {nb_ip.address}: {e}")

            self.log_info(
                f"{prefix_str}: {deprecated_then_deleted} IPs freed (deprecated + delete)"
            )

            # If nothing is alive, stop here for this prefix
            if not alive_hosts:
                self.log_warning(f"No hosts found in {prefix_str}")
                continue

            self.log_success(f"Alive IPs found: {sorted(alive_hosts)}")

            # ---- PROCESS ALIVE IPs ----
            for alive in alive_hosts:
                current = netbox_addresses.get(alive)

                if current is not None:
                    # If the IP exists in NetBox but is not active, reactivate it
                    if current.status and current.status.value != "active":
                        try:
                            nb.ipam.ip_addresses.update(
                                [{"id": current.id, "status": "active"}]
                            )
                        except Exception as e:
                            self.log_error(
                                f"Error setting active for {current.address}: {e}"
                            )

                    # Sync DNS name based on reverse lookup
                    name = reverse_lookup(alive)
                    current_dns = (current.dns_name or "").strip()

                    if current_dns.lower() != name.lower():
                        self.log_success(f"DNS name for {alive} updated -> {name}")
                        try:
                            nb.ipam.ip_addresses.update(
                                [{"id": current.id, "dns_name": name}]
                            )
                        except Exception as e:
                            self.log_error(
                                f"Error updating dns_name for {current.address}: {e}"
                            )

                else:
                    # Alive IP not present in NetBox -> create it as active
                    name = reverse_lookup(alive)
                    ip_mask = f"{alive}{mask}"

                    try:
                        res = nb.ipam.ip_addresses.create(
                            address=ip_mask,
                            status="active",
                            dns_name=name
                        )
                        if res:
                            self.log_success(f"Added {alive} - {name}")
                        else:
                            self.log_error(f"Adding {alive} - {name} FAILED")
                    except Exception as e:
                        self.log_error(f"Error creating {ip_mask}: {e}")
