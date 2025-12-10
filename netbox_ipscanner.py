import os
import socket
import ipaddress
import urllib3
import pynetbox
import networkscan

from extras.scripts import Script

NETBOX_URL_ENV = "NETBOX_URL"
NETBOX_TOKEN_ENV = "NETBOX_TOKEN"
DEFAULT_NETBOX_URL = ""

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class IpScan(Script):
    class Meta:
        name = "IP Scanner"
        description = "Scans available prefixes and updates ip addresses in IPAM Module"

    def run(self, data, commit):
        nb_url = os.getenv(NETBOX_URL_ENV, DEFAULT_NETBOX_URL).strip()
        nb_token = os.getenv(NETBOX_TOKEN_ENV, "").strip()

        if not nb_token:
            self.log_failure(
                f"Variable d'environnement {NETBOX_TOKEN_ENV} absente : impossible de continuer."
            )
            return
        if not nb_url:
            self.log_failure("URL NetBox manquante (NETBOX_URL).")
            return

        nb = pynetbox.api(nb_url, token=nb_token)
        nb.http_session.verify = False

        dns_cache: dict[str, str] = {}

        def reverse_lookup(ip: str) -> str:
            """DNS reverse lookup avec échec contrôlé et mise en cache."""
            if ip in dns_cache:
                return dns_cache[ip]
            try:
                host, _, _ = socket.gethostbyaddr(ip)
                dns_cache[ip] = host or ""
            except Exception:
                dns_cache[ip] = ""
            return dns_cache[ip]

        def norm_ip(ip_str: str) -> str:
            """
            Normalise une IP en string canonique.
            Retourne '' si invalide.
            """
            try:
                return str(ipaddress.ip_address(ip_str.strip()))
            except Exception:
                return ""

        def update_ips(payload: list[dict], desc: str) -> bool:
            """Met à jour des IPs en respectant le mode dry-run."""
            if not payload:
                return True
            if not commit:
                self.log_info(f"[DRY-RUN] {desc}")
                return True
            try:
                res = nb.ipam.ip_addresses.update(payload)
                if not res:
                    self.log_error(f"Update refusé: {desc}")
                    return False
                return True
            except Exception as exc:
                self.log_error(f"Erreur lors de {desc}: {exc}")
                return False

        def create_ip(kwargs: dict, desc: str) -> bool:
            """Crée une IP en respectant le mode dry-run."""
            if not commit:
                self.log_info(f"[DRY-RUN] {desc}")
                return True
            try:
                res = nb.ipam.ip_addresses.create(**kwargs)
                if not res:
                    self.log_error(f"Création refusée: {desc}")
                    return False
                return True
            except Exception as exc:
                self.log_error(f"Erreur création {kwargs.get('address')}: {exc}")
                return False

        subnets = nb.ipam.prefixes.all()

        for subnet in subnets:
            prefix_str = str(subnet.prefix)

            status_slug = (
                getattr(getattr(subnet, "status", None), "value", "") or ""
            ).lower()
            if status_slug in {"reserved", "container"}:
                self.log_warning(f"Scan de {prefix_str} NON fait (status={status_slug})")
                continue

            # IPv4 only
            try:
                ipv4_network = ipaddress.IPv4Network(prefix_str)
            except ValueError:
                self.log_warning(f"Prefix {prefix_str} ignoré (pas IPv4 valide)")
                continue

            mask = f"/{ipv4_network.prefixlen}"

            # Scan réseau
            try:
                scan = networkscan.Networkscan(prefix_str)
                scan.run()
            except Exception as exc:
                self.log_error(f"Scan de {prefix_str} impossible: {exc}")
                continue

            self.log_info(f"Scan de {prefix_str} terminé.")

            # Normalisation des IP vivantes
            raw_alive = scan.list_of_hosts_found or []
            alive_hosts = set(filter(None, (norm_ip(h) for h in raw_alive)))

            # Extraction NetBox -> dict IP sans masque
            netbox_addresses = {}
            filter_kwargs = {"parent": prefix_str}
            vrf_id = getattr(getattr(subnet, "vrf", None), "id", None)
            if vrf_id:
                filter_kwargs["vrf_id"] = vrf_id
            for ip in nb.ipam.ip_addresses.filter(**filter_kwargs):
                ip_no_mask = norm_ip(str(ip.address).split("/")[0])
                if ip_no_mask:
                    netbox_addresses[ip_no_mask] = ip

            self.log_debug(
                f"{prefix_str}: NetBox={len(netbox_addresses)} IPs, Alive={len(alive_hosts)} IPs"
            )

            # Deprecated : IP NetBox non vivante
            deprecated_count = 0
            for address in ipv4_network.hosts():
                address_str = str(address)
                nb_ip = netbox_addresses.get(address_str)

                if nb_ip is not None and address_str not in alive_hosts:
                    if update_ips(
                        [{"id": nb_ip.id, "status": "deprecated"}],
                        f"{prefix_str}: {nb_ip.address} -> deprecated",
                    ):
                        deprecated_count += 1

            self.log_info(f"{prefix_str}: {deprecated_count} IPs passées deprecated")

            if not alive_hosts:
                self.log_warning(f"Aucun host trouvé sur {prefix_str}")
                continue

            self.log_success(f"IPs trouvées: {sorted(alive_hosts)}")

            # Traitement IP vivantes
            activated_count = 0
            dns_updates = 0
            created_count = 0

            for alive in alive_hosts:
                current = netbox_addresses.get(alive)

                if current is not None:
                    # Remettre active si besoin
                    current_status = getattr(current.status, "value", None)
                    if current_status != "active":
                        if update_ips(
                            [{"id": current.id, "status": "active"}],
                            f"{prefix_str}: {current.address} -> active",
                        ):
                            activated_count += 1

                    # Sync DNS (ne pas écraser avec une valeur vide)
                    name = reverse_lookup(alive)
                    current_dns = (current.dns_name or "").strip()
                    if name and current_dns.lower() != name.lower():
                        if update_ips(
                            [{"id": current.id, "dns_name": name}],
                            f"{prefix_str}: DNS {current_dns or '-'} -> {name}",
                        ):
                            dns_updates += 1

                else:
                    # Nouvelle IP vivante -> création
                    name = reverse_lookup(alive)
                    ip_mask = f"{alive}{mask}"
                    payload = {"address": ip_mask, "status": "active"}
                    if name:
                        payload["dns_name"] = name
                    if vrf_id:
                        payload["vrf"] = vrf_id

                    if create_ip(payload, f"{prefix_str}: ajout {ip_mask} ({name or 'sans nom'})"):
                        created_count += 1

            self.log_info(
                f"{prefix_str}: {activated_count} réactivées, {dns_updates} DNS mis à jour, "
                f"{created_count} créées"
            )
