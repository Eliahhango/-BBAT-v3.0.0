"""
Reconnaissance module for BBAT.
Performs subdomain enumeration, DNS resolution, port scanning, and WHOIS using async I/O.
"""

import socket
from typing import List, Dict
from modules.utils import get_random_ua
from modules.async_engine import AsyncEngine

# Optional dnspython
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class ReconModule:
    """Module handling target reconnaissance with async I/O."""

    def __init__(self, config: dict):
        self.config = config.get("recon", {})
        self.timeout = self.config.get("timeout", 10)
        self.default_wordlist = self.config.get("wordlist", "./wordlists/common.txt")
        self.user_agent = self.config.get("user_agent", get_random_ua)

    @staticmethod
    def _is_valid_dns_label(label: str) -> bool:
        import re
        if not label or len(label) > 63:
            return False
        return bool(re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$", label))

    def enumerate_subdomains(self, domain: str, wordlist_path: str = None) -> List[Dict]:
        """Brute-force subdomain enumeration using async engine."""
        found = []
        wordlist_path = wordlist_path or self.default_wordlist
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            from modules import utils
            words = utils.load_wordlist(wordlist_path) or [
                "www", "mail", "ftp", "admin", "blog", "api", "dev", "staging", "test", "portal"
            ]
        words = [w for w in words if self._is_valid_dns_label(w)]

        # Resolve DNS using dnspython (non-blocking iterator possible via async)
        if DNS_AVAILABLE:
            for word in words:
                subdomain = f"{word}.{domain}"
                try:
                    ans = dns.resolver.resolve(subdomain, "A", lifetime=self.timeout)
                    ip = str(list(ans)[0])
                    found.append({"subdomain": subdomain, "ip": ip})
                except Exception:
                    pass
        else:
            for word in words:
                subdomain = f"{word}.{domain}"
                try:
                    ip = socket.gethostbyname(subdomain)
                    found.append({"subdomain": subdomain, "ip": ip})
                except (socket.gaierror, OSError, UnicodeEncodeError):
                    pass

        return found

    def resolve_dns(self, domain: str) -> Dict:
        """Resolve DNS records for a domain using dnspython if available."""
        records = {}
        if DNS_AVAILABLE:
            record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype, lifetime=self.timeout)
                    records[rtype] = [str(rdata) for rdata in answers]
                except Exception:
                    pass
        else:
            try:
                ip = socket.gethostbyname(domain)
                records["A"] = [ip]
            except (socket.gaierror, OSError) as e:
                records["error"] = str(e)
        return records

    def port_scan(self, target: str, max_ports: int = None) -> List[Dict]:
        """Lightweight TCP port scan on common ports using connect_ex."""
        top_ports = max_ports or self.config.get("port_scan", {}).get("top_ports", 1000)
        timeout = self.config.get("timeout", 3)
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
            3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        open_ports = []
        ports = sorted(common_ports.keys()) if top_ports <= 20 else range(1, min(top_ports + 1, 10001))
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    if sock.connect_ex((target, port)) == 0:
                        service = common_ports.get(port, "unknown")
                        open_ports.append({"port": port, "service": service, "state": "open"})
            except (OSError, socket.error):
                pass
        return open_ports

    def whois_lookup(self, domain: str) -> Dict:
        """Basic WHOIS via python-whois if available."""
        try:
            import whois
            w = whois.whois(domain)
            return {
                "registrar": str(w.registrar) if w.registrar else None,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "name_servers": list(w.name_servers) if w.name_servers else []
            }
        except ImportError:
            return {
                "domain": domain,
                "error": "python-whois not installed. pip install python-whois"
            }
        except Exception as e:
            return {"domain": domain, "error": str(e)}
