"""
CTLog module for BBAT.
Fetches subdomains from Certificate Transparency logs via crt.sh.
"""

import httpx
from typing import List
from modules.utils import get_random_ua

CRTS_SH_API = "https://crt.sh/?q=%.{domain}&output=json"


class CTLogModule:
    """Certificate Transparency log subdomain discovery."""

    def __init__(self, config: dict):
        self.config = config.get("ctlog", {})
        self.timeout = self.config.get("timeout", 30)
        self.ssl_verify = config.get("recon", {}).get("ssl_verify", False)

    def fetch_subdomains(self, domain: str) -> List[str]:
        """Fetch subdomains from crt.sh. Always returns List[str]."""
        subdomains = set()
        url = CRTS_SH_API.replace("{domain}", domain)
        print(f"[*] Querying Certificate Transparency logs for {domain}...")

        try:
            resp = httpx.get(url, headers={"User-Agent": get_random_ua()}, timeout=self.timeout, verify=self.ssl_verify)
            if resp.status_code != 200:
                print(f"[!] crt.sh returned status {resp.status_code}")
                return []
            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "").strip()
                if name:
                    for sub in name.split("\n"):
                        sub = sub.strip()
                        if sub:
                            subdomains.add(sub)
        except httpx.TimeoutException:
            print(f"[!] crt.sh timed out after {self.timeout}s")
        except Exception as e:
            print(f"[!] crt.sh error: {e}")

        print(f"[+] CT log query complete. Found {len(subdomains)} unique subdomains.")
        return sorted(list(subdomains))
