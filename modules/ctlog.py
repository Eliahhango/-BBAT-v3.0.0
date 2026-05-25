"""
CTLog module for BBAT.
Fetches subdomains from Certificate Transparency logs via crt.sh.
"""

import requests
import json
from typing import List, Dict, Set

CRTS_SH_API = "https://crt.sh/?q=%.{domain}&output=json"


class CTLogModule:
    """Certificate Transparency log subdomain discovery."""

    def __init__(self, config: dict):
        self.config = config.get("ctlog", {})
        self.headers = {
            "User-Agent": config.get("recon", {}).get("user_agent", "BBAT/1.0")
        }
        self.timeout = self.config.get("timeout", 30)

    def fetch_subdomains(self, domain: str) -> List[Dict]:
        """Fetch subdomains from crt.sh for a given domain."""
        subdomains = set()
        url = CRTS_SH_API.replace("{domain}", domain)
        print(f"[*] Querying Certificate Transparency logs for {domain}...")

        try:
            resp = requests.get(url, headers=self.headers, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "").strip()
                    if name:
                        # Handle multi-line entries
                        for sub in name.split("\n"):
                            sub = sub.strip()
                            if sub and sub.endswith(f".{domain}") and sub != domain:
                                subdomains.add(sub)
                            elif sub == domain:
                                subdomains.add(sub)
            else:
                return [{"error": f"crt.sh returned status {resp.status_code}", "domain": domain}]
        except requests.RequestException as e:
            return [{"error": str(e), "domain": domain}]
        except json.JSONDecodeError as e:
            return [{"error": f"Invalid JSON from crt.sh: {e}", "domain": domain}]

        print(f"[+] CT log query complete. Found {len(subdomains)} unique subdomains.")
        return sorted(list(subdomains))
