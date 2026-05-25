"""
Wayback module for BBAT.
Fetches historical URLs from the Internet Archive (archive.org).
"""

import requests
import json
from typing import List, Dict, Set
from urllib.parse import urlparse

WAYBACK_URL = "http://web.archive.org/cdx/search/cdx"


class WaybackModule:
    """Fetches URLs from Wayback Machine for a target domain."""

    def __init__(self, config: dict):
        self.config = config.get("wayback", {})
        self.timeout = self.config.get("timeout", 60)
        self.user_agent = config.get("recon", {}).get("user_agent", "BBAT/1.0")

    def fetch_urls(self, domain: str, match_subdomains: bool = True) -> List[Dict]:
        """Fetch historical URLs from Wayback Machine."""
        query = f"*.{domain}" if match_subdomains else domain
        params = {
            "url": query,
            "fl": "original",
            "collapse": "urlkey",
            "output": "json",
        }
        print(f"[*] Querying Wayback Machine for {query}...")

        try:
            resp = requests.get(
                WAYBACK_URL,
                params=params,
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent}
            )
            if resp.status_code != 200:
                return [{"error": f"Wayback returned {resp.status_code}", "domain": domain}]

            data = resp.json()
            urls = set()
            for row in data[1:]:  # skip header
                if row:
                    urls.add(row[0])

            # Try with status filter to get more endpoints
            params["filter"] = "statuscode:200"
            resp2 = requests.get(
                WAYBACK_URL,
                params=params,
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent}
            )
            if resp2.status_code == 200:
                data2 = resp2.json()
                for row in data2[1:]:
                    if row:
                        urls.add(row[0])

            print(f"[+] Wayback Machine query complete. Found {len(urls)} unique URLs.")
            return sorted(list(urls))
        except requests.RequestException as e:
            return [{"error": str(e), "domain": domain}]
        except json.JSONDecodeError as e:
            return [{"error": f"Invalid JSON: {e}", "domain": domain}]
