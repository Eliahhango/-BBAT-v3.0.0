"""
Fuzzer module for BBAT.
Performs directory/file brute-forcing on authorized targets.
"""

import requests
import os
from urllib.parse import urljoin
from typing import List, Dict
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FuzzerModule:
    """Directory and file fuzzer for authorized bug bounty targets."""

    def __init__(self, config: dict):
        self.config = config.get("fuzzer", {})
        self.extensions = self.config.get("extensions", ["txt", "bak", "zip", "tar.gz"])
        self.methods = self.config.get("methods", ["GET"])
        self.headers = {
            "User-Agent": config.get("recon", {}).get("user_agent", "BBAT/1.0")
        }

    def fuzz(self, target: str, wordlist_path: str = None) -> List[Dict]:
        """
        Fuzz directories and files on a target.
        """
        from modules.utils import normalize_url
        base = normalize_url(target)
        wordlist_path = wordlist_path or self.config.get("wordlist", "wordlists/common.txt")

        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            words = [
                "admin", "login", "backup", "test", "api", "debug", "config",
                ".env", "robots.txt", "sitemap.xml", "README", ".git", ".svn"
            ]

        results = []
        print(f"[*] Fuzzing {base} with {len(words)} words...")

        for word in words:
            urls_to_test = [urljoin(base, word)]
            if "." not in word:
                for ext in self.extensions:
                    urls_to_test.append(urljoin(base, f"{word}.{ext}"))

            for url in urls_to_test:
                try:
                    resp = requests.get(url, headers=self.headers, timeout=10, verify=False, allow_redirects=False)
                    if resp.status_code in (200, 403, 301, 302, 307, 401, 500):
                        results.append({
                            "url": url,
                            "status_code": resp.status_code,
                            "content_length": len(resp.content),
                            "method": "GET",
                        })
                except requests.RequestException:
                    pass

        print(f"[+] Fuzzing complete. Found {len(results)} interesting responses.")
        return {
            "target": target,
            "items": results,
            "total_tested": len(words) * (1 + len(self.extensions))
        }
