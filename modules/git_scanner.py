"""
GitScanner module for BBAT.
Checks for exposed .git directories and source code repositories using async I/O.
"""

import httpx
from urllib.parse import urljoin
from typing import List, Dict
from modules.utils import get_random_ua

EXPOSED_PATHS = [
    ".git/HEAD", ".git/config", ".git/logs/HEAD", ".git/index",
    ".svn/wc.db", ".svn/entries", ".hg/hgrc", ".bzr/README",
    "CVS/Root", ".env", ".env.local", ".env.dev", ".env.production",
    "config.php.bak", "database.yml", "wp-config.php.bak",
    ".DS_Store", "server-status", "phpinfo.php", "phpinfo",
    ".htaccess", ".htpasswd", ".ftpconfig", ".vscode/settings.json",
    ".idea/workspace.xml", ".swp", ".swo",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".ssh/authorized_keys", ".ssh/config", ".ssh/id_rsa",
    "backup.sql", "dump.sql", "database.sql",
]


class GitScannerModule:
    """Scans for exposed source control directories and sensitive files using httpx."""

    def __init__(self, config: dict):
        self.config = config.get("git_scanner", {})
        self.timeout = self.config.get("timeout", 10)
        self._ssl = config.get("recon", {}).get("ssl_verify", False)

    def check_path(self, base_url: str, path: str) -> Dict:
        """Check if a specific path is exposed."""
        url = urljoin(base_url, path)
        try:
            resp = httpx.get(url, headers={"User-Agent": get_random_ua()}, timeout=self.timeout, verify=self._ssl, follow_redirects=False)
            if resp.status_code == 200:
                return {
                    "url": url, "status_code": resp.status_code, "accessible": True,
                    "content_type": resp.headers.get("Content-Type", ""), "size": len(resp.content),
                    "sensitive": self._is_sensitive(path),
                }
        except Exception:
            pass
        return {"url": url, "status_code": None, "accessible": False}

    def _is_sensitive(self, path: str) -> bool:
        sensitive_keywords = [".env", "id_rsa", ".ssh", "wp-config", "htpasswd", "config.php", "database", ".ftpconfig", "backup.sql"]
        return any(kw in path.lower() for kw in sensitive_keywords)

    def scan(self, target: str) -> List[Dict]:
        """Scan a target for exposed repositories and sensitive files using async engine."""
        from modules.utils import normalize_url
        from modules.async_engine import AsyncEngine
        base = normalize_url(target)
        print(f"[*] Scanning for exposed repositories and sensitive files on {base}...")

        # Use AsyncEngine for high-speed parallel checks
        urls = [urljoin(base, p) for p in EXPOSED_PATHS]
        engine = AsyncEngine(self.config)
        results = engine.run(urls)

        findings = []
        for result in results:
            if result.get("status") == 200:
                parsed_path = result["url"].replace(base, "")
                findings.append({
                    "url": result["url"],
                    "status_code": result["status"],
                    "accessible": True,
                    "content_type": result.get("headers", {}).get("content-type", ""),
                    "size": result.get("content_length", 0),
                    "sensitive": self._is_sensitive(parsed_path),
                })

        print(f"[+] Git-scan complete. Found {len(findings)} exposed paths.")
        return findings
