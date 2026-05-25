"""
GitScanner module for BBAT.
Checks for exposed .git directories and source code repositories.
"""

import requests
from urllib.parse import urljoin
from typing import List, Dict
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

EXPOSED_PATHS = [
    ".git/HEAD",
    ".git/config",
    ".git/logs/HEAD",
    ".git/index",
    ".svn/wc.db",
    ".svn/entries",
    ".hg/hgrc",
    ".bzr/README",
    "CVS/Root",
    ".env",
    ".env.local",
    ".env.dev",
    ".env.test",
    ".env.production",
    "config.php.bak",
    "database.yml",
    "wp-config.php.bak",
    ".DS_Store",
    "WEB-INF/web.xml",
    "server-status",
    "phpinfo.php",
    "phpinfo",
    ".htaccess",
    ".htpasswd",
    ".ftpconfig",
    ".vscode/settings.json",
    ".idea/workspace.xml",
    ".swp",
    ".swo",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".ssh/authorized_keys",
    ".ssh/config",
    ".ssh/id_rsa",
    "backup.sql",
    "dump.sql",
    "database.sql",
]


class GitScannerModule:
    """Scans for exposed source control directories and sensitive files."""

    def __init__(self, config: dict):
        self.config = config.get("git_scanner", {})
        self.headers = {
            "User-Agent": config.get("recon", {}).get("user_agent", "BBAT/1.0")
        }
        self.timeout = self.config.get("timeout", 10)

    def check_path(self, base_url: str, path: str) -> Dict:
        """Check if a specific path is exposed."""
        url = urljoin(base_url, path)
        try:
            resp = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=False)
            if resp.status_code == 200:
                content_type = resp.headers.get("Content-Type", "")
                size = len(resp.content)
                return {
                    "url": url,
                    "status_code": resp.status_code,
                    "accessible": True,
                    "content_type": content_type,
                    "size": size,
                    "sensitive": self._is_sensitive(path),
                }
        except requests.RequestException:
            pass
        return {"url": url, "status_code": None, "accessible": False}

    def _is_sensitive(self, path: str) -> bool:
        """Determine if a path is highly sensitive."""
        sensitive_keywords = [
            ".env", "id_rsa", ".ssh", "wp-config", "htpasswd",
            "config.php", "database", ".ftpconfig", "backup.sql"
        ]
        return any(kw in path.lower() for kw in sensitive_keywords)

    def scan(self, target: str) -> List[Dict]:
        """Scan a target for exposed repositories and sensitive files."""
        from modules.utils import normalize_url
        base = normalize_url(target)
        findings = []
        print(f"[*] Scanning for exposed repositories and sensitive files on {base}...")
        for path in EXPOSED_PATHS:
            result = self.check_path(base, path)
            if result.get("accessible"):
                findings.append(result)
        print(f"[+] Git/source scan complete. Found {len(findings)} exposed paths.")
        return findings
