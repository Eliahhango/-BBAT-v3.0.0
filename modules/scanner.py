"""
Scanner module for BBAT.
Detects common web vulnerabilities and misconfigurations.
"""

import requests
import json
import urllib3
import urllib.parse
import socket
from urllib.parse import urljoin
from typing import Dict, List, Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ScannerModule:
    """Vulnerability scanner for authorized bug bounty targets."""

    def __init__(self, config: dict):
        self.config = config.get("scanner", {})
        self.headers = {
            "User-Agent": config.get("recon", {}).get("user_agent", "BBAT/1.0")
        }

    def _check_headers(self, url: str) -> List[Dict]:
        """Check for security headers and misconfigurations."""
        findings = []
        try:
            resp = requests.head(url, headers=self.headers, timeout=10, verify=False, allow_redirects=True)
            headers = resp.headers
            expected = {
                "Strict-Transport-Security": "Missing HSTS header",
                "Content-Security-Policy": "Missing CSP header",
                "X-Frame-Options": "Missing X-Frame-Options header (Clickjacking risk)",
                "X-Content-Type-Options": "Missing X-Content-Type-Options header",
                "Referrer-Policy": "Missing Referrer-Policy header",
                "Permissions-Policy": "Missing Permissions-Policy header",
            }
            for header, description in expected.items():
                if header not in headers:
                    findings.append({
                        "type": "missing_header",
                        "header": header,
                        "description": description,
                        "severity": "medium",
                        "url": url,
                    })

            if headers.get("X-Powered-By"):
                findings.append({
                    "type": "info_disclosure",
                    "header": "X-Powered-By",
                    "description": f"Technology disclosure: {headers['X-Powered-By']}",
                    "severity": "low",
                    "url": url,
                })

            if "Server" in headers:
                findings.append({
                    "type": "info_disclosure",
                    "header": "Server",
                    "description": f"Server banner: {headers['Server']}",
                    "severity": "info",
                    "url": url,
                })
        except requests.RequestException as e:
            findings.append({"type": "error", "message": str(e), "url": url})
        return findings

    def _check_ssl(self, url: str) -> List[Dict]:
        """Check SSL/TLS configuration."""
        findings = []
        if url.startswith("https://"):
            try:
                import ssl
                parsed = urllib.parse.urlparse(url)
                hostname = parsed.hostname or parsed.netloc
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        version = ssock.version()
                        if version in ("TLSv1", "TLSv1.1"):
                            findings.append({
                                "type": "weak_tls",
                                "description": f"Weak TLS version: {version}",
                                "severity": "medium",
                                "url": url,
                            })
            except Exception as e:
                findings.append({"type": "ssl_error", "message": str(e), "url": url})
        return findings

    def _check_open_redirect(self, url: str) -> List[Dict]:
        """Check for open redirect vulnerability."""
        findings = []
        test_url = urljoin(url, "/redirect?url=https://evil.com")
        try:
            resp = requests.get(test_url, headers=self.headers, timeout=10, verify=False, allow_redirects=False)
            if resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get("Location", "")
                if "evil.com" in location:
                    findings.append({
                        "type": "open_redirect",
                        "description": f"Open redirect found at {test_url}",
                        "severity": "medium",
                        "url": url,
                    })
        except requests.RequestException:
            pass
        return findings

    def _check_cors(self, url: str) -> List[Dict]:
        """Check for CORS misconfiguration."""
        findings = []
        try:
            test_headers = {
                **self.headers,
                "Origin": "https://evil.com"
            }
            resp = requests.get(url, headers=test_headers, timeout=10, verify=False)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            if "evil.com" in acao:
                if acac.lower() == "true":
                    findings.append({
                        "type": "cors_misconfiguration",
                        "description": "CORS allows arbitrary origin with credentials",
                        "severity": "high",
                        "url": url,
                    })
                else:
                    findings.append({
                        "type": "cors_misconfiguration",
                        "description": "CORS allows arbitrary origin",
                        "severity": "medium",
                        "url": url,
                    })
        except requests.RequestException:
            pass
        return findings

    def scan(self, target: str) -> List[Dict]:
        """Run full vulnerability scan pipeline on a target."""
        from modules.utils import normalize_url
        url = normalize_url(target)
        print(f"[*] Scanning {url}...")

        findings = []
        findings.extend(self._check_headers(url))
        findings.extend(self._check_open_redirect(url))
        findings.extend(self._check_cors(url))

        return {
            "target": target,
            "findings_count": len(findings),
            "findings": findings,
        }
