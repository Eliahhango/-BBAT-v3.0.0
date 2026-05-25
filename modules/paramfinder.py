"""
ParamFinder module for BBAT.
Discovers GET/POST parameters and checks for reflection vulnerabilities.
"""

import requests
import urllib.parse
from typing import List, Dict
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common parameters to test
COMMON_PARAMS = [
    "id", "page", "user", "name", "search", "q", "query", "cat", "category",
    "type", "action", "view", "do", "cmd", "exec", "callback", "redirect",
    "url", "next", "return", "return_to", "ref", "src", "dest", "destination",
    "path", "dir", "file", "filename", "document", "folder", "root", "base",
    "host", "ip", "domain", "port", "lang", "language", "locale", "format",
    "mode", "status", "state", "code", "token", "key", "api_key", "secret",
    "email", "phone", "message", "comment", "subject", "body", "content", "data",
    "xml", "json", "html", "text", "output", "response", "result", "value",
    "amount", "price", "cost", "quantity", "limit", "offset", "start", "end",
    "date", "time", "year", "month", "day", "hour", "minute", "second",
    "version", "v", "edition", "release", "build", "patch", "update",
    "debug", "test", "dev", "staging", "sandbox", "mode", "env", "environment",
]

PAYLOADS = [
    "BBAT_TEST_12345",
    "<script>alert('BBAT_XSS')</script>",
    "' OR '1'='1",
    "../../../etc/passwd",
    "{{7*7}}",
]


class ParamFinderModule:
    """Discovers and tests URL parameters for reflection."""

    def __init__(self, config: dict):
        self.config = config.get("paramfinder", {})
        self.headers = {
            "User-Agent": config.get("recon", {}).get("user_agent", "BBAT/1.0")
        }
        self.timeout = self.config.get("timeout", 10)

    def _inject_param(self, base_url: str, param: str, payload: str) -> Dict:
        """Inject a parameter into a URL and check for reflection."""
        parsed = urllib.parse.urlparse(base_url)
        query = urllib.parse.parse_qs(parsed.query)
        query[param] = [payload]
        new_query = urllib.parse.urlencode(query, doseq=True)
        new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

        try:
            resp = requests.get(new_url, headers=self.headers, timeout=self.timeout, verify=False)
            reflected = payload in resp.text
            return {
                "url": new_url,
                "param": param,
                "payload": payload,
                "status_code": resp.status_code,
                "reflected": reflected,
                "response_length": len(resp.text),
            }
        except requests.RequestException as e:
            return {
                "url": new_url,
                "param": param,
                "payload": payload,
                "error": str(e),
                "reflected": False,
            }

    def find_params(self, urls: List[str]) -> List[Dict]:
        """Discover which URLs accept common parameters."""
        print(f"[*] Testing {len(urls)} URLs with {len(COMMON_PARAMS)} common parameters...")
        findings = []
        for url in urls:
            for param in COMMON_PARAMS[:20]:  # Limit for speed
                result = self._inject_param(url, param, "BBAT_TEST_12345")
                if "error" not in result:
                    findings.append(result)
        print(f"[+] Parameter discovery complete. Tested {len(findings)} parameter injections.")
        return findings

    def check_reflection(self, urls: List[str]) -> List[Dict]:
        """Check URLs for reflected XSS payloads."""
        print(f"[*] Checking {len(urls)} URLs for reflection vulnerabilities...")
        findings = []
        for url in urls:
            for param in COMMON_PARAMS[:10]:
                for payload in PAYLOADS:
                    result = self._inject_param(url, param, payload)
                    if result.get("reflected"):
                        findings.append(result)
        print(f"[+] Reflection check complete. Found {len(findings)} reflected payloads.")
        return findings
