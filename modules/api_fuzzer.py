"""
ApiFuzzer module for BBAT.
Discovers and fuzzes REST/GraphQL endpoints from OpenAPI/Swagger specs.
"""

import requests
import json
import re
from urllib.parse import urljoin
from typing import List, Dict
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

COMMON_API_ENDPOINTS = [
    "/v1/users", "/v2/users", "/api/users", "/api/v1/users", "/api/v2/users",
    "/v1/accounts", "/v2/accounts", "/api/accounts",
    "/v1/auth", "/v2/auth", "/api/auth", "/api/v1/auth",
    "/v1/login", "/v2/login", "/api/login",
    "/v1/register", "/api/register",
    "/v1/admin", "/api/admin",
    "/v1/products", "/api/products",
    "/v1/orders", "/api/orders",
    "/v1/items", "/api/items",
    "/v1/search", "/api/search",
    "/v1/upload", "/api/upload",
    "/v1/files", "/api/files",
    "/v1/media", "/api/media",
    "/graphql", "/api/graphql", "/v1/graphql",
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/v1", "/rest/v2",
    "/internal", "/internal/api", "/internal/v1",
    "/private", "/private/api",
    "/public", "/public/api",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]


class ApiFuzzerModule:
    """Discovers and fuzzes API endpoints."""

    def __init__(self, config: dict):
        self.config = config.get("api_fuzzer", {})
        self.headers = {
            "User-Agent": config.get("recon", {}).get("user_agent", "BBAT/1.0"),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.timeout = self.config.get("timeout", 10)

    def discover_endpoints(self, base_url: str) -> List[Dict]:
        """Brute-force common API endpoints."""
        found = []
        print(f"[*] Brute-forcing API endpoints on {base_url}...")
        for endpoint in COMMON_API_ENDPOINTS:
            url = urljoin(base_url, endpoint)
            try:
                resp = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=False)
                if resp.status_code not in (404, 410, 500):
                    content_type = resp.headers.get("Content-Type", "")
                    content_length = len(resp.content)
                    found.append({
                        "url": url,
                        "status_code": resp.status_code,
                        "content_type": content_type,
                        "content_length": content_length,
                        "method": "GET",
                    })
            except requests.RequestException:
                pass
        print(f"[+] API discovery complete. Found {len(found)} endpoints.")
        return found

    def fuzz_methods(self, endpoints: List[str]) -> List[Dict]:
        """Test different HTTP methods on discovered endpoints."""
        results = []
        for url in endpoints:
            allowed = []
            for method in HTTP_METHODS:
                try:
                    if method == "GET":
                        resp = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=False)
                    elif method == "POST":
                        resp = requests.post(url, headers=self.headers, data="{}", timeout=self.timeout, verify=False, allow_redirects=False)
                    elif method == "PUT":
                        resp = requests.put(url, headers=self.headers, data="{}", timeout=self.timeout, verify=False, allow_redirects=False)
                    elif method == "DELETE":
                        resp = requests.delete(url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=False)
                    elif method == "PATCH":
                        resp = requests.patch(url, headers=self.headers, data="{}", timeout=self.timeout, verify=False, allow_redirects=False)
                    else:
                        resp = requests.options(url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=False)

                    if resp.status_code not in (404, 405, 501):
                        allowed.append({
                            "method": method,
                            "status_code": resp.status_code,
                            "content_length": len(resp.content),
                        })
                except requests.RequestException:
                    pass
            if allowed:
                results.append({"url": url, "allowed_methods": allowed})
        return results

    def test_idor(self, base_endpoint: str) -> List[Dict]:
        """Basic Insecure Direct Object Reference (IDOR) tests."""
        print(f"[*] Testing IDOR on {base_endpoint}...")
        findings = []
        test_ids = ["1", "2", "3", "0", "-1", "99999", "1'", "1 AND 1=1"]
        for test_id in test_ids:
            url = base_endpoint.rstrip("/") + "/" + test_id
            try:
                resp = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
                if resp.status_code == 200:
                    findings.append({
                        "url": url,
                        "test_id": test_id,
                        "status_code": resp.status_code,
                        "content_length": len(resp.text),
                        "type": "idor_test",
                    })
            except requests.RequestException:
                pass
        print(f"[+] IDOR testing complete. Found {len(findings)} accessible paths.")
        return findings

    def scan(self, target: str, idor_test: bool = True) -> Dict:
        """Run full API fuzzing scan."""
        from modules.utils import normalize_url
        base = normalize_url(target)
        endpoints = self.discover_endpoints(base)
        urls = [e["url"] for e in endpoints]
        method_results = self.fuzz_methods(urls)

        idor_results = []
        if idor_test and urls:
            idor_results = self.test_idor(urls[0])

        return {
            "target": target,
            "endpoints_discovered": len(endpoints),
            "endpoints": endpoints,
            "method_fuzzing": method_results,
            "idor_tests": idor_results,
        }
