"""
JSAnalyzer module for BBAT.
Analyzes JavaScript files for hidden endpoints, API keys, secrets,
and sensitive patterns.
"""

import re
import requests
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Patterns for secret detection
SECRET_PATTERNS = {
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"[0-9a-zA-Z/+]{40}",
    "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
    "GitHub OAuth Token": r"gho_[a-zA-Z0-9]{36}",
    "Slack Token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,10}/[a-zA-Z0-9_]{24}",
    "AWS Access Key (alt)": r"A[SK]IA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Firebase Database URL": r"https://[a-z0-9_-]+\.firebaseio\.com",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Twilio Account SID": r"AC[0-9a-fA-F]{32}",
    "SendGrid API Key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
    "Heroku API Key": r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
    "Basic Auth Header": r"Basic\s+[a-zA-Z0-9+/=]{20,}",
    "Bearer Token": r"Bearer\s+[a-zA-Z0-9_\-\.]+",
    "Private Key (PEM)": r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Generic API Key": r"[aA][pP][iI][_\-\.]?[kK][eE][yY][_\-\.]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{16,}['\"]?",
    "Generic Secret": r"[sS][eE][cC][rR][eE][tT][_\-\.]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{16,}['\"]?",
    "Password/Passphrase": r"[pP][aA][sS][sS][wW][oO][rR][dD][_\-\.]?\s*[:=]\s*['\"]?[a-zA-Z0-9!@#$%^&*]{8,}['\"]?",
    "Cloudflare API Key": r"[0-9a-f]{37}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\\-_]{43}",
    "Square Access Token": r"sqOatp-[0-9A-Za-z\\-_]{22,}",
    "PayPal Braintree Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Picatic API Key": r"sk_live_[0-9a-z]{32}",
    "NPM Token": r"npm_[a-zA-Z0-9]{36}",
    "Docker Registry Auth": r"[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}",
    "Artifactory API Key": r"AKCp8[a-zA-Z0-9]{32,}",
}

# URL patterns inside JS
ENDPOINT_PATTERNS = [
    r'["\']((?:\/|https?:\/\/)[a-zA-Z0-9_\-\/.:]{2,}[a-zA-Z0-9_\-]{2,})["\']',
    r'["\'](\/api\/v[0-9]+\/[^"\']+)["\']',
    r'["\'](\/[^"\']*\.[a-zA-Z0-9]{2,5})["\']',
    r'["\']([a-zA-Z0-9_\-/]+/(?:graphql|rest|api|internal|private|public|health|status|metrics|swagger|docs|openapi))["\']',
]


class JSAnalyzerModule:
    """Analyzes JavaScript files for endpoints and secrets."""

    def __init__(self, config: dict):
        self.config = config.get("js_analyzer", {})
        self.headers = {
            "User-Agent": config.get("recon", {}).get("user_agent", "BBAT/1.0")
        }

    def fetch_js(self, url: str) -> str:
        """Fetch JavaScript content from URL."""
        try:
            resp = requests.get(url, headers=self.headers, timeout=15, verify=False)
            if resp.status_code == 200 and "javascript" in resp.headers.get("Content-Type", "").lower():
                return resp.text
            if url.endswith(".js"):
                return resp.text
        except requests.RequestException:
            pass
        return ""

    def find_secrets(self, js_content: str, source: str = "") -> List[Dict]:
        """Find potential secrets in JS content."""
        findings = []
        for name, pattern in SECRET_PATTERNS.items():
            matches = set(re.findall(pattern, js_content))
            for match in matches:
                findings.append({
                    "type": "secret",
                    "name": name,
                    "match": match if len(match) < 100 else match[:100] + "...",
                    "source": source,
                    "severity": "critical" if "Private Key" in name or "Secret" in name else "high",
                })
        return findings

    def find_endpoints(self, js_content: str, base_url: str = "") -> List[Dict]:
        """Find API endpoints and URLs in JS content."""
        endpoints = set()
        for pattern in ENDPOINT_PATTERNS:
            found = re.findall(pattern, js_content)
            for match in found:
                if match.startswith("/") and base_url:
                    endpoints.add(urljoin(base_url, match))
                else:
                    endpoints.add(match)

        return [{
            "type": "endpoint",
            "url": ep,
            "source": base_url,
        } for ep in sorted(endpoints)]

    def analyze_urls(self, js_urls: List[str]) -> Dict:
        """Analyze a list of JavaScript URLs."""
        all_secrets = []
        all_endpoints = []
        print(f"[*] Analyzing {len(js_urls)} JS files...")

        for js_url in js_urls:
            content = self.fetch_js(js_url)
            if not content:
                continue
            secrets = self.find_secrets(content, source=js_url)
            endpoints = self.find_endpoints(content, base_url=js_url)
            all_secrets.extend(secrets)
            all_endpoints.extend(endpoints)

        print(f"[+] JS analysis complete. Found {len(all_secrets)} secrets, {len(all_endpoints)} endpoints.")
        return {
            "total_files": len(js_urls),
            "secrets": all_secrets,
            "endpoints": all_endpoints,
            "secrets_count": len(all_secrets),
            "endpoints_count": len(all_endpoints),
        }
