"""
Takeover module for BBAT.
Detects subdomain takeover vulnerabilities via provider-specific error fingerprints.
"""

import httpx
from typing import List, Dict

# Known error-body signatures per service
TAKEOVER_FINGERPRINTS = {
    "AWS S3 Bucket": ["NoSuchBucket", "The specified bucket does not exist", "nosuchbucket"],
    "AWS CloudFront": ["Bad Request", "GeneratedByCloudFront"],
    "GitHub Pages": ["There isn't a GitHub Pages site here.", "404 Not Found", "GitHub Pages"],
    "GitLab Pages": ["404 Not Found", "GitLab", "No GitLab Pages site here"],
    "Heroku": ["No such app", "heroku", "There is no app configured at that hostname."],
    "Netlify": ["Not Found", "netlify.app", "Netlify"],
    "Vercel": ["404: Not Found", "vercel.app", "The deployment could not be found on Vercel"],
    "Surge.sh": ["Not Found", "surge.sh", "project not found"],
    "Bitbucket": ["bitbucket.io", "Repository not found", "404"],
    "Fastly": ["Fastly error", "fastly"],
    "Azure Blob": ["BlobNotFound", "The specified blob does not exist.", "azure"],
    "Azure App Service": ["Microsoft Azure", "Error 404 - Web app not found.", "azurewebsites.net"],
    "Azure TrafficManager": ["trafficmanager.net", "tm-frontend"],
    "Firebase": ["Site Not Found", "firebaseapp.com", "Firebase Hosting Setup Complete"],
    "Shopify": ["Sorry, this shop is currently unavailable.", "myshopify.com", "shopify"],
    "Tumblr": ["Not found.", "tumblr.com", "There's nothing here."],
    "Unbounce": ["The requested URL was not found on this server.", "unbouncepages.com"],
    "Pantheon": ["pantheonsite.io", "404"],
    "Acquia Cloud": ["acquia-sites.com", "404"],
    "Zendesk": ["zendesk.com", "Help Center Closed", "Zendesk"],
    "StatusPage": ["statuspage.io", "StatusPage"],
    "Ghost.io": ["ghost.io", "404"],
    "WordPress.com": ["wordpress.com", "Do you want to register"],
    "Cargo Collective": ["cargocollective.com", "404"],
    "WebFlow": ["webflow.io", "The page you are looking for doesn't exist"],
    "Digital Ocean": ["ondigitalocean.app", "404"],
    "ReadMe": ["readme.io", "404"],
    "Kinsta": ["kinsta.cloud", "404"],
    "FlyWheel": ["flywheelsites.com", "404"],
    "GitBook": ["gitbook.io", "404"],
    "Webflow": ["webflow.io", "The page you are looking for doesn't have an associated"],
}

# CNAME indicators (initial triage)
CNAME_INDICATORS = [
    ("AWS S3 Bucket", ".s3.amazonaws.com"),
    ("AWS CloudFront", ".cloudfront.net"),
    ("GitHub Pages", ".github.io"),
    ("GitLab Pages", ".gitlab.io"),
    ("Heroku", ".herokuapp.com"),
    ("Netlify", ".netlify.app"),
    ("Vercel", ".vercel.app"),
    ("Surge.sh", ".surge.sh"),
    ("Bitbucket", ".bitbucket.io"),
    ("Fastly", ".fastly.net"),
    ("Azure Blob", ".blob.core.windows.net"),
    ("Azure App Service", ".azurewebsites.net"),
    ("Azure TrafficManager", ".trafficmanager.net"),
    ("Firebase", ".firebaseapp.com"),
    ("Shopify", ".myshopify.com"),
    ("Tumblr", ".tumblr.com"),
    ("Unbounce", ".unbouncepages.com"),
    ("Pantheon", ".pantheonsite.io"),
    ("Acquia Cloud", ".acquia-sites.com"),
    ("Zendesk", ".zendesk.com"),
    ("StatusPage", ".statuspage.io"),
    ("Ghost.io", ".ghost.io"),
    ("WordPress.com", ".wordpress.com"),
    ("Cargo Collective", ".cargocollective.com"),
    ("WebFlow", ".webflow.io"),
    ("FlyWheel", ".flywheelsites.com"),
    ("GitBook", ".gitbook.io"),
    ("Digital Ocean", ".ondigitalocean.app"),
    ("ReadMe", ".readme.io"),
    ("Kinsta", ".kinsta.cloud"),
]


class TakeoverModule:
    """Detects potential subdomain takeover vulnerabilities with fingerprint verification."""

    def __init__(self, config: dict):
        self.config = config.get("takeover", {})
        self.verify = self.config.get("verify", True)
        self._ssl = config.get("recon", {}).get("ssl_verify", False)

    def _fetch(self, url: str, timeout: int = 15) -> httpx.Response:
        """Stealth fetch with random UA and configurable SSL."""
        from modules.utils import get_random_ua
        headers = {"User-Agent": get_random_ua(), "Accept": "text/html"}
        return httpx.get(url, headers=headers, timeout=timeout, verify=self._ssl, follow_redirects=False)

    def _verify_fingerprint(self, service_name: str, resp: httpx.Response) -> bool:
        """Verify takeover by matching provider-specific error body signatures."""
        fingerprints = TAKEOVER_FINGERPRINTS.get(service_name, [])
        if not fingerprints:
            return False
        body = resp.text.lower()
        for sig in fingerprints:
            if sig.lower() in body:
                return True
        return False

    def check_subdomain(self, subdomain: str) -> List[Dict]:
        """Check a single subdomain for takeover with fingerprint verification."""
        findings = []
        url = f"http://{subdomain}"

        if not self.verify:
            return findings

        try:
            resp = self._fetch(url)
            # Verify by fingerprint, not generic 404
            if resp.status_code in (200, 404, 403):
                for service, indicator in CNAME_INDICATORS:
                    if indicator in subdomain.lower():
                        if self._verify_fingerprint(service, resp):
                            findings.append({
                                "subdomain": subdomain,
                                "service": service,
                                "indicator": indicator,
                                "severity": "high",
                                "type": "subdomain_takeover",
                                "description": f"Fingerprint-verified takeover potential on {subdomain} via {service}.",
                                "confirmed": True,
                            })
        except Exception:
            pass
        return findings

    def check_subdomains(self, subdomains: List[str]) -> List[Dict]:
        """Check a list of subdomains for takeover vulnerabilities."""
        results = []
        print(f"[*] Checking {len(subdomains)} subdomains for takeover vulnerabilities...")
        for subdomain in subdomains:
            findings = self.check_subdomain(subdomain)
            if findings:
                results.extend(findings)
        print(f"[+] Takeover check complete. Found {len(results)} potential takeovers.")
        return results
