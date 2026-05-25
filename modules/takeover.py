"""
Takeover module for BBAT.
Detects subdomain takeover vulnerabilities by checking DNS records
against known vulnerable service signatures.
"""

import socket
import requests
from typing import List, Dict, Optional

# Known takeover signatures: (service_name, indicator_keyword, detection_type)
TAKEOVER_SIGNATURES = [
    {"name": "AWS S3 Bucket", "indicator": ".s3.amazonaws.com", "type": "CNAME", "vulnerable": True},
    {"name": "AWS S3 Bucket (us-east-1)", "indicator": ".s3-website-us-east-1.amazonaws.com", "type": "CNAME", "vulnerable": True},
    {"name": "AWS CloudFront", "indicator": ".cloudfront.net", "type": "CNAME", "vulnerable": True},
    {"name": "GitHub Pages", "indicator": ".github.io", "type": "CNAME", "vulnerable": True},
    {"name": "GitLab Pages", "indicator": ".gitlab.io", "type": "CNAME", "vulnerable": True},
    {"name": "Heroku", "indicator": ".herokuapp.com", "type": "CNAME", "vulnerable": True},
    {"name": "Netlify", "indicator": ".netlify.app", "type": "CNAME", "vulnerable": True},
    {"name": "Vercel", "indicator": ".vercel.app", "type": "CNAME", "vulnerable": True},
    {"name": "Surge.sh", "indicator": ".surge.sh", "type": "CNAME", "vulnerable": True},
    {"name": "Bitbucket", "indicator": ".bitbucket.io", "type": "CNAME", "vulnerable": True},
    {"name": "Fastly", "indicator": ".fastly.net", "type": "CNAME", "vulnerable": True},
    {"name": "Azure Blob", "indicator": ".blob.core.windows.net", "type": "CNAME", "vulnerable": True},
    {"name": "Azure App Service", "indicator": ".azurewebsites.net", "type": "CNAME", "vulnerable": True},
    {"name": "Azure TrafficManager", "indicator": ".trafficmanager.net", "type": "CNAME", "vulnerable": True},
    {"name": "Google Cloud Storage", "indicator": ".storage.googleapis.com", "type": "CNAME", "vulnerable": True},
    {"name": "Firebase", "indicator": ".firebaseapp.com", "type": "CNAME", "vulnerable": True},
    {"name": "Shopify", "indicator": ".myshopify.com", "type": "CNAME", "vulnerable": True},
    {"name": "Tumblr", "indicator": ".tumblr.com", "type": "CNAME", "vulnerable": True},
    {"name": "Unbounce", "indicator": ".unbouncepages.com", "type": "CNAME", "vulnerable": True},
    {"name": "Pantheon", "indicator": ".pantheonsite.io", "type": "CNAME", "vulnerable": True},
    {"name": "Acquia Cloud", "indicator": ".acquia-sites.com", "type": "CNAME", "vulnerable": True},
    {"name": "Zendesk", "indicator": ".zendesk.com", "type": "CNAME", "vulnerable": True},
    {"name": "StatusPage", "indicator": ".statuspage.io", "type": "CNAME", "vulnerable": True},
    {"name": "Ghost.io", "indicator": ".ghost.io", "type": "CNAME", "vulnerable": True},
    {"name": "WordPress.com", "indicator": ".wordpress.com", "type": "CNAME", "vulnerable": True},
    {"name": "Cargo Collective", "indicator": ".cargocollective.com", "type": "CNAME", "vulnerable": True},
    {"name": "strikinglydns.com", "indicator": ".strikinglydns.com", "type": "CNAME", "vulnerable": True},
    {"name": "WP Engine", "indicator": ".wpengine.com", "type": "CNAME", "vulnerable": True},
    {"name": "Smartling", "indicator": ".smartling.com", "type": "CNAME", "vulnerable": True},
    {"name": "Teamwork", "indicator": ".teamwork.com", "type": "CNAME", "vulnerable": True},
    {"name": "Help Scout", "indicator": ".helpscoutdocs.com", "type": "CNAME", "vulnerable": True},
    {"name": "SendGrid", "indicator": ".sendgrid.net", "type": "CNAME", "vulnerable": True},
    {"name": "Intercom", "indicator": ".custom.intercom.help", "type": "CNAME", "vulnerable": True},
    {"name": "SurveyMonkey", "indicator": ". surveymonkey.com", "type": "CNAME", "vulnerable": True},
    {"name": "GetResponse", "indicator": ".gr8.com", "type": "CNAME", "vulnerable": True},
    {"name": "Digital Ocean", "indicator": ".ondigitalocean.app", "type": "CNAME", "vulnerable": True},
    {"name": "ReadMe", "indicator": ".readme.io", "type": "CNAME", "vulnerable": True},
    {"name": "Kinsta", "indicator": ".kinsta.cloud", "type": "CNAME", "vulnerable": True},
    {"name": "LaunchRock", "indicator": ".launchrock.com", "type": "CNAME", "vulnerable": True},
    {"name": "Hatena", "indicator": ".hatenablog.com", "type": "CNAME", "vulnerable": True},
    {"name": "WebFlow", "indicator": ".webflow.io", "type": "CNAME", "vulnerable": True},
    {"name": "FlyWheel", "indicator": ".flywheelsites.com", "type": "CNAME", "vulnerable": True},
    {"name": "GitBook", "indicator": ".gitbook.io", "type": "CNAME", "vulnerable": True},
    {"name": "Airee", "indicator": ".airee.ru", "type": "CNAME", "vulnerable": True},
    {"name": "Anima", "indicator": ".animaapp.io", "type": "CNAME", "vulnerable": True},
    {"name": "Campaign Monitor", "indicator": ".createsend.com", "type": "CNAME", "vulnerable": True},
    {"name": "Canny", "indicator": ".canny.io", "type": "CNAME", "vulnerable": True},
    {"name": "Gemfury", "indicator": ".fury.ws", "type": "CNAME", "vulnerable": True},
    {"name": "Hopper", "indicator": ".hoppercms.com", "type": "CNAME", "vulnerable": True},
    {"name": "Rebrandly", "indicator": ".rebrandly.com", "type": "CNAME", "vulnerable": True},
    {"name": "Short.io", "indicator": ".shortcm.li", "type": "CNAME", "vulnerable": True},
    {"name": "VigLink", "indicator": ".viglink.com", "type": "CNAME", "vulnerable": True},
]


class TakeoverModule:
    """Detects potential subdomain takeover vulnerabilities."""

    def __init__(self, config: dict):
        self.config = config.get("takeover", {})
        self.verify = self.config.get("verify", True)  # Verify by HTTP request

    def check_subdomain(self, subdomain: str) -> List[Dict]:
        """Check a single subdomain for takeover indicators."""
        findings = []
        try:
            cname = socket.gethostbyname(subdomain)
        except (socket.gaierror, OSError):
            cname = None

        # Try CNAME via DNS if available
        if DNS_AVAILABLE:
            try:
                import dns.resolver
                answers = dns.resolver.resolve(subdomain, "CNAME")
                cname = str(list(answers)[0])
            except Exception:
                pass

        if cname:
            for sig in TAKEOVER_SIGNATURES:
                if sig["indicator"] in cname.lower():
                    finding = {
                        "subdomain": subdomain,
                        "service": sig["name"],
                        "indicator": sig["indicator"],
                        "cname": cname,
                        "severity": "high",
                        "type": "subdomain_takeover",
                        "description": f"{subdomain} points to {sig['name']} which may be claimable.",
                    }
                    # Verify by HTTP if enabled
                    if self.verify:
                        try:
                            resp = requests.get(f"http://{subdomain}", timeout=10, allow_redirects=False)
                            if resp.status_code == 404 or "NoSuchBucket" in resp.text or "not found" in resp.text.lower():
                                finding["confirmed"] = True
                                finding["description"] += " HTTP verification CONFIRMED vulnerable."
                            else:
                                finding["confirmed"] = False
                        except requests.RequestException:
                            finding["confirmed"] = None
                    findings.append(finding)

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


# Optional dependency
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
