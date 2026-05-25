"""
Fingerprint module for BBAT.
Detects technologies, frameworks, CMS, and server software from HTTP responses.
"""

import requests
import re
from typing import List, Dict
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Technology signatures: (name, detection_method, pattern_or_header)
TECH_SIGNATURES = [
    # Headers
    {"name": "Apache", "method": "header", "key": "Server", "pattern": r"Apache[\/\s]?([0-9.]+)?", "category": "web_server"},
    {"name": "Nginx", "method": "header", "key": "Server", "pattern": r"nginx[\/\s]?([0-9.]+)?", "category": "web_server"},
    {"name": "IIS", "method": "header", "key": "Server", "pattern": r"Microsoft-IIS[\/\s]?([0-9.]+)?", "category": "web_server"},
    {"name": "Cloudflare", "method": "header", "key": "Server", "pattern": r"cloudflare", "category": "cdn"},
    {"name": "Akamai", "method": "header", "key": "Server", "pattern": r"AkamaiGHost", "category": "cdn"},
    {"name": "Fastly", "method": "header", "key": "Via", "pattern": r"fastly", "category": "cdn"},
    {"name": "PHP", "method": "header", "key": "X-Powered-By", "pattern": r"PHP[\/\s]?([0-9.]+)?", "category": "language"},
    {"name": "ASP.NET", "method": "header", "key": "X-Powered-By", "pattern": r"ASP\.NET", "category": "framework"},
    {"name": "Express.js", "method": "header", "key": "X-Powered-By", "pattern": r"Express", "category": "framework"},
    {"name": "Django", "method": "header", "key": "Server", "pattern": r"WSGIServer", "category": "framework"},
    {"name": "WPEngine", "method": "header", "key": "X-Powered-By", "pattern": r"WPEngine", "category": "hosting"},
    {"name": "WordPress", "method": "header", "key": "X-Powered-By", "pattern": r"WordPress", "category": "cms"},
    {"name": "Drupal", "method": "header", "key": "X-Generator", "pattern": r"Drupal", "category": "cms"},
    {"name": "Joomla", "method": "header", "key": "X-Generator", "pattern": r"Joomla", "category": "cms"},
    {"name": "Amazon S3", "method": "header", "key": "Server", "pattern": r"AmazonS3", "category": "storage"},
    {"name": "Amazon ELB", "method": "header", "key": "Server", "pattern": r"awselb", "category": "load_balancer"},
    {"name": "OpenResty", "method": "header", "key": "Server", "pattern": r"openresty", "category": "web_server"},
    {"name": "LiteSpeed", "method": "header", "key": "Server", "pattern": r"LiteSpeed", "category": "web_server"},
    {"name": "Caddy", "method": "header", "key": "Server", "pattern": r"Caddy", "category": "web_server"},
    {"name": "Gunicorn", "method": "header", "key": "Server", "pattern": r"gunicorn", "category": "app_server"},
    {"name": "uWSGI", "method": "header", "key": "Server", "pattern": r"uWSGI", "category": "app_server"},
    {"name": "Jetty", "method": "header", "key": "Server", "pattern": r"Jetty", "category": "app_server"},
    {"name": "Tomcat", "method": "header", "key": "Server", "pattern": r"Apache-Coyote", "category": "app_server"},
    {"name": "WebLogic", "method": "header", "key": "Server", "pattern": r"WebLogic", "category": "app_server"},
    {"name": "SAP NetWeaver", "method": "header", "key": "Server", "pattern": r"SAP NetWeaver", "category": "app_server"},
    {"name": "HAProxy", "method": "header", "key": "Via", "pattern": r"HAProxy", "category": "load_balancer"},
    {"name": "Varnish", "method": "header", "key": "Via", "pattern": r"Varnish", "category": "cache"},
    {"name": "Squid", "method": "header", "key": "Via", "pattern": r"Squid", "category": "proxy"},
    # Body patterns
    {"name": "WordPress", "method": "body", "pattern": r"wp-content|wp-includes", "category": "cms"},
    {"name": "Drupal", "method": "body", "pattern": r"Drupal\.settings|sites/default", "category": "cms"},
    {"name": "Joomla", "method": "body", "pattern": r"/media/jui|/components/com_", "category": "cms"},
    {"name": "Laravel", "method": "body", "pattern": r"laravel_session|csrf-token", "category": "framework"},
    {"name": "React", "method": "body", "pattern": r"React|reactroot|data-reactid", "category": "framework"},
    {"name": "Angular", "method": "body", "pattern": r"ng-app|angular\.js|angularjs", "category": "framework"},
    {"name": "Vue.js", "method": "body", "pattern": r"vue-|__VUE__|vue\.js", "category": "framework"},
    {"name": "jQuery", "method": "body", "pattern": r"jquery|jQuery", "category": "library"},
    {"name": "Bootstrap", "method": "body", "pattern": r"bootstrap|bootstrap\.css|bootstrap\.js", "category": "library"},
    {"name": "Google Analytics", "method": "body", "pattern": r"google-analytics\.com|gtag\(|ga\(", "category": "analytics"},
    {"name": "Google Tag Manager", "method": "body", "pattern": r"googletagmanager\.com|gtm\.js", "category": "analytics"},
    {"name": "Mixpanel", "method": "body", "pattern": r"mixpanel\.com|mixpanel\(", "category": "analytics"},
    {"name": "Segment", "method": "body", "pattern": r"segment\.com|analytics\.js", "category": "analytics"},
    {"name": "New Relic", "method": "body", "pattern": r"newrelic\.com|NREUM", "category": "monitoring"},
    {"name": "Sentry", "method": "body", "pattern": r"sentry\.io|raven\.js|Sentry", "category": "monitoring"},
    {"name": "Django", "method": "body", "pattern": r"csrftoken|django", "category": "framework"},
    {"name": "Ruby on Rails", "method": "body", "pattern": r"csrf-param|authenticity_token|rails", "category": "framework"},
    {"name": "ASP.NET", "method": "body", "pattern": r"__VIEWSTATE|__EVENTVALIDATION", "category": "framework"},
    {"name": "Shopify", "method": "body", "pattern": r"shopify|myshopify", "category": "cms"},
    {"name": "Magento", "method": "body", "pattern": r"mage|Magento", "category": "cms"},
    {"name": "Salesforce", "method": "body", "pattern": r"salesforce| Lightning", "category": "crm"},
    {"name": "HubSpot", "method": "body", "pattern": r"hubspot|hs-script-loader", "category": "marketing"},
    {"name": "Marketo", "method": "body", "pattern": r"marketo|mktForm", "category": "marketing"},
    {"name": "Cloudflare", "method": "body", "pattern": r"cloudflare|cf-browser-verification", "category": "cdn"},
    {"name": "Google Fonts", "method": "body", "pattern": r"fonts\.googleapis\.com|fonts\.gstatic\.com", "category": "cdn"},
    {"name": "Font Awesome", "method": "body", "pattern": r"fontawesome|font-awesome", "category": "library"},
    {"name": "Stripe", "method": "body", "pattern": r"stripe\.com|Stripe", "category": "payment"},
    {"name": "PayPal", "method": "body", "pattern": r"paypal\.com|PayPal", "category": "payment"},
    {"name": "Intercom", "method": "body", "pattern": r"intercom\.io|intercom-settings", "category": "chat"},
    {"name": "Zendesk", "method": "body", "pattern": r"zendesk\.com|zEmbed", "category": "support"},
    {"name": "Disqus", "method": "body", "pattern": r"disqus\.com|disqus_thread", "category": "comment"},
    {"name": "Twitter", "method": "body", "pattern": r"twitter\.com|platform\.twitter\.com", "category": "social"},
    {"name": "Facebook", "method": "body", "pattern": r"facebook\.com|connect\.facebook\.net", "category": "social"},
    {"name": "LinkedIn", "method": "body", "pattern": r"linkedin\.com|platform\.linkedin\.com", "category": "social"},
]


class FingerprintModule:
    """Fingerprint web technologies from HTTP responses."""

    def __init__(self, config: dict):
        self.config = config.get("fingerprint", {})
        self.headers = {
            "User-Agent": config.get("recon", {}).get("user_agent", "BBAT/1.0")
        }

    def analyze(self, url: str) -> List[Dict]:
        """Analyze a URL and return detected technologies."""
        findings = []
        try:
            resp = requests.get(url, headers=self.headers, timeout=15, verify=False)
            headers = resp.headers
            body = resp.text[:100000]  # Limit body size

            for sig in TECH_SIGNATURES:
                if sig["method"] == "header":
                    header_value = headers.get(sig["key"], "")
                    matches = re.findall(sig["pattern"], header_value, re.IGNORECASE)
                    if matches:
                        version = matches[0] if matches[0] else "unknown"
                        findings.append({
                            "name": sig["name"],
                            "category": sig["category"],
                            "method": "header",
                            "header": sig["key"],
                            "value": header_value,
                            "version": version if isinstance(version, str) else "",
                            "confidence": "high",
                        })
                elif sig["method"] == "body":
                    if re.search(sig["pattern"], body, re.IGNORECASE):
                        findings.append({
                            "name": sig["name"],
                            "category": sig["category"],
                            "method": "body",
                            "confidence": "medium",
                        })
        except requests.RequestException:
            pass

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = (f["name"], f["category"])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def analyze_urls(self, urls: List[str]) -> Dict:
        """Analyze multiple URLs and aggregate results."""
        all_technologies = []
        print(f"[*] Fingerprinting {len(urls)} URLs...")
        for url in urls:
            techs = self.analyze(url)
            all_technologies.extend(techs)

        # Count by category
        categories = {}
        for tech in all_technologies:
            cat = tech["category"]
            categories[cat] = categories.get(cat, 0) + 1

        print(f"[+] Fingerprinting complete. Detected {len(all_technologies)} technology instances across {len(categories)} categories.")
        return {
            "urls_checked": len(urls),
            "technologies": all_technologies,
            "categories": categories,
            "total_unique": len({t["name"] for t in all_technologies}),
        }
