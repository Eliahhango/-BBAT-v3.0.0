"""
S3Scanner module for BBAT.
Checks for publicly accessible S3 buckets based on a target domain name.
"""

import requests
from typing import List, Dict

COMMON_BUCKET_NAMES = [
    "{domain}",
    "{domain}-backup",
    "{domain}-backups",
    "{domain}-assets",
    "{domain}-uploads",
    "{domain}-files",
    "{domain}-data",
    "{domain}-dev",
    "{domain}-staging",
    "{domain}-test",
    "{domain}-prod",
    "{domain}-production",
    "{domain}-logs",
    "{domain}-media",
    "{domain}-static",
    "{domain}-images",
    "{domain}-docs",
    "{domain}-documents",
    "{domain}-config",
    "{domain}-api",
    "www-{domain}",
    "cdn-{domain}",
    "assets-{domain}",
    "static-{domain}",
    "media-{domain}",
    "backup-{domain}",
    "{short}-backup",
    "{short}-assets",
    "{short}-uploads",
    "{short}-data",
]


class S3ScannerModule:
    """Finds potentially public S3 buckets for a target domain."""

    def __init__(self, config: dict):
        self.config = config.get("s3_scanner", {})
        self.region = self.config.get("region", "us-east-1")
        self.timeout = self.config.get("timeout", 10)

    def check_bucket(self, bucket_name: str) -> Dict:
        """Check if an S3 bucket exists and is potentially public."""
        aws_url = f"https://{bucket_name}.s3.amazonaws.com"
        results = {
            "bucket": bucket_name,
            "exists": False,
            "public_listing": False,
            "public_objects": False,
            "response_code": None,
        }
        try:
            resp = requests.get(aws_url, timeout=self.timeout, allow_redirects=False)
            results["response_code"] = resp.status_code
            if resp.status_code == 200:
                results["exists"] = True
                if "ListBucketResult" in resp.text or "Contents" in resp.text:
                    results["public_listing"] = True
            elif resp.status_code == 403:
                results["exists"] = True  # Bucket exists but denies access
        except requests.RequestException:
            pass
        return results

    def scan_domain(self, domain: str) -> List[Dict]:
        """Scan a domain for potential S3 buckets."""
        short = domain.split(".")[0]
        found = []
        print(f"[*] Scanning for S3 buckets related to {domain}...")
        for template in COMMON_BUCKET_NAMES:
            bucket_name = template.replace("{domain}", domain).replace("{short}", short)
            result = self.check_bucket(bucket_name)
            if result["exists"]:
                found.append(result)
                print(f"  [!] Found bucket: {bucket_name} (listing={result['public_listing']})")
        print(f"[+] S3 scan complete. Found {len(found)} buckets.")
        return found
