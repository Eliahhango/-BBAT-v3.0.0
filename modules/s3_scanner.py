"""
S3Scanner module for BBAT.
Async S3 enumeration using httpx.
"""

from typing import List, Dict
import httpx
from modules.async_engine import AsyncEngine
from modules.utils import get_random_ua

COMMON_BUCKET_NAMES = [
    "{domain}", "{domain}-backup", "{domain}-assets", "{domain}-uploads",
    "{domain}-data", "{domain}-dev", "{domain}-staging", "{domain}-prod",
    "www-{domain}", "cdn-{domain}", "static-{domain}", "assets-{domain}",
    "{short}-backup", "{short}-assets", "backup-{domain}",
]


class S3ScannerModule:
    """Find potentially public S3 buckets via async httpx."""

    def __init__(self, config: dict):
        self.config = config.get("s3_scanner", {})
        self.region = self.config.get("region", "us-east-1")
        self.timeout = self.config.get("timeout", 10)
        self._ssl = config.get("recon", {}).get("ssl_verify", False)

    def check_bucket(self, bucket_name: str) -> Dict:
        """Check if an S3 bucket exists and is potentially public."""
        aws_url = f"https://{bucket_name}.s3.amazonaws.com"
        result = {"bucket": bucket_name, "exists": False, "public_listing": False, "response_code": None}
        try:
            resp = httpx.get(aws_url, headers={"User-Agent": get_random_ua()}, timeout=self.timeout, verify=self._ssl, allow_redirects=False)
            result["response_code"] = resp.status_code
            if resp.status_code == 200:
                result["exists"] = True
                if "ListBucketResult" in resp.text or "Contents" in resp.text:
                    result["public_listing"] = True
            elif resp.status_code == 403:
                result["exists"] = True
        except Exception:
            pass
        return result

    def scan_domain(self, domain: str) -> List[Dict]:
        """Scan a domain for potential S3 buckets using AsyncEngine."""
        short = domain.split(".")[0]
        urls = []
        bucket_map = {}
        for template in COMMON_BUCKET_NAMES:
            bucket = template.replace("{domain}", domain).replace("{short}", short)
            aws_url = f"https://{bucket}.s3.amazonaws.com"
            urls.append(aws_url)
            bucket_map[aws_url] = bucket

        engine = AsyncEngine(self.config)
        async_results = engine.run(urls)

        found = []
        for result in async_results:
            if "error" in result:
                continue
            url = result.get("url", "")
            bucket = bucket_map.get(url, "")
            status = result.get("status", 0)
            exists = status in (200, 403)
            public = status == 200 and ("ListBucketResult" in result.get("content", "") or "Contents" in result.get("content", ""))
            if exists:
                found.append({
                    "bucket": bucket, "exists": True, "public_listing": public,
                    "url": url, "response_code": status,
                })
                print(f"  [!] Found bucket: {bucket} (listing={public})")

        print(f"[+] S3 scan complete. Found {len(found)} related buckets.")
        return found
