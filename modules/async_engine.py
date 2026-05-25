"""
AsyncEngine module for BBAT.
Concurrent HTTP request engine using httpx for high-speed scanning.
"""

import asyncio
from urllib.parse import urljoin
from typing import List, Dict
import random
import time

# Optional dependency
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

from modules.utils import get_random_ua


class AsyncEngine:
    """High-speed async HTTP engine for BBAT modules."""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.semaphore_limit = self.config.get("concurrency", 100)
        self.user_agent = self.config.get("user_agent", get_random_ua())
        self.ssl_verify = self.config.get("ssl_verify", False)
        self.jitter_min = self.config.get("jitter_min_ms", 0)
        self.jitter_max = self.config.get("jitter_max_ms", 500)
        self.headers = {"User-Agent": self.user_agent, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "DNT": "1", "Connection": "keep-alive"}

    def _jitter(self):
        """Sleep for a random short duration to avoid WAF rate-limiting."""
        if self.jitter_max > 0:
            delay = random.uniform(self.jitter_min / 1000, self.jitter_max / 1000)
            time.sleep(delay)

    @staticmethod
    def _needs_ua(headers: dict) -> dict:
        h = dict(headers)
        if "User-Agent" not in h:
            h["User-Agent"] = get_random_ua()
        return h

    async def _fetch(self, client: httpx.AsyncClient, url: str, method: str = "GET", data=None, extra_headers: dict = None) -> Dict:
        """Fetch a single URL asynchronously."""
        if not HTTPX_AVAILABLE:
            return {"url": url, "error": "httpx not installed. pip install httpx"}
        headers = self._needs_ua(dict(self.headers))
        if extra_headers:
            headers.update(extra_headers)
        self._jitter()
        try:
            if method == "POST":
                resp = await client.post(url, headers=headers, data=data, timeout=self.timeout, follow_redirects=False)
            elif method == "HEAD":
                resp = await client.head(url, headers=headers, timeout=self.timeout, follow_redirects=False)
            else:
                resp = await client.get(url, headers=headers, timeout=self.timeout, follow_redirects=False)
            return {
                "url": url,
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "content": resp.text if resp.status_code < 500 else "",
                "content_length": len(resp.content),
            }
        except asyncio.TimeoutError:
            return {"url": url, "error": "timeout"}
        except Exception as e:
            return {"url": url, "error": str(e)}

    async def fetch_urls(self, urls: List[str], extra_headers: dict = None) -> List[Dict]:
        """Fetch multiple URLs concurrently using httpx."""
        if not HTTPX_AVAILABLE:
            return [{"error": "httpx not installed"}]
        limits = httpx.Limits(max_connections=200, max_keepalive_connections=20)
        async with httpx.AsyncClient(verify=self.ssl_verify, limits=limits, http2=True) as client:
            sem = asyncio.Semaphore(self.semaphore_limit)

            async def bounded_fetch(url):
                async with sem:
                    return await self._fetch(client, url, extra_headers=extra_headers)

            tasks = [bounded_fetch(u) for u in urls]
            return await asyncio.gather(*tasks)

    async def fuzz_directories(self, base_url: str, wordlist: List[str], extensions: List[str] = None) -> List[Dict]:
        """Async directory fuzzing."""
        urls = []
        for word in wordlist:
            urls.append(urljoin(base_url, word))
            if extensions and "." not in word:
                for ext in extensions:
                    urls.append(urljoin(base_url, f"{word}.{ext}"))
        return await self.fetch_urls(urls)

    def run(self, urls: List[str], extra_headers: dict = None) -> List[Dict]:
        """Synchronous wrapper for async fetching."""
        if not urls:
            return []
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(self.fetch_urls(urls, extra_headers=extra_headers))

    def run_fuzz(self, base_url: str, wordlist: List[str], extensions: List[str] = None) -> List[Dict]:
        """Synchronous wrapper for async fuzzing."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(self.fuzz_directories(base_url, wordlist, extensions))
