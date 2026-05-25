"""
AsyncEngine module for BBAT.
Concurrent HTTP request engine using asyncio/aiohttp for high-speed scanning.
"""

import asyncio
from urllib.parse import urljoin
from typing import List, Dict
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Optional dependency
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False


class AsyncEngine:
    """High-speed async HTTP engine for BBAT modules."""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.user_agent = self.config.get("user_agent", "BBAT/2.0")
        self.semaphore_limit = self.config.get("concurrency", 100)
        self.headers = {"User-Agent": self.user_agent}
        if AIOHTTP_AVAILABLE:
            self._connector = aiohttp.TCPConnector(
                limit=self.semaphore_limit * 2,
                limit_per_host=20,
                ssl=False,
                enable_cleanup_closed=True,
                force_close=True,
            )

    async def _fetch(self, session, url: str, method: str = "GET", data=None) -> Dict:
        """Fetch a single URL asynchronously."""
        if not AIOHTTP_AVAILABLE:
            return {"url": url, "error": "aiohttp not installed. pip install aiohttp"}
        try:
            async with asyncio.Semaphore(self.semaphore_limit):
                if method == "POST":
                    async with session.post(url, headers=self.headers, data=data, timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                        return {
                            "url": url,
                            "status": resp.status,
                            "headers": dict(resp.headers),
                            "content_length": len(await resp.read()),
                        }
                elif method == "HEAD":
                    async with session.head(url, headers=self.headers, timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                        return {
                            "url": url,
                            "status": resp.status,
                            "headers": dict(resp.headers),
                        }
                else:
                    async with session.get(url, headers=self.headers, timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                        return {
                            "url": url,
                            "status": resp.status,
                            "content_type": resp.headers.get("Content-Type", ""),
                            "content_length": len(await resp.read()),
                        }
        except asyncio.TimeoutError:
            return {"url": url, "error": "timeout"}
        except Exception as e:
            return {"url": url, "error": str(e)}

    async def fetch_urls(self, urls: List[str]) -> List[Dict]:
        """Fetch multiple URLs concurrently."""
        if not AIOHTTP_AVAILABLE:
            return [{"error": "aiohttp not installed"}]
        async with aiohttp.ClientSession(connector=self._connector, headers=self.headers) as session:
            tasks = [self._fetch(session, url) for url in urls]
            return await asyncio.gather(*tasks)

    async def fuzz_directories(self, base_url: str, wordlist: List[str], extensions: List[str] = None) -> List[Dict]:
        """Async directory fuzzing."""
        urls = []
        for word in wordlist:
            urls.append(urljoin(base_url, word))
            if extensions and "." not in word:
                for ext in extensions:
                    urls.append(urljoin(base_url, f"{word}.{ext}"))
        results = await self.fetch_urls(urls)
        interesting = [
            r for r in results
            if "status" in r and r["status"] in (200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500, 502, 503)
        ]
        return interesting

    def run(self, urls: List[str]) -> List[Dict]:
        """Synchronous wrapper for async fetching."""
        if not urls:
            return []
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(self.fetch_urls(urls))

    def run_fuzz(self, base_url: str, wordlist: List[str], extensions: List[str] = None) -> List[Dict]:
        """Synchronous wrapper for async fuzzing."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(self.fuzz_directories(base_url, wordlist, extensions))
