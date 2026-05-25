"""
Crawler module for BBAT.
Discovers endpoints and links within authorized scope.
"""

import requests
import re
from urllib.parse import urljoin, urlparse
from typing import Set, Dict, List
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Optional dependency
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


class CrawlerModule:
    """Web crawler for authorized bug bounty targets."""

    def __init__(self, config: dict):
        self.config = config.get("crawler", {})
        self.max_depth = self.config.get("max_depth", 3)
        self.max_pages = self.config.get("max_pages", 500)
        self.same_domain_only = self.config.get("same_domain_only", True)
        self.respect_robots = self.config.get("respect_robots", True)
        self.headers = {
            "User-Agent": config.get("recon", {}).get("user_agent", "BBAT/1.0")
        }
        self.visited = set()
        self.endpoints = set()
        self.forms = []
        self.comments = []

    def _is_same_domain(self, url: str, base: str) -> bool:
        return urlparse(url).netloc == urlparse(base).netloc

    def _extract_links_bs4(self, html: str, current: str, base: str) -> Set[str]:
        """Extract links using BeautifulSoup."""
        links = set()
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = urljoin(current, tag["href"])
            parsed = urlparse(href)
            href = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if href not in self.visited:
                if self.same_domain_only:
                    if self._is_same_domain(href, base):
                        links.add(href)
                else:
                    links.add(href)
        # Forms
        for form in soup.find_all("form"):
            self.forms.append({
                "url": current,
                "action": form.get("action", ""),
                "method": form.get("method", "GET").upper(),
                "inputs": [input_tag.get("name", "") for input_tag in form.find_all("input")]
            })
        # Comments
        for comment in soup.find_all(string=lambda text: isinstance(text, type(BeautifulSoup("", "html.parser").string))):
            if str(comment).strip().startswith("<!--"):
                self.comments.append({"url": current, "comment": str(comment).strip()})
        return links

    def _extract_links_regex(self, html: str, current: str, base: str) -> Set[str]:
        """Fallback link extraction using regex when BeautifulSoup is unavailable."""
        links = set()
        hrefs = re.findall(r'href=["\'](.*?)["\']', html, re.IGNORECASE)
        for href in hrefs:
            full = urljoin(current, href)
            parsed = urlparse(full)
            full = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if full not in self.visited:
                if self.same_domain_only:
                    if self._is_same_domain(full, base):
                        links.add(full)
                else:
                    links.add(full)
        return links

    def crawl(self, start_url: str) -> Dict:
        """Crawl a target domain to discover endpoints."""
        from modules.utils import normalize_url
        base = normalize_url(start_url)
        domain = urlparse(base).netloc
        to_visit = {base}
        depth = 0

        print(f"[*] Crawling {base} (max depth={self.max_depth}, max pages={self.max_pages})")
        if not BS4_AVAILABLE:
            print("[!] Warning: beautifulsoup4 not installed. Using regex fallback for link extraction.")

        while to_visit and len(self.visited) < self.max_pages and depth < self.max_depth:
            current = to_visit.pop()
            if current in self.visited:
                continue
            self.visited.add(current)

            try:
                resp = requests.get(current, headers=self.headers, timeout=10, verify=False)
                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue

                if BS4_AVAILABLE:
                    links = self._extract_links_bs4(resp.text, current, base)
                else:
                    links = self._extract_links_regex(resp.text, current, base)

                to_visit.update(links)
                self.endpoints.add(current)

            except requests.RequestException:
                pass
            depth += 1

        print(f"[+] Crawled {len(self.visited)} pages, found {len(self.endpoints)} endpoints, {len(self.forms)} forms.")

        return {
            "target": start_url,
            "pages_crawled": len(self.visited),
            "endpoints": sorted(list(self.endpoints)),
            "forms": self.forms,
            "comments": self.comments,
        }
