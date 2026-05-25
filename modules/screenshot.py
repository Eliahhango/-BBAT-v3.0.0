"""
Screenshot module for BBAT.
Captures headless browser screenshots of discovered endpoints.
Requires playwright or selenium (optional dependencies).
"""

import os
import base64
from typing import List, Dict
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ScreenshotModule:
    """Captures screenshots of web endpoints for visual triage."""

    def __init__(self, config: dict):
        self.config = config.get("screenshot", {})
        self.timeout = self.config.get("timeout", 30)
        self.resolution = self.config.get("resolution", "1920x1080")
        self.output_dir = self.config.get("output_dir", "./output/screenshots")
        self.user_agent = config.get("recon", {}).get("user_agent", "BBAT/1.0")
        self._backend = None

    def _get_backend(self):
        """Lazy-load screenshot backend."""
        if self._backend == "playwright":
            return "playwright"
        if self._backend == "selenium":
            return "selenium"
        try:
            from playwright.sync_api import sync_playwright
            self._backend = "playwright"
        except ImportError:
            try:
                from selenium import webdriver
                from selenium.webdriver.chrome.options import Options
                self._backend = "selenium"
            except ImportError:
                self._backend = None
        return self._backend

    def _screenshot_playwright(self, url: str, output_path: str) -> bool:
        """Capture screenshot using Playwright."""
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page(viewport={"width": 1920, "height": 1080})
                page.set_extra_http_headers({"User-Agent": self.user_agent})
                page.goto(url, timeout=self.timeout * 1000, wait_until="networkidle")
                page.screenshot(path=output_path, full_page=False)
                browser.close()
                return True
        except Exception as e:
            print(f"[!] Screenshot failed for {url}: {e}")
            return False

    def _screenshot_selenium(self, url: str, output_path: str) -> bool:
        """Capture screenshot using Selenium."""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service

            options = Options()
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument(f"--user-agent={self.user_agent}")
            options.add_argument("--window-size=1920,1080")

            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(self.timeout)
            driver.get(url)
            driver.save_screenshot(output_path)
            driver.quit()
            return True
        except Exception as e:
            print(f"[!] Screenshot failed for {url}: {e}")
            return False

    def capture(self, url: str) -> Dict:
        """Capture screenshot of a single URL."""
        os.makedirs(self.output_dir, exist_ok=True)
        safe_name = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")[:80]
        filename = f"{safe_name}.png"
        output_path = os.path.join(self.output_dir, filename)

        backend = self._get_backend()
        if not backend:
            return {
                "url": url,
                "error": "No screenshot backend available. Install playwright: pip install playwright && playwright install chromium",
            }

        if backend == "playwright":
            ok = self._screenshot_playwright(url, output_path)
        else:
            ok = self._screenshot_selenium(url, output_path)

        if ok and os.path.exists(output_path):
            size_kb = os.path.getsize(output_path) / 1024
            return {
                "url": url,
                "screenshot": output_path,
                "size_kb": round(size_kb, 2),
                "backend": backend,
            }
        return {"url": url, "error": "Screenshot capture failed"}

    def capture_batch(self, urls: List[str]) -> List[Dict]:
        """Capture screenshots for multiple URLs."""
        results = []
        print(f"[*] Capturing screenshots for {len(urls)} URLs...")
        for url in urls:
            result = self.capture(url)
            results.append(result)
        successes = [r for r in results if "screenshot" in r]
        print(f"[+] Screenshot capture complete. {len(successes)}/{len(urls)} succeeded.")
        return results
