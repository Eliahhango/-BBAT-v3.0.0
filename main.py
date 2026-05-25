#!/usr/bin/env python3
"""
BBAT (Bug Bounty Automation Toolkit) v3.0.0
A modular, extensible framework for authorized bug bounty reconnaissance.

Usage:
    python main.py recon        <target>
    python main.py scan         <target>
    python main.py fuzz         <target>
    python main.py crawl        <target>
    python main.py takeover     <target>
    python main.py js_analyze   <url_list_file>
    python main.py fingerprint  <target>
    python main.py ctlog        <domain>
    python main.py wayback      <domain>
    python main.py s3           <domain>
    python main.py gitscan      <target>
    python main.py nuclei       <target>
    python main.py screenshot   <urls_file>
    python main.py waf          <target>
    python main.py api_fuzz     <target>
    python main.py dashboard    # Runs Flask web dashboard
    python main.py full         <target>

Author: Security Researcher
License: MIT
"""

import argparse
import sys
import os

# Add modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "modules"))

import utils
from recon import ReconModule
from scanner import ScannerModule
from fuzzer import FuzzerModule
from crawler import CrawlerModule
from takeover import TakeoverModule
from js_analyzer import JSAnalyzerModule
from fingerprint import FingerprintModule
from ctlog import CTLogModule
from notifier import NotifierModule
from report import ReportModule
from wayback import WaybackModule
from s3_scanner import S3ScannerModule
from git_scanner import GitScannerModule
from nuclei_scanner import NucleiScannerModule
from screenshot import ScreenshotModule
from waf_detector import WAFDetectorModule
from api_fuzzer import ApiFuzzerModule
from async_engine import AsyncEngine


class BBAT:
    """Main orchestrator for the Bug Bounty Automation Toolkit."""

    def __init__(self, config_path="config.json"):
        self.config = utils.load_config(config_path)
        self.output_dir = self.config["project"]["output_dir"]
        os.makedirs(self.output_dir, exist_ok=True)

        self.recon = ReconModule(self.config)
        self.scanner = ScannerModule(self.config)
        self.fuzzer = FuzzerModule(self.config)
        self.crawler = CrawlerModule(self.config)
        self.takeover = TakeoverModule(self.config)
        self.js_analyzer = JSAnalyzerModule(self.config)
        self.fingerprint = FingerprintModule(self.config)
        self.ctlog = CTLogModule(self.config)
        self.notifier = NotifierModule(self.config)
        self.report = ReportModule(self.config)
        self.wayback = WaybackModule(self.config)
        self.s3_scanner = S3ScannerModule(self.config)
        self.git_scanner = GitScannerModule(self.config)
        self.nuclei = NucleiScannerModule(self.config)
        self.screenshot = ScreenshotModule(self.config)
        self.waf = WAFDetectorModule(self.config)
        self.api_fuzzer = ApiFuzzerModule(self.config)
        self.async_engine = AsyncEngine(self.config.get("recon", {}))

    def _safe_file(self, name: str) -> str:
        return utils.sanitize_filename(name)

    # ──────────────────────── Individual Commands ────────────────────────

    def run_recon(self, target):
        print(f"[+] Starting reconnaissance on: {target}")
        results = {
            "subdomains": self.recon.enumerate_subdomains(target),
            "dns_records": self.recon.resolve_dns(target),
            "port_scan": self.recon.port_scan(target),
            "whois": self.recon.whois_lookup(target),
        }
        utils.save_results(results, f"{self.output_dir}/recon_{self._safe_file(target)}.json")
        return results

    def run_scan(self, target):
        print(f"[+] Starting vulnerability scan on: {target}")
        results = self.scanner.scan(target)
        utils.save_results(results, f"{self.output_dir}/scan_{self._safe_file(target)}.json")
        return results

    def run_fuzz(self, target):
        print(f"[+] Starting fuzzing on: {target}")
        results = self.fuzzer.fuzz(target)
        utils.save_results(results, f"{self.output_dir}/fuzz_{self._safe_file(target)}.json")
        return results

    def run_crawl(self, target):
        print(f"[+] Starting crawling on: {target}")
        results = self.crawler.crawl(target)
        utils.save_results(results, f"{self.output_dir}/crawl_{self._safe_file(target)}.json")
        return results

    def run_takeover(self, target):
        print(f"[+] Starting subdomain takeover detection on: {target}")
        subs = self.recon.enumerate_subdomains(target)
        subdomains = [s["subdomain"] for s in subs]
        results = self.takeover.check_subdomains(subdomains)
        utils.save_results(results, f"{self.output_dir}/takeover_{self._safe_file(target)}.json")
        return results

    def run_js_analyze(self, urls_file):
        print(f"[+] Starting JavaScript analysis from: {urls_file}")
        with open(urls_file, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        results = self.js_analyzer.analyze_urls(urls)
        utils.save_results(results, f"{self.output_dir}/js_analyze.json")
        return results

    def run_fingerprint(self, target):
        print(f"[+] Starting fingerprinting on: {target}")
        urls = [utils.normalize_url(target)]
        results = self.fingerprint.analyze_urls(urls)
        utils.save_results(results, f"{self.output_dir}/fingerprint_{self._safe_file(target)}.json")
        return results

    def run_ctlog(self, domain):
        print(f"[+] Starting CT log enumeration for: {domain}")
        results = {"subdomains": self.ctlog.fetch_subdomains(domain)}
        utils.save_results(results, f"{self.output_dir}/ctlog_{self._safe_file(domain)}.json")
        return results

    def run_wayback(self, domain):
        print(f"[+] Starting Wayback Machine enumeration for: {domain}")
        results = {"urls": self.wayback.fetch_urls(domain)}
        utils.save_results(results, f"{self.output_dir}/wayback_{self._safe_file(domain)}.json")
        return results

    def run_s3(self, domain):
        print(f"[+] Starting S3 bucket scan for: {domain}")
        results = self.s3_scanner.scan_domain(domain)
        utils.save_results(results, f"{self.output_dir}/s3_{self._safe_file(domain)}.json")
        return results

    def run_gitscan(self, target):
        print(f"[+] Starting exposed repository scan on: {target}")
        results = self.git_scanner.scan(target)
        utils.save_results(results, f"{self.output_dir}/gitscan_{self._safe_file(target)}.json")
        return results

    def run_nuclei(self, target):
        print(f"[+] Starting Nuclei scan on: {target}")
        results = self.nuclei.scan_target(target)
        utils.save_results(results, f"{self.output_dir}/nuclei_{self._safe_file(target)}.json")
        return results

    def run_screenshot(self, urls_file):
        print(f"[+] Starting screenshot capture from: {urls_file}")
        with open(urls_file, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        results = self.screenshot.capture_batch(urls)
        utils.save_results(results, f"{self.output_dir}/screenshots.json")
        return results

    def run_waf(self, target):
        print(f"[+] Starting WAF detection on: {target}")
        results = self.waf.detect_batch([utils.normalize_url(target)])
        utils.save_results(results, f"{self.output_dir}/waf_{self._safe_file(target)}.json")
        return results

    def run_api_fuzz(self, target):
        print(f"[+] Starting API fuzzing on: {target}")
        results = self.api_fuzzer.scan(target)
        utils.save_results(results, f"{self.output_dir}/api_fuzz_{self._safe_file(target)}.json")
        return results

    def run_dashboard(self, host="127.0.0.1", port=5000):
        print(f"[*] Starting BBAT Dashboard on http://{host}:{port}")
        from modules.dashboard import app
        app.run(host=host, port=port, debug=False)

    # ─────────────────────────── Full Pipeline ───────────────────────────

    def run_full(self, target):
        print(f"[*] Full pipeline started for target: {target}")
        results = {
            "target": target,
            "recon": self.run_recon(target),
            "ctlog": self.run_ctlog(target),
            "wayback": self.run_wayback(target),
            "crawl": self.run_crawl(target),
            "fuzz": self.run_fuzz(target),
            "scan": self.run_scan(target),
            "takeover": self.run_takeover(target),
            "s3": self.run_s3(target),
            "gitscan": self.run_gitscan(target),
            "fingerprint": self.run_fingerprint(target),
        }
        safe = self._safe_file(target)
        utils.save_results(results, f"{self.output_dir}/full_{safe}.json")
        self.report.generate_and_save(results, target, self.output_dir)
        print(f"[*] Full pipeline complete. Results saved to {self.output_dir}/full_{safe}.json")
        return results


def main():
    parser = argparse.ArgumentParser(
        description="BBAT - Bug Bounty Automation Toolkit v3.0.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py recon        example.com
  python main.py scan          https://example.com
  python main.py fuzz          https://example.com
  python main.py crawl         https://example.com
  python main.py takeover      example.com
  python main.py js_analyze    js_urls.txt
  python main.py fingerprint   https://example.com
  python main.py ctlog         example.com
  python main.py wayback       example.com
  python main.py s3            example.com
  python main.py gitscan       https://example.com
  python main.py nuclei        https://example.com
  python main.py screenshot    urls.txt
  python main.py waf           https://example.com
  python main.py api_fuzz      https://api.example.com
  python main.py dashboard     # Launches web dashboard
  python main.py full          example.com
        """,
    )
    parser.add_argument(
        "command",
        choices=[
            "recon", "scan", "fuzz", "crawl", "full",
            "takeover", "js_analyze", "fingerprint", "ctlog",
            "wayback", "s3", "gitscan", "nuclei", "screenshot",
            "waf", "api_fuzz", "dashboard",
        ],
        help="Command to run"
    )
    parser.add_argument("target", nargs="?", default="", help="Target domain, URL, or file")
    parser.add_argument("--config", default="config.json", help="Path to configuration file")
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Dashboard port (default: 5000)")
    args = parser.parse_args()

    bbat = BBAT(config_path=args.config)

    if args.command == "recon":
        if not args.target: parser.error("recon requires a target")
        bbat.run_recon(args.target)
    elif args.command == "scan":
        if not args.target: parser.error("scan requires a target")
        bbat.run_scan(args.target)
    elif args.command == "fuzz":
        if not args.target: parser.error("fuzz requires a target")
        bbat.run_fuzz(args.target)
    elif args.command == "crawl":
        if not args.target: parser.error("crawl requires a target")
        bbat.run_crawl(args.target)
    elif args.command == "takeover":
        if not args.target: parser.error("takeover requires a target")
        bbat.run_takeover(args.target)
    elif args.command == "js_analyze":
        if not args.target: parser.error("js_analyze requires a file")
        bbat.run_js_analyze(args.target)
    elif args.command == "fingerprint":
        if not args.target: parser.error("fingerprint requires a target")
        bbat.run_fingerprint(args.target)
    elif args.command == "ctlog":
        if not args.target: parser.error("ctlog requires a domain")
        bbat.run_ctlog(args.target)
    elif args.command == "wayback":
        if not args.target: parser.error("wayback requires a domain")
        bbat.run_wayback(args.target)
    elif args.command == "s3":
        if not args.target: parser.error("s3 requires a domain")
        bbat.run_s3(args.target)
    elif args.command == "gitscan":
        if not args.target: parser.error("gitscan requires a target")
        bbat.run_gitscan(args.target)
    elif args.command == "nuclei":
        if not args.target: parser.error("nuclei requires a target")
        bbat.run_nuclei(args.target)
    elif args.command == "screenshot":
        if not args.target: parser.error("screenshot requires a urls file")
        bbat.run_screenshot(args.target)
    elif args.command == "waf":
        if not args.target: parser.error("waf requires a target")
        bbat.run_waf(args.target)
    elif args.command == "api_fuzz":
        if not args.target: parser.error("api_fuzz requires a target")
        bbat.run_api_fuzz(args.target)
    elif args.command == "dashboard":
        bbat.run_dashboard(host=args.host, port=args.port)
    elif args.command == "full":
        if not args.target: parser.error("full requires a target")
        bbat.run_full(args.target)


if __name__ == "__main__":
    main()
