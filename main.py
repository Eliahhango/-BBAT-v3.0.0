#!/usr/bin/env python3
"""
BBAT (Bug Bounty Automation Toolkit) v3.2.0
A modular, extensible framework for authorized bug bounty reconnaissance.

CLI Usage:
    python main.py recon        <target>
    python main.py scan         <target>
    python main.py fuzz         <target>
    python main.py full         <target>
    ...

TUI Usage (NEW):
    python main.py --tui        # Launch the interactive Dracula-themed Textual TUI

Author: Red-Team Engineer
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
from db import BBATDatabase


class BBAT:
    """Main orchestrator for the Bug Bounty Automation Toolkit."""

    def __init__(self):
        self.config = utils.load_config("config.json")
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
        self.db = BBATDatabase(self.config.get("reporting", {}).get("db_path", "./output/bbat.db"))

    # ... persistence helpers same as before ...
    def _persist_recon(self, target_id: int, results: dict):
        if results.get("subdomains"):
            self.db.insert_subdomains(target_id, results["subdomains"])
        if results.get("dns_records"):
            self.db.insert_dns_records(target_id, results["dns_records"])
        if results.get("port_scan"):
            self.db.insert_ports(target_id, results["port_scan"])

    def _persist_findings(self, target_id: int, findings: list):
        if findings:
            self.db.insert_findings(target_id, findings)
            self.notifier.notify_findings(findings, self.current_target or "unknown")

    def run_recon(self, target):
        print(f"[+] Reconnaissance on: {target}")
        tid = self.db.insert_target(target)
        results = {"subdomains": self.recon.enumerate_subdomains(target), "dns_records": self.recon.resolve_dns(target),
                   "port_scan": self.recon.port_scan(target), "whois": self.recon.whois_lookup(target)}
        self._persist_recon(tid, results)
        utils.save_results(results, f"{self.output_dir}/recon_{utils.sanitize_filename(target)}.json")
        return results

    def run_scan(self, target):
        results = self.scanner.scan(target)
        tid = self.db.get_target_id(utils.get_domain(target)) or self.db.insert_target(target)
        self._persist_findings(tid, results.get("findings", []))
        utils.save_results(results, f"{self.output_dir}/scan_{utils.sanitize_filename(target)}.json")
        return results

    def run_fuzz(self, target):
        results = self.fuzzer.fuzz(target)
        tid = self.db.get_target_id(utils.get_domain(target)) or self.db.insert_target(target)
        self.db.insert_endpoints(tid, results.get("items", []), source="fuzzer")
        utils.save_results(results, f"{self.output_dir}/fuzz_{utils.sanitize_filename(target)}.json")
        return results

    def run_crawl(self, target):
        results = self.crawler.crawl(target)
        tid = self.db.get_target_id(utils.get_domain(target)) or self.db.insert_target(target)
        self.db.insert_endpoints(tid, results.get("endpoints", []), source="crawler")
        utils.save_results(results, f"{self.output_dir}/crawl_{utils.sanitize_filename(target)}.json")
        return results

    def run_takeover(self, target):
        subs = self.recon.enumerate_subdomains(target)
        results = self.takeover.check_subdomains([s["subdomain"] for s in subs])
        tid = self.db.get_target_id(target) or self.db.insert_target(target)
        self._persist_findings(tid, results)
        utils.save_results(results, f"{self.output_dir}/takeover_{utils.sanitize_filename(target)}.json")
        return results

    def run_fingerprint(self, target):
        results = self.fingerprint.analyze_urls([utils.normalize_url(target)])
        tid = self.db.get_target_id(utils.get_domain(target)) or self.db.insert_target(target)
        self.db.insert_technologies(tid, results.get("technologies", []))
        utils.save_results(results, f"{self.output_dir}/fingerprint_{utils.sanitize_filename(target)}.json")
        return results

    def run_ctlog(self, domain):
        results = {"subdomains": self.ctlog.fetch_subdomains(domain)}
        tid = self.db.insert_target(domain)
        self.db.insert_subdomains(tid, [{"subdomain": s, "ip": ""} for s in results["subdomains"]])
        utils.save_results(results, f"{self.output_dir}/ctlog_{utils.sanitize_filename(domain)}.json")
        return results

    def run_wayback(self, domain):
        results = {"urls": self.wayback.fetch_urls(domain)}
        utils.save_results(results, f"{self.output_dir}/wayback_{utils.sanitize_filename(domain)}.json")
        return results

    def run_s3(self, domain):
        results = self.s3_scanner.scan_domain(domain)
        tid = self.db.insert_target(domain)
        self._persist_findings(tid, results)
        utils.save_results(results, f"{self.output_dir}/s3_{utils.sanitize_filename(domain)}.json")
        return results

    def run_gitscan(self, target):
        results = self.git_scanner.scan(target)
        tid = self.db.get_target_id(utils.get_domain(target)) or self.db.insert_target(target)
        self._persist_findings(tid, results)
        utils.save_results(results, f"{self.output_dir}/gitscan_{utils.sanitize_filename(target)}.json")
        return results

    def run_nuclei(self, target):
        results = self.nuclei.scan_target(target)
        tid = self.db.get_target_id(utils.get_domain(target)) or self.db.insert_target(target)
        self._persist_findings(tid, results)
        utils.save_results(results, f"{self.output_dir}/nuclei_{utils.sanitize_filename(target)}.json")
        return results

    def run_screenshot(self, urls_file):
        with open(urls_file, "r", encoding="utf-8") as f:
            urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        results = self.screenshot.capture_batch(urls)
        utils.save_results(results, f"{self.output_dir}/screenshots.json")
        return results

    def run_waf(self, target):
        results = self.waf.detect_batch([utils.normalize_url(target)])
        utils.save_results(results, f"{self.output_dir}/waf_{utils.sanitize_filename(target)}.json")
        return results

    def run_api_fuzz(self, target):
        results = self.api_fuzzer.scan(target)
        utils.save_results(results, f"{self.output_dir}/api_fuzz_{utils.sanitize_filename(target)}.json")
        return results

    def run_dashboard(self, host="127.0.0.1", port=5000):
        print(f"[*] Dashboard: http://{host}:{port}")
        from modules.dashboard import app
        app.run(host=host, port=port, debug=False)

    def run_js_analyze(self, urls_file):
        with open(urls_file, "r", encoding="utf-8") as f:
            urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        results = self.js_analyzer.analyze_urls(urls)
        utils.save_results(results, f"{self.output_dir}/js_analyze.json")
        return results

    def run_full(self, target):
        print(f"[*] Full pipeline: {target}")
        self.current_target = target; tid = self.db.insert_target(target)
        results = {"target": target,
            "recon": self.run_recon(target), "ctlog": self.run_ctlog(target), "wayback": self.run_wayback(target),
            "crawl": self.run_crawl(target), "fuzz": self.run_fuzz(target), "scan": self.run_scan(target),
            "takeover": self.run_takeover(target), "s3": self.run_s3(target), "gitscan": self.run_gitscan(target),
            "fingerprint": self.run_fingerprint(target)}
        safe = utils.sanitize_filename(target)
        utils.save_results(results, f"{self.output_dir}/full_{safe}.json")
        self.report.generate_and_save(results, target, self.output_dir)
        print(f"[*] Complete. Saved to {self.output_dir}/full_{safe}.json")
        return results


# ═══════════════════════════════════════════════════════════════════
# CLI / TUI dispatch
# ═══════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="BBAT v3.2.0 — Bug Bounty Automation Toolkit\n  CLI: python main.py recon example.com\n  TUI: python main.py --tui",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("command", nargs="?", default="", choices=[
        "recon", "scan", "fuzz", "crawl", "full", "takeover", "js_analyze",
        "fingerprint", "ctlog", "wayback", "s3", "gitscan", "nuclei",
        "screenshot", "waf", "api_fuzz", "dashboard"
    ], help="BBAT module command")
    parser.add_argument("target", nargs="?", default="", help="Target domain, URL, or file")
    parser.add_argument("--tui", action="store_true", help="Launch the interactive Textual TUI")
    parser.add_argument("--config", default="config.json", help="Path to configuration file")
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard host")
    parser.add_argument("--port", type=int, default=5000, help="Dashboard port")
    args = parser.parse_args()

    if args.tui:
        launch_tui()
        return

    bbat = BBAT()
    cmd_map = {
        "recon": bbat.run_recon, "scan": bbat.run_scan, "fuzz": bbat.run_fuzz,
        "crawler": bbat.run_crawl, "full": bbat.run_full, "takeover": bbat.run_takeover,
        "js_analyze": bbat.run_js_analyze, "fingerprint": bbat.run_fingerprint,
        "ctlog": bbat.run_ctlog, "wayback": bbat.run_wayback,
        "s3": bbat.run_s3, "gitscan": bbat.run_gitscan,
        "nuclei": bbat.run_nuclei, "screenshot": bbat.run_screenshot,
        "waf": bbat.run_waf, "api_fuzz": bbat.run_api_fuzz,
        "dashboard": lambda: bbat.run_dashboard(args.host, args.port),
    }

    if not args.command:
        parser.error("No command provided. Use --tui for the interactive interface.")
    if args.command not in cmd_map:
        parser.error(f"Unknown command: {args.command}")

    # Screenshots / JS need a file path; everything else needs a target
    if args.command in ("js_analyze", "screenshot"):
        if not args.target:
            parser.error("js_analyze / screenshot requires a file path")
    elif args.command != "dashboard" and not args.target:
        parser.error(f"{args.command} requires a target")

    cmd_map[args.command](args.target)


def launch_tui():
    """Launch the Textual TUI interface."""
    try:
        import tui; app = tui.BBATApp(); app.run()
    except ImportError as e:
        print(f"[!] TUI requires textual and rich. Install: pip install textual rich")
        print(f"    Missing: {e}")


if __name__ == "__main__":
    main()
