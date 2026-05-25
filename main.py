#!/usr/bin/env python3
"""
BBAT (Bug Bounty Automation Toolkit) v3.2.0
A modular, extensible framework for authorized bug bounty reconnaissance.

When called as `btc` with no arguments -> launches the TUI.
When called with arguments -> runs the CLI workflow.

Install globally via:
    curl -sSL https://raw.githubusercontent.com/Eliahhango/-BBAT-v3.0.0/main/install.sh | bash
"""

import argparse
import sys
import os

# ─── Absolute path resolution ─────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODULES_DIR = os.path.join(BASE_DIR, "modules")
# Both paths needed: BASE_DIR for `from modules.xxx`, MODULES_DIR for `import xxx`
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
if MODULES_DIR not in sys.path:
    sys.path.insert(0, MODULES_DIR)

if "BBAT_BASE_DIR" not in os.environ:
    os.environ["BBAT_BASE_DIR"] = BASE_DIR

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
    """Main orchestrator."""

    def __init__(self):
        self.config = utils.load_config(os.path.join(BASE_DIR, "config.json"))
        self.output_dir = os.path.join(BASE_DIR, self.config["project"]["output_dir"])
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
        self.db = BBATDatabase(self.config.get("reporting", {}).get("db_path", os.path.join(BASE_DIR, "output/bbat.db")))

    # ─── Persistence helpers ───
    def _persist_recon(self, target_id: int, results: dict):
        if results.get("subdomains"):     self.db.insert_subdomains(target_id, results["subdomains"])
        if results.get("dns_records"):  self.db.insert_dns_records(target_id, results["dns_records"])
        if results.get("port_scan"):    self.db.insert_ports(target_id, results["port_scan"])

    def _persist_findings(self, target_id: int, findings: list):
        if findings:
            self.db.insert_findings(target_id, findings)
            self.notifier.notify_findings(findings, getattr(self, "current_target", "unknown"))

    # ─── Individual Commands ───
    def run_recon(self, target):
        print(f"[+] Reconnaissance: {target}")
        tid = self.db.insert_target(target)
        results = {"subdomains": self.recon.enumerate_subdomains(target), "dns_records": self.recon.resolve_dns(target),
                   "port_scan": self.recon.port_scan(target), "whois": self.recon.whois_lookup(target)}
        self._persist_recon(tid, results)
        utils.save_results(results, os.path.join(self.output_dir, f"recon_{utils.sanitize_filename(target)}.json"))
        return results

    def run_scan(self, target):
        results = self.scanner.scan(target)
        tid = self.db.get_target_id(utils.get_domain(target)) or self.db.insert_target(target)
        self._persist_findings(tid, results.get("findings", []))
        utils.save_results(results, os.path.join(self.output_dir, f"scan_{utils.sanitize_filename(target)}.json"))
        return results

    def run_fuzz(self, target):
        results = self.fuzzer.fuzz(target)
        tid = self.db.get_target_id(utils.get_domain(target)) or self.db.insert_target(target)
        self.db.insert_endpoints(tid, results.get("items", []), source="fuzzer")
        utils.save_results(results, os.path.join(self.output_dir, f"fuzz_{utils.sanitize_filename(target)}.json"))
        return results

    def run_crawl(self, target):
        results = self.crawler.crawl(target)
        tid = self.db.get_target_id(utils.get_domain(target)) or self.db.insert_target(target)
        self.db.insert_endpoints(tid, results.get("endpoints", []), source="crawler")
        utils.save_results(results, os.path.join(self.output_dir, f"crawl_{utils.sanitize_filename(target)}.json"))
        return results

    def run_takeover(self, target):
        subs = self.recon.enumerate_subdomains(target)
        results = self.takeover.check_subdomains([s["subdomain"] for s in subs])
        tid = self.db.get_target_id(target) or self.db.insert_target(target)
        self._persist_findings(tid, results)
        utils.save_results(results, os.path.join(self.output_dir, f"takeover_{utils.sanitize_filename(target)}.json"))
        return results

    def run_fingerprint(self, target):
        results = self.fingerprint.analyze_urls([utils.normalize_url(target)])
        tid = self.db.get_target_id(utils.get_domain(target)) or self.db.insert_target(target)
        self.db.insert_technologies(tid, results.get("technologies", []))
        utils.save_results(results, os.path.join(self.output_dir, f"fingerprint_{utils.sanitize_filename(target)}.json"))
        return results

    def run_ctlog(self, domain):
        results = {"subdomains": self.ctlog.fetch_subdomains(domain)}
        tid = self.db.insert_target(domain)
        self.db.insert_subdomains(tid, [{"subdomain": s, "ip": ""} for s in results["subdomains"]])
        utils.save_results(results, os.path.join(self.output_dir, f"ctlog_{utils.sanitize_filename(domain)}.json"))
        return results

    def run_wayback(self, domain):
        results = {"urls": self.wayback.fetch_urls(domain)}
        utils.save_results(results, os.path.join(self.output_dir, f"wayback_{utils.sanitize_filename(domain)}.json"))
        return results

    def run_s3(self, domain):
        results = self.s3_scanner.scan_domain(domain)
        tid = self.db.insert_target(domain)
        self._persist_findings(tid, results)
        utils.save_results(results, os.path.join(self.output_dir, f"s3_{utils.sanitize_filename(domain)}.json"))
        return results

    def run_gitscan(self, target):
        results = self.git_scanner.scan(target)
        tid = self.db.get_target_id(utils.get_domain(target)) or self.db.insert_target(target)
        self._persist_findings(tid, results)
        utils.save_results(results, os.path.join(self.output_dir, f"gitscan_{utils.sanitize_filename(target)}.json"))
        return results

    def run_nuclei(self, target):
        results = self.nuclei.scan_target(target)
        tid = self.db.get_target_id(utils.get_domain(target)) or self.db.insert_target(target)
        self._persist_findings(tid, results)
        utils.save_results(results, os.path.join(self.output_dir, f"nuclei_{utils.sanitize_filename(target)}.json"))
        return results

    def run_screenshot(self, urls_file):
        with open(urls_file, "r", encoding="utf-8") as f:
            urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        results = self.screenshot.capture_batch(urls)
        utils.save_results(results, os.path.join(self.output_dir, "screenshots.json"))
        return results

    def run_waf(self, target):
        results = self.waf.detect_batch([utils.normalize_url(target)])
        utils.save_results(results, os.path.join(self.output_dir, f"waf_{utils.sanitize_filename(target)}.json"))
        return results

    def run_api_fuzz(self, target):
        results = self.api_fuzzer.scan(target)
        utils.save_results(results, os.path.join(self.output_dir, f"api_fuzz_{utils.sanitize_filename(target)}.json"))
        return results

    def run_dashboard(self, host="127.0.0.1", port=5000):
        print(f"[*] Dashboard: http://{host}:{port}")
        from modules.dashboard import app
        app.run(host=host, port=port, debug=False)

    def run_js_analyze(self, urls_file):
        with open(urls_file, "r", encoding="utf-8") as f:
            urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        results = self.js_analyzer.analyze_urls(urls)
        utils.save_results(results, os.path.join(self.output_dir, "js_analyze.json"))
        return results

    def run_full(self, target):
        print(f"[*] Full pipeline: {target}")
        self.current_target = target; tid = self.db.insert_target(target)
        results = {
            "target": target, "recon": self.run_recon(target), "ctlog": self.run_ctlog(target),
            "wayback": self.run_wayback(target), "crawl": self.run_crawl(target),
            "fuzz": self.run_fuzz(target), "scan": self.run_scan(target),
            "takeover": self.run_takeover(target), "s3": self.run_s3(target),
            "gitscan": self.run_gitscan(target), "fingerprint": self.run_fingerprint(target)}
        safe = utils.sanitize_filename(target)
        utils.save_results(results, os.path.join(self.output_dir, f"full_{safe}.json"))
        self.report.generate_and_save(results, target, self.output_dir)
        print(f"[*] Complete. Saved to {self.output_dir}/full_{safe}.json")
        return results


# ══════════════════════════════════════════════════════════════════
# CLI / TUI dispatch
# ══════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="BBAT v3.2.0 — Bug Bounty Automation Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("module", nargs="?", default="", help="BBAT module (recon, scan, fuzz, full, ...)")
    parser.add_argument("target", nargs="?", default="", help="Target domain, URL, or file")
    parser.add_argument("--tui", action="store_true", help="Force TUI mode")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    # Default to TUI when no module argument given
    if not args.module or args.tui:
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

    if args.module not in cmd_map:
        parser.error(f"Unknown command: {args.module}")

    if args.module in ("js_analyze", "screenshot"):
        if not args.target:
            parser.error("js_analyze / screenshot requires a file path")
    elif args.module != "dashboard" and not args.target:
        parser.error(f"{args.module} requires a target")

    cmd_map[args.module](args.target)


def launch_tui():
    """Launch the Textual TUI — gracefully falls back if textual is missing."""
    try:
        import tui; app = tui.BBATApp(); app.run()
    except ImportError:
        from rich.console import Console
        Console().print("[bold red]BBAT TUI requires `textual` and `rich`[/bold red]")
        Console().print("  Install: [bold green]pip install textual rich[/bold green]")


if __name__ == "__main__":
    main()
