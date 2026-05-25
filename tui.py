"""
BBAT TUI v3.3.0 — Operator-Grade Command Interface
OpenClaw-inspired: True-black, command-centric, minimal chrome.
Launch: bbat
"""

import asyncio
import os
import sys
from typing import List, Dict
from dataclasses import dataclass, field

BASE_DIR = os.environ.get("BBAT_BASE_DIR", os.path.dirname(os.path.abspath(__file__)))
MODULES_DIR = os.path.join(BASE_DIR, "modules")
if BASE_DIR not in sys.path:     sys.path.insert(0, BASE_DIR)
if MODULES_DIR not in sys.path:  sys.path.insert(0, MODULES_DIR)

from textual.app import App, ComposeResult
from textual.containers import Container, Vertical
from textual.widgets import Input, Static, RichLog, ProgressBar
from textual.binding import Binding
from textual.reactive import reactive

THEME = {
    "bg":       "#000000", "fg":       "#E0E0E0", "accent":   "#B388FF",
    "success":  "#00E676", "warn":     "#FFEA00", "err":      "#FF1744",
    "dim":      "#424242", "border":   "#212121",
}

BANNER = """[bold #B388FF]
 ▄▄▄▄    ▄▄▄      ▄▄▄      ▄███▄   █▄▄▄▄
█   ▀▄   █▄▀ ▀▄   █   █   █▀   ▀  █  ▄▀
▀▄▄    ▄  █   █   █▀▀▀▀   ██▄▄    █▀▀
    ▀▀ █  ███▀    █      █▄   ▄▀ █
▀▄▄▄▄▀   █        █       ▀███▀   █
         ▀                        ▀
         [dim]Bug Bounty Automation Toolkit v3.3.0[/dim]
[/bold #B388FF]"""

MODULE_MAP = {
    "recon": "Reconnaissance", "ctlog": "CT Log Enum",
    "crawler": "Web Crawler", "fuzzer": "Directory Fuzzer",
    "scanner": "Vulnerability Scanner", "takeover": "Subdomain Takeover",
    "s3": "S3 Bucket Scan", "gitscan": "Git/SVN Exposure",
    "fingerprint": "Tech Fingerprint", "waf": "WAF Detection",
    "api_fuzz": "API Fuzzer", "screenshot": "Screenshot Capture",
    "all": "All Modules",
}


@dataclass
class ModuleTask:
    name: str
    label: str
    status: str = "pending"
    results: list = field(default_factory=list)


class ScanOrchestrator:
    """Executes BBAT modules asynchronously."""

    def __init__(self, target: str, selected: List[str], app: "BBATApp"):
        self.target = target
        self.selected = selected
        self.app = app
        self.tasks = {key: ModuleTask(key, MODULE_MAP.get(key, key))
                      for key in MODULE_MAP if key != "all"}
        self._stop = False

    async def run(self):
        total = len(self.selected); done = 0
        self.app.emit("[bold #B388FF]━" * 40 + "[/]")
        self.app.emit(f"[bold #B388FF]▶ TARGET  {self.target}[/]")
        self.app.emit(f"[bold #B388FF]▶ MODULES {', '.join(self.selected)}[/]")
        self.app.emit("[bold #B388FF]━" * 40 + "[/]")

        for mod_key in self.selected:
            if self._stop:
                self.app.alert("[bold #FF1744]⏹ ABORTED BY OPERATOR[/]")
                break
            task = self.tasks[mod_key]; task.status = "running"
            self.app.emit(f"[bold #B388FF]▶ {task.label.upper()} ...[/]")
            try:
                result = await self._dispatch(mod_key)
                task.results = [result] if not isinstance(result, list) else result
                task.status = "completed"
                self.app.emit(f"[bold #00E676]✔ {task.label} COMPLETED[/]")
                if isinstance(result, dict) and result.get("findings"):
                    for f in result["findings"]:
                        self.app.card(f)
            except Exception as exc:
                task.status = "error"
                self.app.alert(f"[bold #FF1744]✘ {task.label} FAILED: {exc}[/]")
            done += 1; self.app.update_progress(done / total)

        self.app.emit("[bold #B388FF]━" * 40 + "[/]")
        self.app.emit("[bold #00E676]✔ SESSION COMPLETE[/]")
        self.app.show_cmd()

    def stop(self):
        self._stop = True

    async def _dispatch(self, mod_key: str):
        from utils import load_config
        config = load_config(os.path.join(BASE_DIR, "config.json"))
        config.setdefault("recon", {})
        config["recon"]["wordlist"] = config["recon"].get("wordlist",
            os.path.join(BASE_DIR, "wordlists", "common.txt"))

        if mod_key == "recon":
            from recon import ReconModule; m = ReconModule(config)
            return {"subdomains": m.enumerate_subdomains(self.target),
                    "dns_records": m.resolve_dns(self.target),
                    "port_scan": m.port_scan(self.target),
                    "whois": m.whois_lookup(self.target)}
        if mod_key == "ctlog":
            from ctlog import CTLogModule; m = CTLogModule(config)
            return {"subdomains": m.fetch_subdomains(self.target)}
        if mod_key == "crawler":
            from crawler import CrawlerModule; m = CrawlerModule(config)
            return m.crawl(self.target)
        if mod_key == "fuzzer":
            from fuzzer import FuzzerModule; m = FuzzerModule(config)
            return m.fuzz(self.target)
        if mod_key == "scanner":
            from scanner import ScannerModule; m = ScannerModule(config)
            return m.scan(self.target)
        if mod_key == "takeover":
            from takeover import TakeoverModule; from recon import ReconModule
            rm = ReconModule(config); m = TakeoverModule(config)
            return m.check_subdomains([s["subdomain"] for s in rm.enumerate_subdomains(self.target)])
        if mod_key == "s3":
            from s3_scanner import S3ScannerModule; m = S3ScannerModule(config)
            return m.scan_domain(self.target)
        if mod_key == "gitscan":
            from git_scanner import GitScannerModule; m = GitScannerModule(config)
            return m.scan(self.target)
        if mod_key == "fingerprint":
            from fingerprint import FingerprintModule; from utils import normalize_url
            return FingerprintModule(config).analyze_urls([normalize_url(self.target)])
        if mod_key == "waf":
            from waf_detector import WAFDetectorModule; from utils import normalize_url
            return WAFDetectorModule(config).detect(normalize_url(self.target))
        if mod_key == "api_fuzz":
            from api_fuzzer import ApiFuzzerModule; m = ApiFuzzerModule(config)
            return m.scan(self.target)
        if mod_key == "screenshot":
            from screenshot import ScreenshotModule; m = ScreenshotModule(config)
            return m.capture_batch([f"http://{self.target}"])
        return {}


class BBATApp(App):
    """OpenClaw-inspired command-terminal interface."""

    CSS = """
    Screen { background: #000000; color: #E0E0E0; }
    .banner { text-align: center; padding-top: 1; }
    .cmd-bar { dock: top; height: 3; }
    #cmd-input { border: none; background: #000000; color: #B388FF; content-align: left middle; }
    #cmd-input:focus { border-bottom: solid #B388FF; }
    .divider { color: #212121; text-align: center; }
    #live-log { background: #000000; border: none; padding: 1; }
    #progress { height: 8px; background: transparent; margin: 0 2; }
    #progress > .bar { background: #B388FF; }
    #status-strip { height: 1; background: #000000; color: #424242; content-align: center middle; }
    """

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=True),
        Binding("ctrl+s", "save", "Save", show=True),
        Binding("ctrl+c", "abort", "Abort", show=True),
    ]

    progress_value: reactive[float] = reactive(0.0)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orchestrator: ScanOrchestrator | None = None
        self.scan_task: asyncio.Task | None = None
        self._scanning = False

    def compose(self) -> ComposeResult:
        yield Static(BANNER, id="banner", classes="banner")
        yield Static("[dim]example.com,recon,waf,scanner  |  example.com,all[/dim]", id="hint", classes="divider")
        yield Input(placeholder="target.com,recon,scanner  —  press ENTER to execute", id="cmd-input", classes="cmd-bar")
        yield Static("━" * 80, classes="divider")
        yield RichLog(id="live-log", auto_scroll=True, wrap=True)
        yield ProgressBar(id="progress", total=1.0, show_eta=False, show_percentage=False)
        yield Static("bbat v3.3.0  |  ctrl+s save  |  ctrl+c abort  |  ctrl+q quit", id="status-strip")

    def on_mount(self):
        self._welcome()
        self.query_one("#cmd-input", Input).focus()

    def _welcome(self):
        self.emit("[bold #B388FF]Welcome, operator.[/]")
        self.emit("[dim]Syntax: target.com,module1,module2  (or 'all')[/dim]")
        self.emit("[dim]Modules:[/dim] " + ", ".join([f"[bold #B388FF]{k}[/]" for k in list(MODULE_MAP.keys())[:-1]]))
        self.emit("")

    # ── ENTER → Execute ──
    def on_input_submitted(self, event: Input.Submitted) -> None:
        if not self._scanning:
            self._parse_and_run(event.value)

    def _parse_and_run(self, raw: str):
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        if not parts:
            self.alert("[bold #FF1744]✘ No input[/]"); return

        target = parts[0]
        selected = parts[1:]
        if "all" in selected:
            selected = [k for k in MODULE_MAP if k != "all"]
        if not selected:
            selected = ["recon", "scanner", "fuzzer", "takeover"]

        invalid = [s for s in selected if s not in MODULE_MAP]
        if invalid:
            self.alert(f"[bold #FF1744]✘ Unknown: {', '.join(invalid)}[/]"); return

        self._launch(target, selected)

    def _launch(self, target: str, selected: List[str]):
        self._scanning = True
        inp = self.query_one("#cmd-input", Input)
        inp.disabled = True
        inp.placeholder = "SCANNING...  (ctrl+c to abort)"
        self.query_one("#progress", ProgressBar).update(progress=0.0)
        self.orchestrator = ScanOrchestrator(target, selected, self)
        self.scan_task = asyncio.create_task(self.orchestrator.run())

    def action_abort(self):
        if self.orchestrator:
            self.orchestrator.stop()
        if self.scan_task and not self.scan_task.done():
            self.scan_task.cancel()
        self._scanning = False
        self.show_cmd()
        self.alert("[bold #FFEA00]⏹ ABORTED[/]")

    def action_save(self):
        import os; from datetime import datetime; from utils import save_results
        os.makedirs("./output", exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        report = {"timestamp": f"{ts}Z", "target": self.orchestrator.target if self.orchestrator else "N/A"}
        path = f"./output/bbat_{ts}.json"
        save_results(report, path)
        self.emit(f"[bold #00E676]📄 SAVED → {path}[/]")

    # ── UI Bridges ──
    def emit(self, line: str):
        self.query_one("#live-log", RichLog).write(line)

    def update_progress(self, value: float):
        self.query_one("#progress", ProgressBar).update(progress=value)

    def alert(self, line: str):
        self.emit(line)

    def card(self, finding: Dict):
        sev = finding.get("severity", "info")
        desc = finding.get("description", "")
        url = finding.get("url", "")
        color = {"critical":"#FF1744","high":"#FFEA00","medium":"#B388FF","low":"#00E676","info":"#E0E0E0"}.get(sev, "#E0E0E0")
        self.emit(
            f"[bold {color}]┏ ALERT: {sev.upper()}[/bold {color}]\n"
            f"[bold {color}]┃ TYPE: {finding.get('type','N/A')}[/bold {color}]\n"
            f"[bold {color}]┃ DESC: {desc[:90]}{'...' if len(desc)>90 else ''}[/bold {color}]\n"
            f"[bold {color}]┃ URL:  {url}[/bold {color}]\n"
            f"[bold {color}]┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold {color}]"
        )

    def show_cmd(self):
        self._scanning = False
        inp = self.query_one("#cmd-input", Input)
        inp.disabled = False; inp.value = ""
        inp.placeholder = "target.com,recon,scanner  —  press ENTER to execute"
        inp.focus()


if __name__ == "__main__":
    BBATApp().run()
