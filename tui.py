"""
BBAT TUI — Professional Terminal User Interface
Textual + Rich powered interface for BBAT v3.2.0
Launch: bbat  (after install.sh)  OR  python tui.py
"""

import asyncio
import os
import sys
from typing import List, Dict, Any
from dataclasses import dataclass, field

# ─── Absolute-path resolution ────────────────────────────────────
# When installed via install.sh, BBAT_BASE_DIR is set by /usr/local/bin/bbat.
# When run standalone via `python tui.py`, fall back to __file__.
BASE_DIR = os.environ.get("BBAT_BASE_DIR", os.path.dirname(os.path.abspath(__file__)))
MODULES_DIR = os.path.join(BASE_DIR, "modules")
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
if MODULES_DIR not in sys.path:
    sys.path.insert(0, MODULES_DIR)

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Input, Button, Checkbox, Static,
    DataTable, RichLog, ProgressBar,
    TabbedContent, TabPane, Footer, Label,
)
from textual.binding import Binding
from textual.reactive import reactive
from textual.css.query import NoMatches

# ═══════════════════════════════════════════════════════════════════
# DRACULA THEME COLOR CONSTANTS
# ═══════════════════════════════════════════════════════════════════
DRACULA = {
    "bg":        "#21222c", "fg":        "#f8f8f2", "comment":   "#6272a4",
    "cyan":      "#8be9fd", "green":     "#50fa7b", "orange":    "#ffb86c",
    "pink":      "#ff79c6", "purple":    "#bd93f9", "red":       "#ff5555",
    "yellow":    "#f1fa8c", "dark":      "#282a36", "row_alt":   "#44475a",
}

BBAT_LOGO = """
┏━┓┏━┓┏━━━┓┏━━━━┓
┃ ┗┛ ┃┃┏━┓┃┃┏┓┏┓┃
┃┏┓┏┓┃┃┃ ┃┃┗┛┃┃┗┛
┃┃┃┃┃┃┃┗━┛┃  ┃┃
┃┃┃┃┃┃┃┏━┓┃  ┃┃
┗┛┗┛┗┛┗┛ ┗┛  ┗┛
 Bug Bounty Automation Toolkit v3.2.0 — Dracula Edition
""".strip()

# ═══════════════════════════════════════════════════════════════════
# MODULE REGISTRY
# ═══════════════════════════════════════════════════════════════════
MODULES = [
    ("recon",       "Reconnaissance",         True),
    ("ctlog",       "CT Log Enum",            True),
    ("crawler",     "Web Crawler",            True),
    ("fuzzer",      "Directory Fuzzer",       True),
    ("scanner",     "Vulnerability Scanner",  True),
    ("takeover",    "Subdomain Takeover",     True),
    ("s3",          "S3 Bucket Scan",         False),
    ("gitscan",     "Git/SVN Exposure",       False),
    ("fingerprint", "Tech Fingerprint",       True),
    ("waf",         "WAF Detection",          False),
    ("api_fuzz",    "API Fuzzer",             False),
    ("screenshot",  "Screenshot Capture",     False),
]


# ═══════════════════════════════════════════════════════════════════
# SCAN ORCHESTRATOR (async bridge into BBAT modules)
# ═══════════════════════════════════════════════════════════════════
@dataclass
class ModuleTask:
    name: str
    label: str
    status: str = "pending"
    results: list = field(default_factory=list)


class ScanOrchestrator:
    """Executes BBAT modules asynchronously while streaming to the TUI."""

    def __init__(self, target: str, selected: List[str], app: "BBATApp"):
        self.target = target
        self.selected = selected
        self.app = app
        self.tasks: Dict[str, ModuleTask] = {
            m[0]: ModuleTask(m[0], m[1]) for m in MODULES
        }
        self._stop = False

    # ─── Main Execution Loop ────────────────────────────────────────
    async def run(self):
        total = len(self.selected); done = 0
        self.app.log_line("[purple]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/purple]")
        self.app.log_line(f"[purple]🎯  TARGET  → {self.target}[/purple]")
        self.app.log_line(f"[purple]📦  MODULES → {len(self.selected)} selected[/purple]")
        self.app.log_line("[purple]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/purple]")
        for mod_key in self.selected:
            if self._stop:
                self.app.log_line("[red]⚠  Interrupted by user.[/red]"); break
            task = self.tasks[mod_key]; task.status = "running"
            self.app.update_module_status(mod_key, "[yellow]RUNNING[/yellow]")
            self.app.log_line(f"[cyan]▶ {task.label} ...[/cyan]")
            try:
                result = await self._dispatch(mod_key)
                task.results = [result] if not isinstance(result, list) else result
                task.status = "completed"
                self.app.update_module_status(mod_key, "[green]COMPLETED[/green]")
                self.app.log_line(f"[green]✔ {task.label} done[/green]")
                if isinstance(result, dict) and result.get("findings"):
                    for f in result["findings"]:
                        self.app.add_finding(f)
                        sev = f.get("severity", "info")
                        color = "red" if sev == "critical" else "orange" if sev == "high" else "yellow"
                        self.app.log_line(f"  [{color}]{sev.upper():8} {f.get('type')}: {f.get('description','')[:70]}[/]")
            except Exception as exc:
                task.status = "error"
                self.app.update_module_status(mod_key, "[red]ERROR[/red]")
                self.app.log_line(f"[red]✘ {task.label} failed: {exc}[/red]")
            done += 1; self.app.update_progress(done / total)
        self.app.log_line("[purple]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/purple]")
        self.app.log_line("[green]✔ Session finished.[/green]")
        self.app.switch_tab("summary")

    def stop(self):
        self._stop = True

    # ─── Module Dispatcher (absolute paths) ───────────────────────────
    async def _dispatch(self, mod_key: str):
        from utils import load_config
        config_path = os.path.join(BASE_DIR, "config.json")
        config = load_config(config_path)
        config.setdefault("recon", {})
        config["recon"]["wordlist"] = config["recon"].get("wordlist",
            os.path.join(BASE_DIR, "wordlists", "common.txt"))

        if mod_key == "recon":
            from recon import ReconModule; m = ReconModule(config)
            return {"subdomains": m.enumerate_subdomains(self.target),
                    "dns_records": m.resolve_dns(self.target),
                    "port_scan": m.port_scan(self.target), "whois": m.whois_lookup(self.target)}

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
            subs = rm.enumerate_subdomains(self.target)
            return m.check_subdomains([s["subdomain"] for s in subs])

        if mod_key == "s3":
            from s3_scanner import S3ScannerModule; m = S3ScannerModule(config)
            return m.scan_domain(self.target)

        if mod_key == "gitscan":
            from git_scanner import GitScannerModule; m = GitScannerModule(config)
            return m.scan(self.target)

        if mod_key == "fingerprint":
            from fingerprint import FingerprintModule; from utils import normalize_url
            m = FingerprintModule(config)
            return m.analyze_urls([normalize_url(self.target)])

        if mod_key == "waf":
            from waf_detector import WAFDetectorModule; from utils import normalize_url
            m = WAFDetectorModule(config)
            return m.detect(normalize_url(self.target))

        if mod_key == "api_fuzz":
            from api_fuzzer import ApiFuzzerModule; m = ApiFuzzerModule(config)
            return m.scan(self.target)

        if mod_key == "screenshot":
            from screenshot import ScreenshotModule; m = ScreenshotModule(config)
            return m.capture_batch([f"http://{self.target}"])

        return {}


# ═══════════════════════════════════════════════════════════════════
# TUI APPLICATION
# ═══════════════════════════════════════════════════════════════════
class BBATApp(App):
    """Professional Textual TUI for BBAT."""

    CSS = """
    Screen { background: #21222c; color: #f8f8f2; }
    .header-box { height: 8; content-align: center middle; }
    .logo { color: #50fa7b; text-style: bold; }
    .subtitle { text-align: center; color: #bd93f9; padding-bottom: 1; }
    #sidebar { width: 30; background: #282a36; border-right: solid #6272a4; }
    #target-input { border: solid #bd93f9; margin: 1 2; }
    #execute-btn { background: #50fa7b; color: #21222c; }
    #stop-btn  { background: #ff5555; color: #f8f8f2; }
    #module-grid { grid-size: 3; grid-gutter: 1; height: auto; margin: 0 2; }
    #module-grid Checkbox { color: #8be9fd; }
    #progress { height: 1; color: #50fa7b; margin: 1 2; }
    #live-log { background: #282a36; border: solid #6272a4; }
    #summary-table { background: #282a36; border: solid #6272a4; }
    DataTable .datatable--header { background: #44475a; color: #f8f8f2; }
    DataTable .datatable--cursor { background: #bd93f9; }
    """

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=True),
        Binding("ctrl+s", "save_report", "Save Report", show=True),
        Binding("ctrl+k", "stop_scan", "Stop Scan", show=True),
    ]

    progress_value: reactive[float] = reactive(0.0)
    findings_list: reactive[list] = reactive([], layout=False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orchestrator: ScanOrchestrator | None = None
        self.scan_task: asyncio.Task | None = None

    # ─── Compose ───────────────────────────────────────────────────
    def compose(self) -> ComposeResult:
        yield Static(BBAT_LOGO, id="logo", classes="header-box logo")
        yield Static("Bug Bounty Automation Toolkit v3.2.0 — Dracula Edition", classes="subtitle")

        with Horizontal():
            # Sidebar
            with Vertical(id="sidebar"):
                yield Label("[bold #bd93f9]Target[/]", id="target-label")
                yield Input(placeholder="example.com  |  https://target.com", id="target-input")
                yield Static("")
                yield Label("[bold #bd93f9]Module Selector[/]", id="modules-label")
                with Horizontal(id="module-grid"):
                    for key, label, default in MODULES:
                        yield Checkbox(label, value=default, id=f"chk-{key}")
                yield Static("")
                yield Button("▶  Execute Scan", id="execute-btn", variant="success")
                yield Button("⏹  Stop Scan",  id="stop-btn",  variant="error")
                yield Static("")
                yield Label("[bold #6272a4]Shortcuts[/]")
                yield Label("[cyan]Ctrl+S[/] Save Report")
                yield Label("[red]Ctrl+K[/]  Stop Scan")
                yield Label("[yellow]Ctrl+Q[/] Quit")

            # Main area
            with Vertical(id="main-content"):
                yield Label("[bold #bd93f9]Module Status[/]", id="status-label")
                yield DataTable(id="status-table", zebra_stripes=True)
                with TabbedContent("Live Log", "Summary", id="tabbed-content"):
                    with TabPane("Live Log", id="tab-live-log"):
                        yield RichLog(id="live-log", auto_scroll=True, wrap=True)
                    with TabPane("Summary", id="tab-summary"):
                        yield DataTable(id="summary-table", zebra_stripes=True)
                yield ProgressBar(id="progress", total=1.0, show_eta=False)

        yield Footer()

    # ─── Mount ─────────────────────────────────────────────────────
    def on_mount(self):
        st = self.query_one("#status-table", DataTable)
        st.add_columns("Module", "Status", "Results")
        for key, label, _ in MODULES:
            st.add_row(label, "⏳ Pending", "—", key=key)
        su = self.query_one("#summary-table", DataTable)
        su.add_columns("Severity", "Type", "Description", "URL")
        self.log_line("[purple]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/purple]")
        self.log_line("[green]  Welcome to BBAT TUI v3.2.0[/green]")
        self.log_line("[cyan]  Enter target → select modules → EXECUTE[/cyan]")
        self.log_line("[purple]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/purple]")

    # ─── Events ────────────────────────────────────────────────────
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "execute-btn":
            self.action_start_scan()
        elif event.button.id == "stop-btn":
            self.action_stop_scan()

    # ─── Actions ────────────────────────────────────────────────────
    def action_start_scan(self):
        inp = self.query_one("#target-input", Input)
        target = inp.value.strip()
        if not target:
            self.log_line("[red]✘  Please enter a target domain/URL.[/red]"); return
        selected: List[str] = []
        for key, _, _ in MODULES:
            if self.query_one(f"#chk-{key}", Checkbox).value:
                selected.append(key)
        if not selected:
            self.log_line("[red]✘  No modules selected.[/red]"); return
        self.query_one("#summary-table", DataTable).clear()
        self.findings_list.clear()
        self.update_progress(0.0)
        self.switch_tab("log")
        st = self.query_one("#status-table", DataTable)
        for key, _, _ in MODULES:
            st.update_cell(key, "Status", "⏳ Pending")
            st.update_cell(key, "Results", "—")
        self.orchestrator = ScanOrchestrator(target, selected, self)
        self.scan_task = asyncio.create_task(self.orchestrator.run())
        self.log_line(f"[cyan]▶ Launching {len(selected)} modules against [bold]{target}[/bold] ...[/cyan]")

    def action_stop_scan(self):
        if self.orchestrator:
            self.orchestrator.stop()
            self.log_line("[yellow]⚠  Stop requested.[/yellow]")
        if self.scan_task and not self.scan_task.done():
            self.scan_task.cancel()

    def action_save_report(self):
        import os, json
        from datetime import datetime
        from utils import save_results
        os.makedirs("./output", exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        report = {
            "timestamp": f"{ts}Z",
            "target": self.orchestrator.target if self.orchestrator else "N/A",
            "findings": self.findings_list,
        }
        path = f"./output/tui_report_{ts}.json"
        save_results(report, path)
        self.log_line(f"[green]📄  Report saved → {path}[/green]")

    # ─── UI Bridges ────────────────────────────────────────────────
    def log_line(self, line: str):
        self.query_one("#live-log", RichLog).write(line)

    def update_module_status(self, key: str, status_text: str):
        try:
            self.query_one("#status-table", DataTable).update_cell(key, "Status", status_text)
        except NoMatches:
            pass

    def update_progress(self, value: float):
        self.query_one("#progress", ProgressBar).update(progress=value)

    def add_finding(self, finding: Dict):
        self.findings_list.append(finding)
        self.query_one("#summary-table", DataTable).add_row(
            f"[bold {self._sev_color(finding.get('severity','info'))}]{finding.get('severity','info').upper()}[/]",
            finding.get("type", "N/A"),
            (finding.get("description", "")[:55] + "...") if len(finding.get("description", "")) > 55 else finding.get("description", ""),
            finding.get("url", ""),
        )

    def switch_tab(self, tab_name: str):
        self.query_one("#tabbed-content", TabbedContent).active = f"tab-{tab_name}"

    @staticmethod
    def _sev_color(sev: str) -> str:
        return {"critical":"red","high":"orange","medium":"yellow","low":"green","info":"comment"}.get(sev, "white")


# ═══════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = BBATApp()
    app.run()
