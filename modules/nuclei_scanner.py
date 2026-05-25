"""
NucleiScanner module for BBAT.
Runs Nuclei template-based vulnerability scans if installed.
Subprocess arguments are strictly sanitized.
"""

import subprocess
import json
import os
import re
import shlex
from typing import List, Dict

# Regex for strict input sanitization
_SAFE_TARGET_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
_SAFE_PATH_RE = re.compile(r"^[\w./\\-~:]+$")
_SAFE_INT_RE = re.compile(r"^\d+$")


class NucleiScannerModule:
    """Integrates with ProjectDiscovery Nuclei for CVE and template scanning."""

    def __init__(self, config: dict):
        self.config = config.get("nuclei", {})
        self.templates_dir = self.config.get("templates_dir", "")
        self.severity = self.config.get("severity", "critical,high,medium")
        self.rate_limit = self.config.get("rate_limit", 150)
        self.timeout = self.config.get("timeout", 10)
        self.concurrency = self.config.get("conConcurrency", 25)
        self.headless = self.config.get("headless", False)
        self._check_installed()

    def _check_installed(self) -> bool:
        """Check if nuclei is available in PATH."""
        try:
            subprocess.run(
                ["nuclei", "-version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    @staticmethod
    def _sanitize_target(target: str) -> str:
        """Strictly sanitize a target URL/domain to prevent command injection."""
        cleaned = target.strip()
        if not _SAFE_TARGET_RE.match(cleaned):
            raise ValueError(f"Unsafe target rejected: {target}")
        return cleaned

    @staticmethod
    def _sanitize_path(path: str) -> str:
        """Strictly sanitize a filesystem path."""
        cleaned = path.strip()
        if not _SAFE_PATH_RE.match(cleaned):
            raise ValueError(f"Unsafe path rejected: {path}")
        return cleaned

    @staticmethod
    def _sanitize_int(value, default=10) -> str:
        v = str(value).strip()
        if not _SAFE_INT_RE.match(v):
            return str(default)
        return v

    def scan_target(self, target: str, output_file: str = None) -> List[Dict]:
        """Run nuclei scan with strictly sanitized arguments."""
        if not self._check_installed():
            return [{"error": "Nuclei not found. Install: https://github.com/projectdiscovery/nuclei"}]

        safe_target = self._sanitize_target(target)

        if not output_file:
            output_file = f"nuclei_{safe_target.replace('/', '_').replace(':', '_')}.json"
        safe_output = self._sanitize_path(output_file)

        cmd = [
            "nuclei",
            "-u", safe_target,
            "-json",
            "-o", safe_output,
            "-rl", self._sanitize_int(self.rate_limit, 150),
            "-c", self._sanitize_int(self.concurrency, 25),
            "-timeout", self._sanitize_int(self.timeout, 10),
        ]

        if self.severity:
            # Severity is a CSV string; split and validate each part
            sevs = [s.strip() for s in self.severity.split(",")]
            allowed = {"critical", "high", "medium", "low", "info"}
            valid_sevs = [s for s in sevs if s in allowed]
            if valid_sevs:
                cmd.extend(["-severity", ",".join(valid_sevs)])

        if self.templates_dir and os.path.exists(self.templates_dir):
            safe_templates = self._sanitize_path(self.templates_dir)
            cmd.extend(["-t", safe_templates])

        if self.headless:
            cmd.append("-headless")

        print(f"[*] Running Nuclei scan on {safe_target}...")
        try:
            subprocess.run(cmd, timeout=300, check=False)
        except subprocess.TimeoutExpired:
            return [{"error": "Nuclei scan timed out after 300s", "target": safe_target}]
        except ValueError as ve:
            return [{"error": f"Sanitization failed: {ve}", "target": safe_target}]
        except Exception as e:
            return [{"error": str(e), "target": safe_target}]

        # Parse results
        findings = []
        if os.path.exists(safe_output):
            with open(safe_output, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        finding = json.loads(line)
                        findings.append(finding)
                    except json.JSONDecodeError:
                        pass
        print(f"[+] Nuclei scan complete. Found {len(findings)} findings.")
        return findings

    def scan_targets(self, targets: List[str]) -> List[Dict]:
        """Run nuclei scan on multiple targets."""
        all_findings = []
        for t in targets:
            findings = self.scan_target(t)
            all_findings.extend(findings)
        return all_findings
