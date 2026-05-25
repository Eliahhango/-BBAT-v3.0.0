"""
NucleiScanner module for BBAT.
Runs Nuclei template-based vulnerability scans if installed.
"""

import subprocess
import json
import os
from typing import List, Dict


class NucleiScannerModule:
    """Integrates with ProjectDiscovery Nuclei for CVE and template scanning."""

    def __init__(self, config: dict):
        self.config = config.get("nuclei", {})
        self.templates_dir = self.config.get("templates_dir", "")
        self.severity = self.config.get("severity", "critical,high,medium")
        self.rate_limit = self.config.get("rate_limit", 150)
        self.timeout = self.config.get("timeout", 10)
        self.concurrency = self.config.get("concurrency", 25)
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

    def scan_target(self, target: str, output_file: str = None) -> List[Dict]:
        """Run nuclei scan on a single target."""
        if not self._check_installed():
            return [{"error": "Nuclei not found. Install: https://github.com/projectdiscovery/nuclei"}]

        if not output_file:
            output_file = f"nuclei_{target.replace('/', '_').replace(':', '_')}.json"

        cmd = [
            "nuclei",
            "-u", target,
            "-json",
            "-o", output_file,
            "-rl", str(self.rate_limit),
            "-c", str(self.concurrency),
            "-timeout", str(self.timeout),
        ]

        if self.severity:
            cmd.extend(["-severity", self.severity])
        if self.templates_dir and os.path.exists(self.templates_dir):
            cmd.extend(["-t", self.templates_dir])
        if self.headless:
            cmd.append("-headless")

        print(f"[*] Running Nuclei scan on {target}...")
        try:
            subprocess.run(cmd, timeout=300, check=False)
        except subprocess.TimeoutExpired:
            return [{"error": "Nuclei scan timed out after 300s", "target": target}]
        except Exception as e:
            return [{"error": str(e), "target": target}]

        # Parse results
        findings = []
        if os.path.exists(output_file):
            with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
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
        for target in targets:
            findings = self.scan_target(target)
            all_findings.extend(findings)
        return all_findings
