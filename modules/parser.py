"""
Parser module for BBAT.
Processes and extracts data from responses and results.
"""

import json
import re
from typing import Dict, List, Any


class ParserModule:
    """Result parser and data extractor."""

    @staticmethod
    def extract_emails(text: str) -> List[str]:
        """Extract email addresses from text."""
        pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        return list(set(re.findall(pattern, text)))

    @staticmethod
    def extract_ips(text: str) -> List[str]:
        """Extract IPv4 addresses from text."""
        pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        return list(set(re.findall(pattern, text)))

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract URLs from text."""
        pattern = r"https?://[^\s\"'\u003c\u003e)]+"
        return list(set(re.findall(pattern, text)))

    @staticmethod
    def extract_api_keys(text: str) -> List[Dict]:
        """Extract potential API keys and secrets from text."""
        findings = []
        patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"[0-9a-zA-Z/+=]{40}",
            "Generic API Key": r"[aA][pP][iI][-_]?[kK][eE][yY][\s]*[=:]+[\s]*['\"][^'\"]{16,}['\"]",
            "Private Key": r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
            "JWT Token": r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
        }
        for name, pattern in patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                findings.append({"type": name, "matches": matches})
        return findings

    @staticmethod
    def parse_nmap_output(xml_content: str) -> List[Dict]:
        """Parse Nmap XML output into Python dicts."""
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_content)
            hosts = []
            for host in root.findall("host"):
                addr = host.find("address")
                if addr is not None:
                    ip = addr.get("addr")
                    ports = []
                    for port in host.findall(".//port"):
                        ports.append({
                            "port": int(port.get("portid")),
                            "protocol": port.get("protocol"),
                            "state": port.find("state").get("state") if port.find("state") is not None else "unknown",
                            "service": port.find("service").get("name") if port.find("service") is not None else "unknown"
                        })
                    hosts.append({"ip": ip, "ports": ports})
            return hosts
        except Exception as e:
            return [{"error": str(e)}]

    @staticmethod
    def generate_markdown_report(data: Dict) -> str:
        """Generate a Markdown report from results."""
        lines = ["# BBAT Report\n", f"**Target:** {data.get('target', 'N/A')}\n", "---\n"]
        for section, content in data.items():
            if section == "target":
                continue
            lines.append(f"## {section.title()}\n")
            lines.append(f"```json\n{json.dumps(content, indent=2)}\n```\n")
        return "\n".join(lines)
