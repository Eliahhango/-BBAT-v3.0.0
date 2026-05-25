"""
Notifier module for BBAT.
Sends notifications via Slack and Discord webhooks.
"""

import requests
import json
from typing import Dict, Optional


class NotifierModule:
    """Sends notifications for BBAT findings."""

    def __init__(self, config: dict):
        self.config = config.get("notifier", {})
        self.slack_webhook = self.config.get("slack_webhook", "")
        self.discord_webhook = self.config.get("discord_webhook", "")
        self.notify_on = self.config.get("notify_on", ["high", "critical"])

    def _send_slack(self, message: str, title: str = "BBAT Alert") -> bool:
        """Send notification to Slack webhook."""
        if not self.slack_webhook:
            return False
        payload = {
            "text": f"*{title}*\n{message}",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": title}
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": message}
                }
            ]
        }
        try:
            resp = requests.post(self.slack_webhook, json=payload, timeout=10)
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def _send_discord(self, message: str, title: str = "BBAT Alert") -> bool:
        """Send notification to Discord webhook."""
        if not self.discord_webhook:
            return False
        payload = {
            "content": None,
            "embeds": [
                {
                    "title": title,
                    "description": message,
                    "color": 15158332,  # Orange
                    "footer": {"text": "BBAT - Bug Bounty Automation Toolkit"},
                }
            ]
        }
        try:
            resp = requests.post(self.discord_webhook, json=payload, timeout=10)
            return resp.status_code in (200, 204)
        except requests.RequestException:
            return False

    def notify(self, title: str, message: str, severity: str = "info") -> Dict:
        """Send notification if severity matches notify_on threshold."""
        result = {"sent": False, "slack_ok": False, "discord_ok": False, "severity": severity}

        if severity.lower() not in [s.lower() for s in self.notify_on]:
            result["reason"] = "Severity below threshold"
            return result

        if self.slack_webhook:
            result["slack_ok"] = self._send_slack(message, title)
        if self.discord_webhook:
            result["discord_ok"] = self._send_discord(message, title)

        result["sent"] = result["slack_ok"] or result["discord_ok"]
        return result

    def notify_findings(self, findings: list, target: str) -> Dict:
        """Send summary notification for a batch of findings."""
        critical = [f for f in findings if f.get("severity", "").lower() == "critical"]
        high = [f for f in findings if f.get("severity", "").lower() == "high"]
        medium = [f for f in findings if f.get("severity", "").lower() == "medium"]

        lines = [
            f"Target: `{target}`",
            f"Total findings: {len(findings)}",
            f"Critical: {len(critical)} | High: {len(high)} | Medium: {len(medium)}",
            "",
        ]

        for f in findings[:10]:  # Limit to top 10
            lines.append(f"• [{f.get('severity', 'unknown').upper()}] {f.get('type', 'finding')}: {f.get('description', '')[:200]}")

        if len(findings) > 10:
            lines.append(f"... and {len(findings) - 10} more findings.")

        message = "\n".join(lines)
        max_sev = "info"
        if critical:
            max_sev = "critical"
        elif high:
            max_sev = "high"
        elif medium:
            max_sev = "medium"

        return self.notify("BBAT Scan Results", message, max_sev)
