"""
app/slack_alert.py
------------------
Slack webhook notifications for critical anomalies.
"""

from __future__ import annotations

import os
from typing import Any

import requests


def notify_critical_anomalies(
    run_id: int,
    anomalies: list[dict[str, Any]],
    webhook_url: str | None = None,
) -> bool:
    """
    Send a Slack alert for critical anomalies.

    Returns True when a request was attempted and succeeded, otherwise False.
    """
    url = (webhook_url or os.environ.get("LOGGUARD_SLACK_WEBHOOK_URL", "")).strip()
    if not url or not anomalies:
        return False

    lines = []
    for a in anomalies[:5]:
        ip = a.get("ip_address", "unknown")
        score = float(a.get("anomaly_score") or 0.0)
        lines.append(f"• `{ip}` — score {(score * 100):.1f}%")

    payload = {
        "text": (
            f"🚨 LogGuard critical anomalies detected (Run #{run_id})\n"
            + "\n".join(lines)
        )
    }
    resp = requests.post(url, json=payload, timeout=5)
    return 200 <= resp.status_code < 300
