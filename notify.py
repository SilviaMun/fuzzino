"""
Notification module — sends alerts when scans complete.
Supports: webhook (generic), Slack, email (SMTP).
"""

import json
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import httpx

logger = logging.getLogger(__name__)


async def send_webhook(url: str, payload: dict, headers: dict | None = None) -> bool:
    """Send a generic webhook POST."""
    try:
        async with httpx.AsyncClient() as client:
            h = {"Content-Type": "application/json"}
            if headers:
                h.update(headers)
            r = await client.post(url, json=payload, headers=h, timeout=10)
            return r.status_code < 400
    except Exception as e:
        logger.error(f"Webhook failed: {e}")
        return False


async def send_slack(webhook_url: str, scan_report: dict) -> bool:
    """Send scan results to Slack via incoming webhook."""
    target = scan_report.get("target", "unknown")
    total = scan_report.get("total_findings", 0)
    counts = scan_report.get("severity_counts", {})
    crit = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)

    color = "#dc2626" if crit > 0 else "#f97316" if high > 0 else "#22c55e" if total == 0 else "#eab308"
    emoji = "🔴" if crit > 0 else "🟠" if high > 0 else "🟢" if total == 0 else "🟡"

    sev_text = " · ".join(f"{k}: {v}" for k, v in counts.items() if v > 0) or "None"

    payload = {
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{emoji} Scan Complete: {target}"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Findings:* {total}"},
                        {"type": "mrkdwn", "text": f"*Files scanned:* {scan_report.get('files_scanned', 0)}"},
                        {"type": "mrkdwn", "text": f"*Severity:* {sev_text}"},
                        {"type": "mrkdwn", "text": f"*Model:* {scan_report.get('model', 'N/A')}"},
                    ]
                },
            ]
        }]
    }

    return await send_webhook(webhook_url, payload)


def send_email(smtp_host: str, smtp_port: int, sender: str, password: str,
               recipient: str, scan_report: dict, use_tls: bool = True) -> bool:
    """Send scan results via email."""
    try:
        target = scan_report.get("target", "unknown")
        total = scan_report.get("total_findings", 0)
        counts = scan_report.get("severity_counts", {})

        subject = f"[Fuzzino] {target} — {total} findings"
        if counts.get("CRITICAL", 0) > 0:
            subject = f"🔴 {subject}"
        elif counts.get("HIGH", 0) > 0:
            subject = f"🟠 {subject}"

        sev_lines = "\n".join(f"  {k}: {v}" for k, v in counts.items() if v > 0)
        body = f"""Fuzzino Report
{'='*40}

Target:    {target}
Date:      {scan_report.get('scan_date', '')}
Model:     {scan_report.get('model', '')}
Files:     {scan_report.get('files_scanned', 0)}
Findings:  {total}

Severity:
{sev_lines or '  None'}

Top findings:
"""
        for f in scan_report.get("findings", [])[:10]:
            body += f"\n  [{f.get('severity','')}] {f.get('description','')}"
            body += f"\n    Source: {f.get('source_url','')}\n"

        msg = MIMEMultipart()
        msg["From"] = sender
        msg["To"] = recipient
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            if use_tls:
                server.starttls()
            if password:
                server.login(sender, password)
            server.send_message(msg)

        return True
    except Exception as e:
        logger.error(f"Email failed: {e}")
        return False


async def notify_scan_complete(scan_report: dict, config: dict):
    """
    Send notifications based on config.
    config can contain:
      webhook_url: str
      slack_url: str
      email: {smtp_host, smtp_port, sender, password, recipient}
    """
    results = {}

    if config.get("webhook_url"):
        results["webhook"] = await send_webhook(config["webhook_url"], {
            "event": "scan_complete",
            "target": scan_report.get("target"),
            "total_findings": scan_report.get("total_findings"),
            "severity_counts": scan_report.get("severity_counts"),
            "scan_date": scan_report.get("scan_date"),
        })

    if config.get("slack_url"):
        results["slack"] = await send_slack(config["slack_url"], scan_report)

    email_cfg = config.get("email")
    if email_cfg and email_cfg.get("recipient"):
        results["email"] = send_email(
            email_cfg.get("smtp_host", "smtp.gmail.com"),
            email_cfg.get("smtp_port", 587),
            email_cfg.get("sender", ""),
            email_cfg.get("password", ""),
            email_cfg["recipient"],
            scan_report,
        )

    return results