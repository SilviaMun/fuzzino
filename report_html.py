"""
Generate a self-contained HTML report from scan results.
"""

import json
from datetime import datetime


def generate_html_report(report: dict) -> str:
    target = _esc(report.get("target", ""))
    scan_date = report.get("scan_date", "")
    model = _esc(report.get("model", ""))
    files_scanned = report.get("files_scanned", 0)
    total = report.get("total_findings", 0)
    counts = report.get("severity_counts", {})
    det_counts = report.get("detector_counts", {})
    findings = report.get("findings", [])
    endpoints = report.get("api_endpoints", [])
    deps = report.get("dependencies", [])

    sev_pills = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c = counts.get(sev, 0)
        if c:
            sev_pills += f'<span class="pill pill-{sev.lower()}">{sev} {c}</span> '

    findings_html = ""
    if not findings:
        findings_html = '<div class="no-findings">No significant vulnerabilities found.</div>'
    else:
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "INFO").lower()
            evidence = _esc(f.get("evidence", ""))
            findings_html += f"""
            <div class="finding">
                <div class="finding-head">
                    <span class="num">#{i}</span>
                    <span class="sev sev-{sev}">{_esc(f.get('severity',''))}</span>
                    <span class="cat">{_esc(f.get('category',''))}</span>
                    <span class="det">[{_esc(f.get('detector',''))}]</span>
                </div>
                <div class="desc">{_esc(f.get('description',''))}</div>
                <table class="meta">
                    <tr><td class="lbl">Source</td><td class="mono">{_esc(f.get('source_url',''))}</td></tr>
                    <tr><td class="lbl">Evidence</td><td><code>{evidence}</code></td></tr>
                    {f'<tr><td class="lbl">Line</td><td>{f["line_number"]}</td></tr>' if f.get("line_number") else ''}
                    <tr><td class="lbl">Impact</td><td>{_esc(f.get('impact',''))}</td></tr>
                    <tr><td class="lbl">Remediation</td><td>{_esc(f.get('recommendation',''))}</td></tr>
                </table>
            </div>"""

    endpoints_html = ""
    if endpoints:
        endpoints_html = "<h2>API Endpoints Discovered</h2><ul class='ep-list'>"
        for ep in endpoints:
            endpoints_html += f"<li><code>{_esc(ep)}</code></li>"
        endpoints_html += "</ul>"

    deps_html = ""
    if deps:
        deps_html = "<h2>Dependencies</h2><table class='dep-table'><thead><tr><th>Library</th><th>Version</th><th>Status</th><th>CVE</th></tr></thead><tbody>"
        for d in deps:
            vuln_cls = "vuln" if d.get("vulnerable") else "ok"
            vuln_txt = "VULNERABLE" if d.get("vulnerable") else "OK"
            deps_html += f"<tr><td>{_esc(d.get('name',''))}</td><td class='mono'>{_esc(d.get('version',''))}</td><td class='{vuln_cls}'>{vuln_txt}</td><td class='mono'>{_esc(d.get('cve',''))}</td></tr>"
        deps_html += "</tbody></table>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Scan Report — {target}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, system-ui, 'Segoe UI', sans-serif; background: #fff; color: #1a1a2e; line-height: 1.6; padding: 40px; max-width: 900px; margin: 0 auto; font-size: 14px; }}
  h1 {{ font-size: 22px; font-weight: 700; margin-bottom: 4px; }}
  h2 {{ font-size: 16px; font-weight: 600; margin: 32px 0 12px; padding-bottom: 6px; border-bottom: 2px solid #e5e7eb; }}
  .subtitle {{ color: #6b7280; font-size: 13px; margin-bottom: 24px; }}
  .stats {{ display: flex; gap: 32px; margin-bottom: 24px; }}
  .stat-val {{ font-size: 32px; font-weight: 700; font-family: 'SF Mono', 'Consolas', monospace; }}
  .stat-label {{ font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: .5px; }}
  .pills {{ margin-bottom: 24px; }}
  .pill {{ display: inline-block; font-size: 12px; font-weight: 700; padding: 2px 10px; border-radius: 10px; margin-right: 6px; font-family: 'SF Mono', 'Consolas', monospace; }}
  .pill-critical {{ background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }}
  .pill-high {{ background: #fff7ed; color: #ea580c; border: 1px solid #fed7aa; }}
  .pill-medium {{ background: #fefce8; color: #ca8a04; border: 1px solid #fef08a; }}
  .pill-low {{ background: #eff6ff; color: #2563eb; border: 1px solid #bfdbfe; }}
  .pill-info {{ background: #f9fafb; color: #6b7280; border: 1px solid #e5e7eb; }}
  .finding {{ border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; margin-bottom: 12px; page-break-inside: avoid; }}
  .finding:hover {{ border-color: #c7d2fe; }}
  .finding-head {{ display: flex; align-items: center; gap: 8px; margin-bottom: 8px; flex-wrap: wrap; }}
  .num {{ font-weight: 700; color: #6b7280; font-size: 13px; }}
  .sev {{ font-size: 11px; font-weight: 700; padding: 1px 8px; border-radius: 4px; text-transform: uppercase; font-family: 'SF Mono', 'Consolas', monospace; }}
  .sev-critical {{ background: #fef2f2; color: #dc2626; }}
  .sev-high {{ background: #fff7ed; color: #ea580c; }}
  .sev-medium {{ background: #fefce8; color: #ca8a04; }}
  .sev-low {{ background: #eff6ff; color: #2563eb; }}
  .sev-info {{ background: #f9fafb; color: #6b7280; }}
  .cat {{ font-size: 12px; color: #6b7280; }}
  .det {{ font-size: 11px; color: #9ca3af; font-family: 'SF Mono', 'Consolas', monospace; }}
  .desc {{ font-size: 14px; font-weight: 500; margin-bottom: 10px; }}
  .meta {{ font-size: 13px; width: 100%; border-collapse: collapse; }}
  .meta td {{ padding: 4px 8px; vertical-align: top; border-top: 1px solid #f3f4f6; }}
  .lbl {{ font-weight: 600; color: #6b7280; width: 100px; white-space: nowrap; }}
  .mono {{ font-family: 'SF Mono', 'Consolas', monospace; font-size: 12px; }}
  code {{ background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 12px; word-break: break-all; }}
  .no-findings {{ padding: 40px; text-align: center; color: #16a34a; font-weight: 600; font-size: 16px; }}
  .ep-list {{ margin-left: 20px; }}
  .ep-list li {{ margin-bottom: 4px; }}
  .dep-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .dep-table th {{ text-align: left; padding: 8px; border-bottom: 2px solid #e5e7eb; font-size: 11px; text-transform: uppercase; color: #6b7280; }}
  .dep-table td {{ padding: 8px; border-bottom: 1px solid #f3f4f6; }}
  .vuln {{ color: #dc2626; font-weight: 700; }}
  .ok {{ color: #16a34a; }}
  .det-info {{ font-size: 12px; color: #6b7280; margin-bottom: 24px; }}
  @media print {{
    body {{ padding: 20px; }}
    .finding {{ break-inside: avoid; }}
  }}
  .footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #9ca3af; text-align: center; }}
</style>
</head>
<body>

<h1>Static File Security Scan Report</h1>
<div class="subtitle">
    Target: <strong>{target}</strong><br>
    Date: {scan_date} · Model: {model}
</div>

<div class="stats">
    <div><div class="stat-val">{files_scanned}</div><div class="stat-label">Files scanned</div></div>
    <div><div class="stat-val">{total}</div><div class="stat-label">Findings</div></div>
</div>

<div class="pills">{sev_pills}</div>

<div class="det-info">
    Detection: {det_counts.get('signature', 0)} signature (regex) · {det_counts.get('llm', 0)} LLM (contextual) 
</div>

<h2>Findings</h2>
{findings_html}

{endpoints_html}
{deps_html}

<div class="footer">
    Generated by Fuzzino · {scan_date}
</div>

</body>
</html>"""


def _esc(s):
    """HTML-escape a string."""
    if not s:
        return ""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )