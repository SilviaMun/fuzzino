"""
Scan Diff — compare two scan reports to show what changed.
New findings, resolved findings, changed severity, new files, etc.
"""

import json


def diff_scans(old_report: dict, new_report: dict) -> dict:
    """
    Compare two scan reports.
    Returns a structured diff with new, resolved, and changed findings.
    """
    old_findings = old_report.get("findings", [])
    new_findings = new_report.get("findings", [])

    # Key each finding by (description, source_url, evidence[:80])
    def finding_key(f):
        return (
            f.get("description", ""),
            f.get("source_url", ""),
            f.get("evidence", "")[:80],
        )

    old_keyed = {finding_key(f): f for f in old_findings}
    new_keyed = {finding_key(f): f for f in new_findings}

    old_keys = set(old_keyed.keys())
    new_keys = set(new_keyed.keys())

    # New findings (in new but not in old)
    added = [new_keyed[k] for k in (new_keys - old_keys)]

    # Resolved findings (in old but not in new)
    resolved = [old_keyed[k] for k in (old_keys - new_keys)]

    # Changed severity (same finding, different severity)
    changed = []
    for k in (old_keys & new_keys):
        old_sev = old_keyed[k].get("severity", "")
        new_sev = new_keyed[k].get("severity", "")
        if old_sev != new_sev:
            changed.append({
                "finding": new_keyed[k],
                "old_severity": old_sev,
                "new_severity": new_sev,
            })

    # Endpoint diff
    old_ep = set(old_report.get("api_endpoints", []))
    new_ep = set(new_report.get("api_endpoints", []))
    new_endpoints = sorted(new_ep - old_ep)
    removed_endpoints = sorted(old_ep - new_ep)

    # Dependency diff
    def dep_key(d):
        return (d.get("name", ""), d.get("version", ""))

    old_deps = {dep_key(d): d for d in old_report.get("dependencies", [])}
    new_deps = {dep_key(d): d for d in new_report.get("dependencies", [])}

    added_deps = [new_deps[k] for k in set(new_deps) - set(old_deps)]
    removed_deps = [old_deps[k] for k in set(old_deps) - set(new_deps)]

    # Files diff
    old_files = set(f.get("url", "") for f in old_report.get("file_details", []))
    new_files = set(f.get("url", "") for f in new_report.get("file_details", []))
    new_file_urls = sorted(new_files - old_files)
    removed_file_urls = sorted(old_files - new_files)

    # Severity comparison
    old_counts = old_report.get("severity_counts", {})
    new_counts = new_report.get("severity_counts", {})

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    severity_diff = {}
    for sev in severity_order:
        old_c = old_counts.get(sev, 0)
        new_c = new_counts.get(sev, 0)
        if old_c != new_c:
            severity_diff[sev] = {"old": old_c, "new": new_c, "delta": new_c - old_c}

    return {
        "old_scan": {
            "target": old_report.get("target", ""),
            "date": old_report.get("scan_date", ""),
            "total_findings": old_report.get("total_findings", 0),
            "files_scanned": old_report.get("files_scanned", 0),
        },
        "new_scan": {
            "target": new_report.get("target", ""),
            "date": new_report.get("scan_date", ""),
            "total_findings": new_report.get("total_findings", 0),
            "files_scanned": new_report.get("files_scanned", 0),
        },
        "summary": {
            "new_findings": len(added),
            "resolved_findings": len(resolved),
            "changed_severity": len(changed),
            "severity_diff": severity_diff,
        },
        "new_findings": sorted(added, key=lambda f: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(f.get("severity","INFO"))),
        "resolved_findings": sorted(resolved, key=lambda f: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(f.get("severity","INFO"))),
        "changed_severity": changed,
        "new_endpoints": new_endpoints,
        "removed_endpoints": removed_endpoints,
        "new_dependencies": added_deps,
        "removed_dependencies": removed_deps,
        "new_files": new_file_urls,
        "removed_files": removed_file_urls,
    }