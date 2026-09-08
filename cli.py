#!/usr/bin/env python3
"""
Fuzzino CLI

Direct mode (Ollama locale):
  python cli.py https://target.com

Relay mode (Ollama via server remoto):
  python cli.py https://target.com --ollama http://192.168.1.50:8080/api/relay --user admin --password secret
"""

import argparse
import json
import sys
import requests
from scanner import StaticScanner

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m\033[1m", "HIGH": "\033[91m",
    "MEDIUM": "\033[93m", "LOW": "\033[94m", "INFO": "\033[90m",
}
RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[90m"


def progress(stage, message, pct):
    bar_len = 30
    filled = int(bar_len * pct / 100)
    bar = "█" * filled + "░" * (bar_len - filled)
    sys.stdout.write(f"\r  [{bar}] {pct:3d}% | {message[:70]:<70}")
    sys.stdout.flush()
    if pct >= 100:
        print()


def print_report(report):
    print(f"\n{'='*80}")
    print(f"{BOLD}  STATIC FILE SECURITY SCAN REPORT{RESET}")
    print(f"{'='*80}")
    print(f"  Target:    {report['target']}")
    print(f"  Date:      {report['scan_date']}")
    print(f"  Model:     {report['model']}")
    print(f"  Files:     {report['files_scanned']}")
    print(f"  Findings:  {report['total_findings']}")
    print()

    counts = report.get("severity_counts", {})
    if counts:
        print(f"  {BOLD}Severity breakdown:{RESET}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            c = counts.get(sev, 0)
            if c:
                color = SEVERITY_COLORS.get(sev, "")
                print(f"    {color}{sev:<10}{RESET} {c}")
        print()

    det = report.get("detector_counts", {})
    if det:
        print(f"  {BOLD}Detection source:{RESET}")
        for d_name, d_count in det.items():
            print(f"    {d_name:<20} {d_count}")
        print()

    if not report["findings"]:
        print(f"  {BOLD}No significant findings.{RESET}\n")
    else:
        print(f"  {BOLD}FINDINGS{RESET}")
        print(f"  {'-'*76}")
        for i, f in enumerate(report["findings"], 1):
            sev = f.get("severity", "?")
            color = SEVERITY_COLORS.get(sev, "")
            det_tag = f"{DIM}[{f.get('detector', '?')}]{RESET}"
            print(f"\n  {BOLD}#{i}{RESET} [{color}{sev}{RESET}] {f.get('category', 'N/A')} {det_tag}")
            print(f"     {f.get('description', 'N/A')}")
            print(f"     Source: {f.get('source_url', 'N/A')}")
            evidence = f.get("evidence", "N/A")
            if len(evidence) > 120:
                evidence = evidence[:120] + "..."
            print(f"     Evidence: {evidence}")
            if f.get("line_number"):
                print(f"     Line: {f['line_number']}")
            print(f"     Impact: {f.get('impact', 'N/A')}")
            print(f"     Fix: {f.get('recommendation', 'N/A')}")

    endpoints = report.get("api_endpoints", [])
    if endpoints:
        print(f"\n  {BOLD}API ENDPOINTS DISCOVERED{RESET}")
        print(f"  {'-'*76}")
        for ep in endpoints:
            print(f"    {ep}")

    deps = report.get("dependencies", [])
    if deps:
        print(f"\n  {BOLD}DEPENDENCIES{RESET}")
        print(f"  {'-'*76}")
        for d in deps:
            vuln = f"{SEVERITY_COLORS['HIGH']}VULNERABLE{RESET}" if d.get("vulnerable") else f"{DIM}ok{RESET}"
            cve = f" ({d['cve']})" if d.get("cve") else ""
            print(f"    {d.get('name','?')} {d.get('version','?')} [{vuln}]{cve}")

    # Data flows confirmed by LLM
    flows = report.get("data_flows", [])
    if flows:
        exploitable = [f for f in flows if f.get("exploitable")]
        if exploitable:
            print(f"\n  {BOLD}CONFIRMED DATA FLOWS{RESET}")
            print(f"  {'-'*76}")
            for df in exploitable:
                print(f"    {SEVERITY_COLORS['HIGH']}⚡{RESET} {df.get('source','')} → {df.get('sink','')}")
                print(f"       {df.get('explanation','')}")

    print(f"\n{'='*80}\n")


def authenticate_relay(ollama_url, username, password):
    """Login to the relay server and return a session with auth cookie."""
    base = ollama_url.split("/api/relay")[0]
    sess = requests.Session()
    sess.verify = False  # self-signed cert
    try:
        r = sess.post(
            f"{base}/api/login",
            json={"username": username, "password": password},
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("ok"):
            return sess
        else:
            print(f"  Login failed: {data.get('error', 'unknown error')}")
            return None
    except Exception as e:
        print(f"  Login failed: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Static File Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Direct Ollama (locale)
  python cli.py https://target.com

  # Via relay (Ollama non esposto)
  python cli.py https://target.com --ollama http://192.168.1.50:8080/api/relay --user admin --password secret

  # Con proxy per raggiungere il target (VPN)
  python cli.py https://target.com --proxy socks5://10.0.0.1:1080

  # Export
  python cli.py https://target.com -o report.json --html report.html
        """,
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--ollama", default="http://localhost:11434", help="Ollama API URL or relay URL")
    parser.add_argument("--model", default="qwen2.5-coder:32b", help="Model name")
    parser.add_argument("--proxy", help="HTTP/SOCKS proxy for target requests")
    parser.add_argument("--rate-limit", type=float, default=0.1, help="Seconds between requests (default: 0.1)")
    parser.add_argument("--output", "-o", help="Save JSON report to file")
    parser.add_argument("--html", help="Save HTML report to file")
    parser.add_argument("--list-models", action="store_true", help="List available models and exit")
    # Crawl & render
    parser.add_argument("--no-crawl", action="store_true", help="Disable recursive crawling")
    parser.add_argument("--max-pages", type=int, default=20, help="Max pages to crawl (default: 20)")
    parser.add_argument("--render", default="auto", choices=["auto", "true", "false"],
                        help="SPA rendering: auto (detect), true (always), false (never)")
    # Relay auth
    parser.add_argument("--user", "-u", help="Username for relay authentication")
    parser.add_argument("--password", "-p", help="Password for relay authentication")

    args = parser.parse_args()

    is_relay = "/api/relay" in args.ollama

    print(f"\n{BOLD}Static File Security Scanner{RESET}")
    print(f"  Ollama:     {args.ollama} {'(relay)' if is_relay else '(direct)'}")
    print(f"  Model:      {args.model}")
    if args.proxy:
        print(f"  Proxy:      {args.proxy}")
    print(f"  Rate limit: {args.rate_limit}s")

    # If relay mode, authenticate first and pass the session
    relay_session = None
    if is_relay:
        if not args.user or not args.password:
            print(f"\n  Error: Relay mode requires --user and --password")
            print(f"  Usage: --ollama http://server:8080/api/relay --user admin --password secret")
            sys.exit(1)
        print(f"  Authenticating to relay...", end=" ")
        relay_session = authenticate_relay(args.ollama, args.user, args.password)
        if not relay_session:
            sys.exit(1)
        print(f"OK ✓")

    scanner = StaticScanner(
        ollama_host=args.ollama,
        model=args.model,
        proxy=args.proxy,
        rate_limit=args.rate_limit,
        enable_crawl=not args.no_crawl,
        max_crawl_pages=args.max_pages,
        enable_renderer=args.render,
    )

    # If using relay, inject the authenticated session for Ollama requests
    if relay_session:
        scanner.ollama_session = relay_session

    if args.list_models:
        check = scanner.check_ollama()
        if not check["ok"]:
            print(f"Error: Cannot reach Ollama at {args.ollama}: {check['error']}")
            sys.exit(1)
        print("\nAvailable models:")
        for m in check["models"]:
            print(f"  - {m}")
        sys.exit(0)

    print()
    check = scanner.check_ollama()
    if not check["ok"]:
        print(f"Error: Cannot reach Ollama at {args.ollama}")
        print(f"  {check['error']}")
        sys.exit(1)
    if not check["model_available"]:
        print(f"Warning: Model '{args.model}' not found. Available: {', '.join(check['models'])}")
        sys.exit(1)

    print(f"  Ollama OK ✓\n")

    scanner.set_progress_callback(progress)
    report = scanner.run(args.url)
    print_report(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"JSON report saved to {args.output}")

    if args.html:
        html = scanner.generate_report_html(report)
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"HTML report saved to {args.html}")


if __name__ == "__main__":
    main()