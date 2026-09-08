"""
SPA Renderer — uses Playwright to render JavaScript-heavy pages
and extract the actual static files loaded at runtime.
Falls back gracefully if Playwright is not installed.
"""

import re
import logging
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

try:
    from playwright.sync_api import sync_playwright  # type: ignore[import-not-found]
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


def is_available() -> bool:
    return HAS_PLAYWRIGHT


def render_and_extract(url: str, timeout_ms: int = 30000) -> dict:
    """
    Render a page with a headless browser and extract:
    - Final rendered HTML
    - All network requests (JS, CSS, API calls, XHR, fetch)
    - Console messages
    - Cookies set

    Returns dict with keys: html, requests, console, cookies, errors
    """
    if not HAS_PLAYWRIGHT:
        return {"html": "", "requests": [], "console": [], "cookies": [], "errors": ["Playwright not installed"]}

    collected_requests = []
    console_msgs = []
    errors = []

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                ignore_https_errors=True,
            )
            page = context.new_page()

            # Capture network requests
            def on_request(req):
                try:
                    collected_requests.append({
                        "url": req.url,
                        "method": req.method,
                        "resource_type": req.resource_type,
                        "headers": dict(req.headers) if req.headers else {},
                    })
                except:
                    pass

            # Capture console
            def on_console(msg):
                try:
                    console_msgs.append({
                        "type": msg.type,
                        "text": msg.text,
                    })
                except:
                    pass

            # Capture errors
            def on_page_error(err):
                errors.append(str(err))

            page.on("request", on_request)
            page.on("console", on_console)
            page.on("pageerror", on_page_error)

            # Navigate and wait for network idle
            page.goto(url, wait_until="networkidle", timeout=timeout_ms)

            # Wait a bit more for lazy-loaded content
            page.wait_for_timeout(2000)

            # Scroll to trigger lazy loading
            page.evaluate("""
                async () => {
                    for (let i = 0; i < 3; i++) {
                        window.scrollBy(0, window.innerHeight);
                        await new Promise(r => setTimeout(r, 500));
                    }
                    window.scrollTo(0, 0);
                }
            """)
            page.wait_for_timeout(1000)

            # Get final rendered HTML
            html = page.content()

            # Get cookies
            cookies = []
            for c in context.cookies():
                cookies.append({
                    "name": c["name"],
                    "value": c["value"][:50],  # truncate values
                    "domain": c.get("domain", ""),
                    "path": c.get("path", ""),
                    "secure": c.get("secure", False),
                    "httpOnly": c.get("httpOnly", False),
                    "sameSite": c.get("sameSite", ""),
                })

            browser.close()

            return {
                "html": html,
                "requests": collected_requests,
                "console": console_msgs,
                "cookies": cookies,
                "errors": errors,
            }

    except Exception as e:
        return {"html": "", "requests": [], "console": [], "cookies": [], "errors": [str(e)]}


def extract_static_urls(render_result: dict, base_url: str) -> set:
    """Extract static file URLs from rendered page network requests."""
    static_types = {"script", "stylesheet", "fetch", "xhr", "other"}
    urls = set()

    for req in render_result.get("requests", []):
        rtype = req.get("resource_type", "")
        req_url = req.get("url", "")

        if rtype in static_types and req_url:
            urls.add(req_url)

        # Also extract API endpoints from XHR/fetch
        if rtype in ("fetch", "xhr") and req_url:
            urls.add(req_url)

    # Also parse the rendered HTML for any additional refs
    html = render_result.get("html", "")
    if html:
        url_pattern = re.compile(r"""(?:["'`])((https?://[^\s"'`<>]+?|/[a-zA-Z0-9._\-/]+\.[a-zA-Z0-9]+))(?:["'`])""")
        for m in url_pattern.finditer(html):
            url = m.group(1)
            if url.startswith("/"):
                url = urljoin(base_url, url)
            urls.add(url)

    return urls


def extract_runtime_endpoints(render_result: dict) -> set:
    """Extract API endpoints from actual network requests at runtime."""
    endpoints = set()
    for req in render_result.get("requests", []):
        if req.get("resource_type") in ("fetch", "xhr"):
            method = req.get("method", "GET").upper()
            url = req.get("url", "")
            if url:
                parsed = urlparse(url)
                path = parsed.path
                if path and not path.endswith((".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff")):
                    endpoints.add(f"{method} {path}")
    return endpoints