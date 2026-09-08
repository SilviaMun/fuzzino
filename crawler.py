"""
Recursive Crawler — discovers internal links from the target
and follows them to find additional pages with different static assets.
"""

import re
import time
import logging
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class Crawler:
    def __init__(self, session, base_url, max_pages=30, rate_limit=0.2, verify_ssl=False):
        self.session = session
        self.base_url = base_url
        self.parsed_base = urlparse(base_url)
        self.base_domain = self.parsed_base.netloc
        self.max_pages = max_pages
        self.rate_limit = rate_limit
        self.verify_ssl = verify_ssl
        self.visited = set()
        self.pages = []  # list of {url, html, status_code}
        self.all_static_urls = set()
        self.progress_callback = None

    def set_progress_callback(self, callback):
        self.progress_callback = callback

    def _report(self, msg):
        if self.progress_callback:
            self.progress_callback(msg)

    def _is_same_origin(self, url):
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain or not parsed.netloc

    def _normalize_url(self, url):
        """Normalize URL: remove fragment, ensure absolute."""
        url = urljoin(self.base_url, url)
        parsed = urlparse(url)
        # Remove fragment
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized

    def _should_follow(self, url):
        """Decide if a URL should be crawled."""
        if not self._is_same_origin(url):
            return False

        parsed = urlparse(url)
        path = parsed.path.lower()

        # Skip static assets
        skip_ext = {
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz",
            ".mp3", ".mp4", ".webm", ".ogg", ".wav",
        }
        for ext in skip_ext:
            if path.endswith(ext):
                return False

        # Skip common noise
        skip_patterns = [
            "/wp-content/", "/wp-includes/", "/node_modules/",
            "javascript:", "mailto:", "tel:", "data:",
            "#", "void(0)",
        ]
        for pattern in skip_patterns:
            if pattern in url.lower():
                return False

        return True

    def _extract_links(self, html, page_url):
        """Extract internal links from HTML."""
        links = set()
        soup = BeautifulSoup(html, "html.parser")

        # <a> tags
        for tag in soup.find_all("a", href=True):
            url = self._normalize_url(urljoin(page_url, str(tag["href"])))
            if self._should_follow(url):
                links.add(url)

        # JS-based navigation patterns
        nav_patterns = [
            re.compile(r"""(?:href|to|path|route)\s*[=:]\s*["'](/[^"']+?)["']"""),
            re.compile(r"""(?:navigate|push|replace)\s*\(\s*["'](/[^"']+?)["']"""),
            re.compile(r"""(?:window\.location|location\.href)\s*=\s*["'](/[^"']+?)["']"""),
        ]
        for pat in nav_patterns:
            for m in pat.finditer(html):
                url = self._normalize_url(urljoin(page_url, m.group(1)))
                if self._should_follow(url):
                    links.add(url)

        return links

    def _extract_static_refs(self, html, page_url):
        """Extract static file references from a page."""
        static_urls = set()
        soup = BeautifulSoup(html, "html.parser")

        for tag in soup.find_all("script", src=True):
            static_urls.add(urljoin(page_url, str(tag["src"])))
        for tag in soup.find_all("link", href=True):
            static_urls.add(urljoin(page_url, str(tag["href"])))

        # Inline URL patterns
        url_pattern = re.compile(
            r"""(?:["'`])((https?://[^\s"'`<>]+?|/[a-zA-Z0-9._\-/]+\.[a-zA-Z0-9]+))(?:["'`])"""
        )
        for m in url_pattern.finditer(html):
            url = m.group(1)
            if url.startswith("/"):
                url = urljoin(page_url, url)
            static_urls.add(url)

        return static_urls

    def crawl(self, start_url=None):
        """
        BFS crawl from start_url.
        Returns list of pages found and set of all static file URLs.
        """
        start = start_url or self.base_url
        queue = [start]
        self.visited.add(start)

        while queue and len(self.pages) < self.max_pages:
            url = queue.pop(0)
            self._report(f"Crawling ({len(self.pages)+1}/{self.max_pages}): {url[:60]}")

            try:
                if self.rate_limit > 0:
                    time.sleep(self.rate_limit)

                resp = self.session.get(url, timeout=10, verify=self.verify_ssl, allow_redirects=True)

                content_type = resp.headers.get("content-type", "")
                if "text/html" not in content_type:
                    continue

                if resp.status_code != 200:
                    continue

                html = resp.text
                self.pages.append({
                    "url": url,
                    "html": html,
                    "status_code": resp.status_code,
                })

                # Extract static refs
                static = self._extract_static_refs(html, url)
                self.all_static_urls.update(static)

                # Extract and queue links
                links = self._extract_links(html, url)
                for link in links:
                    if link not in self.visited:
                        self.visited.add(link)
                        queue.append(link)

            except Exception as e:
                logger.debug(f"Crawl error on {url}: {e}")
                continue

        return self.pages, self.all_static_urls