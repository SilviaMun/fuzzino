"""
Static File Security Scanner
Full pipeline: deobfuscate → beautify → AST → endpoints → secrets → deps → sinks → LLM
"""

import re
import json
import time
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from datetime import datetime
from pathlib import Path
from signatures import (
    scan_content, finding_to_dict, PROBE_PATHS, GRAPHQL_INTROSPECTION_QUERY,
)
from preprocess import preprocess_file, format_briefing_for_llm
from report_html import generate_html_report

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


from config import settings

STATIC_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".json", ".xml", ".yaml", ".yml", ".toml",
    ".html", ".htm", ".svg",
    ".map",
    ".env", ".config", ".conf",
    ".txt", ".md",
}

MAX_FILE_SIZE = settings.max_file_size_mb * 1024 * 1024
MAX_CONTENT_FOR_LLM = 15000

# Load system prompt from file
_PROMPT_PATH = Path(__file__).parent / "system_prompt.txt"
SYSTEM_PROMPT = _PROMPT_PATH.read_text(encoding="utf-8") if _PROMPT_PATH.exists() else ""

USER_PROMPT_TEMPLATE = """File: {url}
Type: {file_type}

═══ DETERMINISTIC BRIEFING ═══
{briefing}
═══ END BRIEFING ═══

File content:
```
{content}
```"""


def _is_spa(html: str) -> bool:
    """
    Detect if an HTML page is a SPA shell (almost empty body, JS-rendered).
    Checks for: empty root divs, framework markers, low text-to-markup ratio.
    """
    from bs4 import BeautifulSoup as BS

    soup = BS(html, "html.parser")
    body = soup.find("body")
    if not body:
        return False

    # 1. Check for framework root elements with no/minimal content
    spa_roots = body.select("#root, #app, #__next, #__nuxt, [id*=react], [id*=angular], [id*=vue], app-root, [ng-version]")
    for root in spa_roots:
        text = root.get_text(strip=True)
        # Root div exists but has very little text → SPA shell
        if len(text) < 50:
            return True

    # 2. Check for framework markers in scripts
    framework_markers = [
        "react", "ReactDOM", "__NEXT_DATA__", "__next",
        "ng-app", "ng-version", "angular",
        "Vue", "__vue__", "__VUE__", "createApp",
        "nuxt", "__nuxt", "__NUXT__",
        "svelte", "SvelteKit",
        "ember",
    ]
    scripts = body.find_all("script")
    all_script_text = " ".join(str(s.string or "") for s in scripts)
    all_script_src = " ".join(str(s.get("src", "")) for s in scripts)
    combined = all_script_text + all_script_src

    marker_hits = sum(1 for m in framework_markers if m.lower() in combined.lower())

    # 3. Check text-to-markup ratio
    body_text = body.get_text(strip=True)
    # Very little visible text but lots of markup → likely SPA
    if len(body_text) < 200 and len(html) > 2000 and marker_hits >= 1:
        return True

    # 4. Noscript tag with "enable JavaScript" message
    noscript = body.find("noscript")
    if noscript:
        noscript_text = noscript.get_text(strip=True).lower()
        if any(kw in noscript_text for kw in ["javascript", "enable", "browser"]):
            if len(body_text) < 300:
                return True

    return False


class StaticScanner:
    def __init__(
        self,
        ollama_host="http://localhost:11434",
        model="qwen2.5-coder:32b",
        proxy=None,
        rate_limit=0.1,
        verify_ssl=False,
        enable_crawl=True,
        max_crawl_pages=20,
        enable_renderer: str = "auto",
    ):
        self.ollama_host = ollama_host.rstrip("/")
        self.model = model
        self.rate_limit = rate_limit
        self.verify_ssl = verify_ssl
        self.enable_crawl = enable_crawl
        self.max_crawl_pages = max_crawl_pages
        self.enable_renderer = enable_renderer

        # Session for target requests (uses proxy)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        # Separate session for Ollama (no proxy)
        self.ollama_session = requests.Session()

        self.downloaded_files = []
        self.results = []
        
        self.all_api_endpoints = set()
        self.all_dependencies = []
        self.all_data_flows = []
        self.progress_callback = None

    def set_progress_callback(self, callback):
        self.progress_callback = callback

    def _report(self, stage, message, pct=0):
        if self.progress_callback:
            self.progress_callback(stage, message, pct)

    def _throttle(self):
        if self.rate_limit > 0:
            time.sleep(self.rate_limit)

    def check_ollama(self):
        try:
            r = self.ollama_session.get(f"{self.ollama_host}/api/tags", timeout=5)
            r.raise_for_status()
            models = [m["name"] for m in r.json().get("models", [])]
            available = any(self.model in m or self.model.split(":")[0] in m for m in models)
            return {"ok": True, "models": models, "model_available": available}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def list_models(self):
        try:
            r = self.ollama_session.get(f"{self.ollama_host}/api/tags", timeout=5)
            r.raise_for_status()
            return [m["name"] for m in r.json().get("models", [])]
        except:
            return []

    # ── PHASE 0: Fetch target ──

    def fetch_target(self, target_url):
        self._report("fetch", f"Fetching {target_url}...", 1)
        try:
            resp = self.session.get(target_url, timeout=15, verify=self.verify_ssl)
            self._report("fetch", "Target fetched", 2)
            return resp
        except Exception as e:
            self._report("error", f"Failed to fetch target: {e}", 0)
            return None

    # ── PHASE 1: Scrape & Download ──

    def scrape_static_files(self, target_url, initial_response=None):
        self._report("scrape", f"Parsing {target_url}...", 3)
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        found_urls = set()

        if initial_response is not None:
            resp = initial_response
        else:
            try:
                resp = self.session.get(target_url, timeout=15, verify=self.verify_ssl)
                resp.raise_for_status()
            except Exception as e:
                self._report("error", f"Failed to fetch target: {e}", 0)
                return []

        soup = BeautifulSoup(resp.text, "html.parser")

        for tag in soup.find_all("script", src=True):
            found_urls.add(urljoin(target_url, str(tag["src"])))
        for tag in soup.find_all("link", href=True):
            found_urls.add(urljoin(target_url, str(tag["href"])))
        for tag in soup.find_all("form", action=True):
            found_urls.add(urljoin(target_url, str(tag["action"])))
        for tag in soup.find_all("img", src=True):
            found_urls.add(urljoin(target_url, str(tag["src"])))
        for tag in soup.find_all("iframe", src=True):
            found_urls.add(urljoin(target_url, str(tag["src"])))
        for tag in soup.find_all("embed", src=True):
            found_urls.add(urljoin(target_url, str(tag["src"])))
        for tag in soup.find_all("object", data=True):
            found_urls.add(urljoin(target_url, str(tag["data"])))

        for meta in soup.find_all("meta", attrs={"http-equiv": "refresh"}):
            content = str(meta.get("content", ""))
            url_match = re.search(r'url=(.+)', content, re.IGNORECASE)
            if url_match:
                found_urls.add(urljoin(target_url, url_match.group(1).strip("'\"")))

        url_pattern = re.compile(
            r"""(?:["'`])((https?://[^\s"'`<>]+?|/[a-zA-Z0-9._\-/]+\.[a-zA-Z0-9]+))(?:["'`])"""
        )
        for match in url_pattern.finditer(resp.text):
            url = match.group(1)
            if url.startswith("/"):
                url = urljoin(base_url, url)
            found_urls.add(url)

        # Webpack chunks
        self._report("scrape", "Extracting webpack chunks...", 5)
        chunk_patterns = [
            re.compile(r"""[\"']([a-zA-Z0-9._\-/]+\.chunk\.js)[\"']"""),
            re.compile(r"""[\"']([a-zA-Z0-9._\-/]+\.bundle\.js)[\"']"""),
            re.compile(r"""(?:src|href)\s*[=:]\s*[\"']?(/static/[^\s\"'<>]+\.js)"""),
            re.compile(r"""[\"'](/(?:assets|chunks|js)/[^\s\"'<>]+\.js)[\"']"""),
        ]
        for cp in chunk_patterns:
            for m in cp.finditer(resp.text):
                found_urls.add(urljoin(base_url, m.group(1)))

        # Probe paths
        self._report("scrape", f"Probing {len(PROBE_PATHS)} sensitive paths...", 6)
        for i, path in enumerate(PROBE_PATHS):
            if i % 20 == 0:
                pct = 6 + int((i / len(PROBE_PATHS)) * 7)
                self._report("scrape", f"Probing paths ({i}/{len(PROBE_PATHS)})...", pct)
            probe_url = urljoin(base_url, path)
            try:
                self._throttle()
                r = self.session.head(probe_url, timeout=4, verify=self.verify_ssl, allow_redirects=False)
                if r.status_code == 200:
                    found_urls.add(probe_url)
                    if path.endswith('.js'):
                        found_urls.add(probe_url + ".map")
            except:
                continue

        # GraphQL introspection
        self._report("scrape", "Testing GraphQL introspection...", 14)
        for gql_path in ["/graphql", "/api/graphql", "/__graphql", "/graphiql"]:
            gql_url = urljoin(base_url, gql_path)
            try:
                self._throttle()
                r = self.session.post(
                    gql_url,
                    data=GRAPHQL_INTROSPECTION_QUERY,
                    headers={"Content-Type": "application/json"},
                    timeout=5,
                    verify=self.verify_ssl,
                )
                if r.status_code == 200 and "__schema" in r.text:
                    self.downloaded_files.append({
                        "url": gql_url + " [introspection]",
                        "content": r.text[:MAX_FILE_SIZE],
                        "type": "graphql-schema",
                        "size": len(r.text),
                    })
            except:
                continue

        # .map for each .js
        js_urls = [u for u in found_urls if u.endswith(".js")]
        for js_url in js_urls:
            found_urls.add(js_url + ".map")

        # Filter
        static_files = []
        for url in found_urls:
            p = urlparse(url)
            ext = Path(p.path).suffix.lower()
            is_interesting = any(path in url for path in PROBE_PATHS)
            if ext in STATIC_EXTENSIONS or is_interesting:
                static_files.append(url)

        self.downloaded_files.append({
            "url": target_url,
            "content": resp.text,
            "type": "html",
            "size": len(resp.text),
        })

        self._report("scrape", f"Found {len(static_files)} static file references", 15)
        return list(set(static_files))

    def download_files(self, urls):
        total = len(urls)
        for i, url in enumerate(urls):
            pct = 15 + int((i / max(total, 1)) * 10)
            if i % 5 == 0:
                self._report("download", f"Downloading ({i+1}/{total}): {url[:60]}", pct)
            try:
                self._throttle()
                resp = self.session.get(url, timeout=10, verify=self.verify_ssl)
                if resp.status_code != 200:
                    continue
                content_type = resp.headers.get("content-type", "")
                if any(t in content_type for t in ["image/", "font/", "audio/", "video/", "octet-stream"]):
                    continue
                if len(resp.content) > MAX_FILE_SIZE:
                    continue
                try:
                    text = resp.text
                except:
                    continue

                ext = Path(urlparse(url).path).suffix.lower()
                file_type = ext.lstrip(".") or "unknown"

                self.downloaded_files.append({
                    "url": url,
                    "content": text,
                    "type": file_type,
                    "size": len(text),
                })

                if file_type in ("js", "mjs"):
                    self._discover_chunks_from_js(text, url)
            except:
                continue

        self._report("download", f"Downloaded {len(self.downloaded_files)} files total", 25)

    def _discover_chunks_from_js(self, content, base_js_url):
        chunk_refs = set()
        patterns = [
            re.compile(r"""[\"']([a-zA-Z0-9._/\-]+\.chunk\.js)[\"']"""),
            re.compile(r"""[\"']([a-zA-Z0-9._/\-]+\.bundle\.js)[\"']"""),
            re.compile(r"""\.src\s*=\s*[\"'](/[^\s\"']+\.js)[\"']"""),
            re.compile(r"""importScripts\s*\(\s*[\"']([^\"']+)[\"']"""),
        ]
        for p in patterns:
            for m in p.finditer(content):
                ref = m.group(1)
                if not ref.startswith("http"):
                    ref = urljoin(base_js_url, ref)
                chunk_refs.add(ref)

        existing_urls = {f["url"] for f in self.downloaded_files}
        for chunk_url in chunk_refs:
            if chunk_url in existing_urls:
                continue
            try:
                self._throttle()
                r = self.session.get(chunk_url, timeout=8, verify=self.verify_ssl)
                if r.status_code == 200 and len(r.content) < MAX_FILE_SIZE:
                    ct = r.headers.get("content-type", "")
                    if "image/" not in ct and "font/" not in ct:
                        self.downloaded_files.append({
                            "url": chunk_url, "content": r.text,
                            "type": "js", "size": len(r.text),
                        })
                        existing_urls.add(chunk_url)
            except:
                continue

    # ── PHASE 2: Preprocessing (deterministic pipeline) ──

    def preprocess_all(self):
        """Run full deterministic pipeline on each file:
        deobfuscate → beautify → AST → endpoints → deps → sinks/sources → signatures
        """
        total = len(self.downloaded_files)
        all_sig_findings = []

        for i, f in enumerate(self.downloaded_files):
            pct = 25 + int((i / max(total, 1)) * 20)
            if i % 3 == 0:
                self._report("preprocess", f"Preprocessing ({i+1}/{total}): {f['url'][:55]}", pct)

            # 1-2-3-4-5-6: Full preprocessing pipeline
            pp = preprocess_file(f["content"], f["type"], f["url"])
            f["_preprocess"] = pp

            # Use deobfuscated+beautified content from now on
            f["content"] = pp.content_beautified or pp.content_deobfuscated or f["content"]
            f["size"] = len(f["content"])

            # 5 (secrets): Run signature detection on cleaned content
            findings = scan_content(f["content"], source_url=f["url"], file_type=f["type"])
            file_sig_findings = [finding_to_dict(fd) for fd in findings]
            all_sig_findings.extend(file_sig_findings)
            f["_sig_findings"] = file_sig_findings

            # Collect endpoints from preprocessing
            for ep in pp.endpoints:
                self.all_api_endpoints.add(f"{ep.method} {ep.url}")

            # Collect dependencies
            for dep in pp.dependencies:
                self.all_dependencies.append({
                    "name": dep.name,
                    "version": dep.version,
                    "source": dep.source,
                    "vulnerable": dep.vulnerable,
                    "cve": dep.cve,
                })

        self._report("preprocess", f"Preprocessing done: {len(all_sig_findings)} signature findings, "
                      f"{len(self.all_api_endpoints)} endpoints, {len(self.all_dependencies)} deps", 45)
        return all_sig_findings

    # ── PHASE 3: LLM Analysis ──

    def analyze_file_llm(self, file_info):
        content = file_info["content"]
        if len(content) > MAX_CONTENT_FOR_LLM:
            content = content[:MAX_CONTENT_FOR_LLM] + "\n\n... [TRUNCATED] ..."

        # Build structured briefing from deterministic pipeline
        pp = file_info.get("_preprocess")
        sig_findings = file_info.get("_sig_findings", [])

        if pp:
            briefing = format_briefing_for_llm(pp, sig_findings)
        else:
            if sig_findings:
                briefing = "\n".join(
                    f"- [{f['severity']}] {f['description']}: {f['evidence'][:80]}"
                    for f in sig_findings[:15]
                )
            else:
                briefing = "(No deterministic findings)"

        prompt = USER_PROMPT_TEMPLATE.format(
            url=file_info["url"],
            file_type=file_info["type"],
            briefing=briefing,
            content=content,
        )

        try:
            resp = self.ollama_session.post(
                f"{self.ollama_host}/api/generate",
                json={
                    "model": self.model,
                    "system": SYSTEM_PROMPT,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": settings.llm_temperature,
                        "num_predict": settings.llm_max_tokens,
                    },
                },
                timeout=settings.llm_timeout,
            )
            resp.raise_for_status()
            raw = resp.json().get("response", "")

            json_match = re.search(r"\{[\s\S]*\}", raw)
            if json_match:
                try:
                    parsed = json.loads(json_match.group())
                    # Collect LLM-discovered endpoints
                    for ep in parsed.get("api_endpoints", []):
                        self.all_api_endpoints.add(ep)
                    # Collect data flow confirmations
                    for df in parsed.get("data_flow_confirmed", []):
                        self.all_data_flows.append(df)
                    for f in parsed.get("findings", []):
                        f["detector"] = "llm"
                    return parsed
                except json.JSONDecodeError:
                    pass
            return {"findings": [], "summary": raw, "raw": True}
        except Exception as e:
            return {"findings": [], "summary": f"Analysis error: {e}", "error": True}

    def analyze_all_llm(self):
        total = len(self.downloaded_files)
        for i, f in enumerate(self.downloaded_files):
            pct = 45 + int((i / max(total, 1)) * 50)
            self._report("llm", f"LLM analysis ({i+1}/{total}): {f['url'][:55]}", pct)
            result = self.analyze_file_llm(f)
            self.results.append({
                "url": f["url"],
                "type": f["type"],
                "size": f["size"],
                "sig_findings": f.get("_sig_findings", []),
                "llm_analysis": result,
            })
        self._report("done", "Analysis complete", 100)

    # ── PIPELINE ──

    def run(self, target_url):
        self.downloaded_files = []
        self.results = []
        
        self.all_api_endpoints = set()
        self.all_dependencies = []
        self.all_data_flows = []

        # Phase 0: Fetch target
        initial_resp = self.fetch_target(target_url)
        if initial_resp is None:
            return self.generate_report(target_url, [])

        # Phase 0.5: SPA auto-detection + rendering
        renderer_urls = set()
        renderer_mode = str(self.enable_renderer).lower()

        if renderer_mode == "true":
            use_renderer = True
        elif renderer_mode == "false":
            use_renderer = False
        else:  # "auto"
            use_renderer = _is_spa(initial_resp.text)
            if use_renderer:
                self._report("render", "SPA detected — switching to headless rendering", 3)

        if use_renderer:
            from renderer import is_available, render_and_extract, extract_static_urls, extract_runtime_endpoints
            if is_available():
                self._report("render", "Rendering page with headless browser...", 3)
                render_result = render_and_extract(target_url)
                renderer_urls = extract_static_urls(render_result, target_url)
                runtime_eps = extract_runtime_endpoints(render_result)
                self.all_api_endpoints.update(runtime_eps)
                if render_result["html"]:
                    initial_resp._content = render_result["html"].encode()
                self._report("render", f"Renderer found {len(renderer_urls)} assets, {len(runtime_eps)} runtime endpoints", 5)
            else:
                self._report("render", "SPA detected but Playwright not installed — install with: pip install playwright && playwright install chromium", 3)

        # Phase 1: Scrape static files from initial page
        urls = self.scrape_static_files(target_url, initial_response=initial_resp)
        urls = list(set(urls) | renderer_urls)

        # Phase 1.1: Recursive crawl (if enabled)
        if self.enable_crawl:
            from crawler import Crawler
            self._report("crawl", "Crawling for additional pages...", 16)
            crawler = Crawler(
                self.session, target_url,
                max_pages=self.max_crawl_pages,
                rate_limit=self.rate_limit,
                verify_ssl=self.verify_ssl,
            )
            crawler.set_progress_callback(lambda msg: self._report("crawl", msg, 17))
            pages, crawl_static = crawler.crawl()
            urls = list(set(urls) | crawl_static)

            # Add crawled page HTML for analysis
            for page in pages:
                if page["url"] != target_url:  # skip main page (already added)
                    self.downloaded_files.append({
                        "url": page["url"],
                        "content": page["html"],
                        "type": "html",
                        "size": len(page["html"]),
                    })

            self._report("crawl", f"Crawled {len(pages)} pages, {len(crawl_static)} additional static refs", 18)

        # Phase 2: Download
        self.download_files(urls)

        # Phase 3: Preprocess (deobfuscate → beautify → AST → endpoints → sigs → deps → sinks)
        sig_findings = self.preprocess_all()

        # Phase 4: LLM analysis
        self.analyze_all_llm()

        # Phase 5: Generate report with false positive filtering
        report = self.generate_report(target_url, sig_findings)

        # Filter false positives if db module is available
        try:
            from db import filter_false_positives
            filtered, fp_count = filter_false_positives(report["findings"], target_url)
            if fp_count > 0:
                report["findings"] = filtered
                report["total_findings"] = len(filtered)
                report["false_positives_filtered"] = fp_count
                # Recalculate severity counts
                sev_counts = {}
                for f in filtered:
                    sev = f.get("severity", "UNKNOWN")
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1
                report["severity_counts"] = sev_counts
        except ImportError:
            pass

        return report

    def generate_report(self, target_url, sig_findings):
        all_findings = list(sig_findings)

        for r in self.results:
            llm = r["llm_analysis"]
            for f in llm.get("findings", []):
                f["source_url"] = r["url"]
                f["file_type"] = r["type"]
                f.setdefault("detector", "llm")
                all_findings.append(f)

        # Deduplicate
        seen = set()
        deduped = []
        for f in all_findings:
            key = (f.get("source_url", ""), f.get("evidence", "")[:100], f.get("description", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        all_findings = deduped

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "INFO"), 5))

        severity_counts = {}
        for f in all_findings:
            sev = f.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        detector_counts = {}
        for f in all_findings:
            d = f.get("detector", "unknown")
            detector_counts[d] = detector_counts.get(d, 0) + 1

        # Deduplicate dependencies
        seen_deps = set()
        unique_deps = []
        for d in self.all_dependencies:
            key = (d.get("name", "").lower(), d.get("version", ""))
            if key not in seen_deps:
                seen_deps.add(key)
                unique_deps.append(d)

        report = {
            "target": target_url,
            "scan_date": datetime.now().isoformat(),
            "model": self.model,
            "files_scanned": len(self.downloaded_files),
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
            "detector_counts": detector_counts,
            "findings": all_findings,
            "api_endpoints": sorted(self.all_api_endpoints),
            "dependencies": unique_deps,
            "data_flows": self.all_data_flows,
            "file_details": [
                {
                    "url": r["url"],
                    "type": r["type"],
                    "size": r["size"],
                    "sig_findings_count": len(r["sig_findings"]),
                    "summary": r["llm_analysis"].get("summary", ""),
                }
                for r in self.results
            ],
        }
        return report

    def generate_report_html(self, report):
        return generate_html_report(report)