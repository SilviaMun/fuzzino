"""
Deterministic preprocessing pipeline.
Extracts as much structured data as possible BEFORE sending to LLM.

Pipeline per file:
  1. Deobfuscation / decode (hex, unicode, base64, string concat)
  2. Beautify
  3. AST-like extraction (functions, classes, variables, exports)
  4. Endpoint extraction (fetch, axios, XHR, routes)
  5. Secrets detection (delegated to signatures.py)
  6. Dependency detection (package.json, CDN, inline libs)
  7. Sink/source mapping with data flow hints
"""

import re
import json
import base64
from dataclasses import dataclass, field
from urllib.parse import urlparse

try:
    import jsbeautifier
    HAS_JSBEAUTIFY = True
except ImportError:
    HAS_JSBEAUTIFY = False


# ════════════════════════════════════════════
# 1. DEOBFUSCATION / DECODE
# ════════════════════════════════════════════

def deobfuscate(content: str, file_type: str = "js") -> str:
    """Apply deterministic deobfuscation passes."""
    if file_type not in ("js", "mjs", "cjs", "jsx", "ts", "tsx", "html", "htm"):
        return content

    # Pass 1: Decode hex escapes  \x41 → A
    def decode_hex(m):
        try:
            return chr(int(m.group(1), 16))
        except:
            return m.group(0)
    content = re.sub(r"\\x([0-9a-fA-F]{2})", decode_hex, content)

    # Pass 2: Decode unicode escapes  \u0041 → A
    def decode_unicode(m):
        try:
            return chr(int(m.group(1), 16))
        except:
            return m.group(0)
    content = re.sub(r"\\u([0-9a-fA-F]{4})", decode_unicode, content)
    # Also handle \u{1234} form
    content = re.sub(r"\\u\{([0-9a-fA-F]{1,6})\}", decode_unicode, content)

    # Pass 3: Decode common base64 strings (atob calls)
    def decode_atob(m):
        try:
            decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
            # Only replace if it looks like readable text
            if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in decoded):
                return f'/* b64decoded: */ "{decoded}"'
        except:
            pass
        return m.group(0)
    content = re.sub(r"""atob\s*\(\s*["']([A-Za-z0-9+/=]{8,})["']\s*\)""", decode_atob, content)

    # Pass 4: Resolve simple string concatenation  "htt" + "ps://" + "api" → "https://api"
    # Only handle adjacent string literals
    def concat_strings(content):
        prev = None
        while prev != content:
            prev = content
            content = re.sub(
                r"""(["'])([^"']*?)\1\s*\+\s*(["'])([^"']*?)\3""",
                lambda m: f'{m.group(1)}{m.group(2)}{m.group(4)}{m.group(1)}' if m.group(1) == m.group(3) else m.group(0),
                content,
            )
        return content
    content = concat_strings(content)

    # Pass 5: Decode HTML entities in HTML files
    if file_type in ("html", "htm"):
        import html as html_mod
        try:
            content = html_mod.unescape(content)
        except:
            pass

    return content


# ════════════════════════════════════════════
# 2. BEAUTIFY
# ════════════════════════════════════════════

def beautify(content: str, file_type: str = "js") -> str:
    """Beautify JS/CSS/HTML for readability."""
    if not HAS_JSBEAUTIFY:
        return content

    if file_type in ("js", "mjs", "cjs", "jsx", "ts", "tsx"):
        try:
            opts = jsbeautifier.default_options()
            opts.indent_size = 2
            opts.max_preserve_newlines = 2
            opts.break_chained_methods = True
            return jsbeautifier.beautify(content, opts)
        except:
            return content

    if file_type in ("css",):
        try:
            from jsbeautifier import css as cssbeautifier
            return cssbeautifier.beautify(content)
        except:
            return content

    if file_type in ("html", "htm"):
        try:
            from jsbeautifier import html as htmlbeautifier
            return htmlbeautifier.beautify(content)
        except:
            return content

    return content


# ════════════════════════════════════════════
# 3. AST-LIKE EXTRACTION
# ════════════════════════════════════════════

@dataclass
class ASTInfo:
    functions: list = field(default_factory=list)    # [{name, params, line}]
    classes: list = field(default_factory=list)       # [{name, methods, line}]
    variables: list = field(default_factory=list)     # [{name, value_hint, line}]
    exports: list = field(default_factory=list)       # [{name, type}]
    imports: list = field(default_factory=list)       # [{module, names}]
    routes: list = field(default_factory=list)        # extracted route definitions
    event_listeners: list = field(default_factory=list)


def extract_ast_info(content: str, file_type: str = "js") -> ASTInfo:
    """Regex-based AST extraction from JS/TS files."""
    if file_type not in ("js", "mjs", "cjs", "jsx", "ts", "tsx"):
        return ASTInfo()

    info = ASTInfo()
    lines = content.split("\n")

    # Functions: named declarations and expressions
    fn_decl = re.compile(r"""(?:^|\s)(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)""")
    fn_arrow = re.compile(r"""(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|(\w+))\s*=>""")
    fn_method = re.compile(r"""(?:^|\s)(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*\{""")

    for i, line in enumerate(lines, 1):
        for m in fn_decl.finditer(line):
            info.functions.append({"name": m.group(1), "params": m.group(2).strip(), "line": i})
        for m in fn_arrow.finditer(line):
            info.functions.append({"name": m.group(1), "params": "arrow", "line": i})

    # Classes
    class_re = re.compile(r"""class\s+(\w+)(?:\s+extends\s+(\w+))?\s*\{""")
    for i, line in enumerate(lines, 1):
        for m in class_re.finditer(line):
            info.classes.append({"name": m.group(1), "extends": m.group(2), "line": i})

    # Important variable assignments (config, urls, keys, etc.)
    var_re = re.compile(r"""(?:const|let|var)\s+(\w+)\s*=\s*(.{1,200})""")
    interesting_var_names = re.compile(
        r"(?:url|api|endpoint|host|server|config|secret|key|token|password|base|auth|header|cookie|route|path|port|domain)",
        re.IGNORECASE,
    )
    for i, line in enumerate(lines, 1):
        for m in var_re.finditer(line):
            name = m.group(1)
            if interesting_var_names.search(name):
                value = m.group(2).strip().rstrip(";,")
                if len(value) > 150:
                    value = value[:150] + "..."
                info.variables.append({"name": name, "value_hint": value, "line": i})

    # Imports
    import_re = re.compile(r"""import\s+(?:\{([^}]+)\}|(\w+))\s+from\s+["']([^"']+)["']""")
    require_re = re.compile(r"""(?:const|let|var)\s+(?:\{([^}]+)\}|(\w+))\s*=\s*require\s*\(\s*["']([^"']+)["']\s*\)""")
    for i, line in enumerate(lines, 1):
        for m in import_re.finditer(line):
            names = m.group(1) or m.group(2) or ""
            info.imports.append({"module": m.group(3), "names": names.strip()})
        for m in require_re.finditer(line):
            names = m.group(1) or m.group(2) or ""
            info.imports.append({"module": m.group(3), "names": names.strip()})

    # Exports
    export_re = re.compile(r"""export\s+(?:default\s+)?(?:const|let|var|function|class|async\s+function)\s+(\w+)""")
    for i, line in enumerate(lines, 1):
        for m in export_re.finditer(line):
            info.exports.append({"name": m.group(1), "line": i})

    # Route definitions (Express-style, Next.js, React Router, etc.)
    route_patterns = [
        # Express: app.get('/path', ...), router.post('/path', ...)
        re.compile(r"""(?:app|router|server)\.(get|post|put|patch|delete|all|use)\s*\(\s*["']([^"']+)["']""", re.IGNORECASE),
        # Next.js API routes from file paths
        re.compile(r"""(?:pages|app)/api/([^\s"']+)"""),
    ]
    for i, line in enumerate(lines, 1):
        for rp in route_patterns:
            for m in rp.finditer(line):
                if rp.groups == 2:
                    info.routes.append({"method": m.group(1).upper(), "path": m.group(2), "line": i})
                else:
                    info.routes.append({"method": "ANY", "path": m.group(1), "line": i})

    # Event listeners
    event_re = re.compile(r"""addEventListener\s*\(\s*["'](\w+)["']""")
    for i, line in enumerate(lines, 1):
        for m in event_re.finditer(line):
            info.event_listeners.append({"event": m.group(1), "line": i})

    return info


# ════════════════════════════════════════════
# 4. ENDPOINT EXTRACTION
# ════════════════════════════════════════════

@dataclass
class Endpoint:
    method: str       # GET, POST, etc. or UNKNOWN
    url: str          # the URL or path
    line: int = 0
    context: str = "" # fetch, axios, XHR, etc.


def extract_endpoints(content: str, file_type: str = "js") -> list[Endpoint]:
    """Extract API endpoints from JS code."""
    endpoints = []
    seen = set()
    lines = content.split("\n")

    patterns = [
        # fetch("url") / fetch("url", {method: "POST"})
        (re.compile(r"""fetch\s*\(\s*["'`]([^"'`]+)["'`](?:\s*,\s*\{[^}]*method\s*:\s*["'](\w+)["'])?""", re.IGNORECASE), "fetch"),
        # axios.get/post/put/delete("url")
        (re.compile(r"""axios\.(\w+)\s*\(\s*["'`]([^"'`]+)["'`]""", re.IGNORECASE), "axios"),
        # axios({url: "...", method: "..."})
        (re.compile(r"""axios\s*\(\s*\{[^}]*url\s*:\s*["'`]([^"'`]+)["'`][^}]*method\s*:\s*["'`](\w+)["'`]""", re.IGNORECASE), "axios_obj"),
        # $.ajax / $.get / $.post
        (re.compile(r"""\$\.(?:ajax|get|post|put|delete)\s*\(\s*(?:["'`]([^"'`]+)["'`]|\{[^}]*url\s*:\s*["'`]([^"'`]+)["'`])""", re.IGNORECASE), "jquery"),
        # XMLHttpRequest.open("METHOD", "url")
        (re.compile(r"""\.open\s*\(\s*["'](\w+)["']\s*,\s*["'`]([^"'`]+)["'`]""", re.IGNORECASE), "xhr"),
        # Generic URL patterns in assignments  apiUrl = "/api/..."
        (re.compile(r"""(?:url|endpoint|path|api|href|action|src)\s*[=:]\s*["'`]((?:https?://|/)[^"'`\s]{5,})["'`]""", re.IGNORECASE), "assignment"),
        # Template literals with API paths
        (re.compile(r"""`((?:https?://|/api|/v[0-9])[^`]{5,})`"""), "template"),
    ]

    for i, line in enumerate(lines, 1):
        for pattern, ctx in patterns:
            for m in pattern.finditer(line):
                if ctx == "fetch":
                    url = m.group(1)
                    method = (m.group(2) or "GET").upper()
                elif ctx == "axios":
                    method = m.group(1).upper()
                    url = m.group(2)
                elif ctx == "axios_obj":
                    url = m.group(1)
                    method = m.group(2).upper()
                elif ctx == "jquery":
                    url = m.group(1) or m.group(2) or ""
                    method = "POST" if "post" in line.lower()[:50] else "GET"
                elif ctx == "xhr":
                    method = m.group(1).upper()
                    url = m.group(2)
                elif ctx in ("assignment", "template"):
                    url = m.group(1)
                    method = "UNKNOWN"
                else:
                    continue

                if not url or url in seen:
                    continue

                # Skip noise
                if any(skip in url.lower() for skip in [
                    ".css", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff",
                    "fonts.", "cdn.", "google-analytics", "googletagmanager",
                    "facebook.", "twitter.", "linkedin.",
                ]):
                    continue

                seen.add(url)
                endpoints.append(Endpoint(method=method, url=url, line=i, context=ctx))

    return endpoints


# ════════════════════════════════════════════
# 5. DEPENDENCY DETECTION
# ════════════════════════════════════════════

@dataclass
class Dependency:
    name: str
    version: str
    source: str = ""    # "package.json", "cdn", "inline", "import"
    vulnerable: bool = False
    cve: str = ""

# Known vulnerable version ranges (simplified checks)
KNOWN_VULNS = {
    "jquery": [
        {"below": "3.5.0", "cve": "CVE-2020-11022", "desc": "XSS via HTML sanitization"},
        {"below": "3.0.0", "cve": "CVE-2015-9251", "desc": "XSS in jQuery.htmlPrefilter"},
    ],
    "lodash": [
        {"below": "4.17.21", "cve": "CVE-2021-23337", "desc": "Command injection via template"},
        {"below": "4.17.12", "cve": "CVE-2019-10744", "desc": "Prototype pollution"},
    ],
    "angular": [
        {"below": "1.8.0", "cve": "Multiple", "desc": "Angular.js 1.x has multiple XSS vectors"},
    ],
    "angularjs": [
        {"below": "1.8.0", "cve": "Multiple", "desc": "Angular.js 1.x EOL, multiple XSS"},
    ],
    "moment": [
        {"below": "2.29.4", "cve": "CVE-2022-31129", "desc": "ReDoS in moment parsing"},
    ],
    "axios": [
        {"below": "1.6.0", "cve": "CVE-2023-45857", "desc": "CSRF token leakage"},
    ],
    "express": [
        {"below": "4.19.2", "cve": "CVE-2024-29041", "desc": "Open redirect"},
    ],
    "minimist": [
        {"below": "1.2.6", "cve": "CVE-2021-44906", "desc": "Prototype pollution"},
    ],
    "node-fetch": [
        {"below": "2.6.7", "cve": "CVE-2022-0235", "desc": "Header leak on redirect"},
    ],
    "handlebars": [
        {"below": "4.7.7", "cve": "CVE-2021-23369", "desc": "Prototype pollution RCE"},
    ],
    "dompurify": [
        {"below": "2.4.1", "cve": "CVE-2023-23631", "desc": "Mutation XSS bypass"},
    ],
    "marked": [
        {"below": "4.0.10", "cve": "CVE-2022-21680", "desc": "ReDoS"},
    ],
    "highlight.js": [
        {"below": "10.4.1", "cve": "CVE-2020-26237", "desc": "ReDoS / Prototype pollution"},
    ],
    "serialize-javascript": [
        {"below": "3.1.0", "cve": "CVE-2020-7660", "desc": "RCE via crafted input"},
    ],
    "postcss": [
        {"below": "8.4.31", "cve": "CVE-2023-44270", "desc": "Line return parsing error"},
    ],
}


def _version_below(version_str: str, threshold: str) -> bool:
    """Simple semver comparison: is version_str < threshold?"""
    try:
        def to_tuple(v):
            # Strip leading v, pre-release tags
            v = re.sub(r"^[v^~>=<]", "", v).split("-")[0].split("+")[0]
            parts = v.split(".")
            return tuple(int(p) for p in parts[:3])
        return to_tuple(version_str) < to_tuple(threshold)
    except:
        return False


def _check_vulns(name: str, version: str) -> tuple[bool, str]:
    """Check if a dependency has known vulnerabilities."""
    norm = name.lower().strip()
    for alias in [norm, norm.replace(".js", ""), norm.replace("js", "")]:
        if alias in KNOWN_VULNS:
            for vuln in KNOWN_VULNS[alias]:
                if _version_below(version, vuln["below"]):
                    return True, vuln["cve"]
    return False, ""


def detect_dependencies(content: str, file_type: str, all_files: list = None) -> list[Dependency]:
    """Detect dependencies from various sources."""
    deps = []
    seen = set()

    def _add(name, version, source):
        key = (name.lower(), version)
        if key in seen:
            return
        seen.add(key)
        vuln, cve = _check_vulns(name, version)
        deps.append(Dependency(name=name, version=version, source=source, vulnerable=vuln, cve=cve))

    # Source 1: package.json
    if file_type == "json":
        try:
            pkg = json.loads(content)
            for dep_key in ("dependencies", "devDependencies", "peerDependencies"):
                for name, ver in pkg.get(dep_key, {}).items():
                    ver_clean = re.sub(r"^[\^~>=<]+", "", ver).split(" ")[0]
                    _add(name, ver_clean, "package.json")
        except:
            pass

    # Source 2: CDN URLs with versions
    cdn_patterns = [
        # cdnjs: /ajax/libs/jquery/3.6.0/jquery.min.js
        re.compile(r"""cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([0-9][^/]+)/"""),
        # unpkg: unpkg.com/react@18.2.0/umd/react.production.min.js
        re.compile(r"""unpkg\.com/([^@/]+)@([0-9][^/]+)"""),
        # jsdelivr: cdn.jsdelivr.net/npm/lodash@4.17.21/
        re.compile(r"""jsdelivr\.net/(?:npm|gh)/([^@/]+)@([0-9][^/]+)"""),
        # Google CDN: ajax.googleapis.com/ajax/libs/jquery/3.6.0/
        re.compile(r"""googleapis\.com/ajax/libs/([^/]+)/([0-9][^/]+)"""),
        # Generic versioned script URL
        re.compile(r"""(?:^|/)([a-z][\w.-]+?)[-.](\d+\.\d+(?:\.\d+)?(?:-[a-z0-9.]+)?)(?:\.min)?\.js""", re.IGNORECASE),
    ]
    for cp in cdn_patterns:
        for m in cp.finditer(content):
            _add(m.group(1), m.group(2), "cdn")

    # Source 3: Inline library fingerprints (comments / banners)
    banner_patterns = [
        # /*! jQuery v3.6.0 | ... */
        re.compile(r"""[/*! ]+(\w[\w.-]+)\s+v?(\d+\.\d+(?:\.\d+)?)\s"""),
        # * Lodash 4.17.21
        re.compile(r"""\*\s+(\w+)\s+(\d+\.\d+\.\d+)"""),
        # @version 2.3.4
        re.compile(r"""@version\s+(\d+\.\d+(?:\.\d+)?)"""),
    ]
    for bp in banner_patterns:
        for m in bp.finditer(content[:5000]):  # banners are at the top
            name = m.group(1) if bp.groups == 2 else "unknown"
            version = m.group(2) if bp.groups == 2 else m.group(1)
            if name != "unknown":
                _add(name, version, "inline_banner")

    # Source 4: Import/require statements (name only, no version)
    import_re = re.compile(r"""(?:from|require\s*\()\s*["']([^"'./][^"']*?)["']""")
    for m in import_re.finditer(content):
        pkg = m.group(1).split("/")[0]  # handle scoped: @scope/name → @scope
        if m.group(1).startswith("@"):
            parts = m.group(1).split("/")
            if len(parts) >= 2:
                pkg = parts[0] + "/" + parts[1]
        if pkg and not pkg.startswith("."):
            key = (pkg.lower(), "unknown")
            if key not in seen:
                seen.add(key)
                deps.append(Dependency(name=pkg, version="unknown", source="import"))

    return deps


# ════════════════════════════════════════════
# 6. SINK / SOURCE MAPPING
# ════════════════════════════════════════════

@dataclass
class SinkSource:
    type: str         # "sink" or "source"
    category: str     # "xss", "redirect", "eval", "storage", "network", etc.
    name: str         # e.g. "innerHTML", "location.href"
    line: int
    context: str      # the line of code (trimmed)
    data_flow_hint: str = ""  # what variable flows in, if detectable


def map_sinks_sources(content: str, file_type: str = "js") -> list[SinkSource]:
    """Map dangerous sinks and user-controlled sources with data flow hints."""
    if file_type not in ("js", "mjs", "cjs", "jsx", "ts", "tsx", "html", "htm"):
        return []

    results = []
    lines = content.split("\n")

    SINKS = [
        # (regex, type, category, name)
        (re.compile(r"""(\w+)\.innerHTML\s*[=+]"""), "sink", "xss", "innerHTML"),
        (re.compile(r"""(\w+)\.outerHTML\s*[=+]"""), "sink", "xss", "outerHTML"),
        (re.compile(r"""document\.write(?:ln)?\s*\((.{0,60})"""), "sink", "xss", "document.write"),
        (re.compile(r"""(?:^|[^.\w])eval\s*\((.{0,60})"""), "sink", "eval", "eval"),
        (re.compile(r"""(?:new\s+)?Function\s*\((.{0,60})"""), "sink", "eval", "Function()"),
        (re.compile(r"""(?:setTimeout|setInterval)\s*\(\s*["'`]"""), "sink", "eval", "setTimeout/setInterval(string)"),
        (re.compile(r"""location\.(?:href|assign|replace)\s*=\s*(.{0,60})"""), "sink", "redirect", "location redirect"),
        (re.compile(r"""window\.open\s*\((.{0,60})"""), "sink", "redirect", "window.open"),
        (re.compile(r"""\.postMessage\s*\((.{0,60})"""), "sink", "postmessage", "postMessage"),
        (re.compile(r"""\$\([^)]*\)\.html\s*\((.{0,60})"""), "sink", "xss", "jQuery.html()"),
        (re.compile(r"""\.insertAdjacentHTML\s*\((.{0,60})"""), "sink", "xss", "insertAdjacentHTML"),
        (re.compile(r"""document\.createElement\s*\(\s*["']script["']"""), "sink", "xss", "createElement(script)"),
        (re.compile(r"""\.setAttribute\s*\(\s*["'](?:on\w+|href|src|action)["']\s*,\s*(.{0,60})"""), "sink", "xss", "setAttribute(event/url)"),
        (re.compile(r"""document\.cookie\s*="""), "sink", "storage", "document.cookie set"),
        (re.compile(r"""(?:localStorage|sessionStorage)\.setItem\s*\((.{0,60})"""), "sink", "storage", "Web Storage write"),
        (re.compile(r"""\.execCommand\s*\("""), "sink", "misc", "execCommand"),
    ]

    SOURCES = [
        (re.compile(r"""(?:location\.(?:search|hash|href|pathname)|window\.location)"""), "source", "url", "URL parameters"),
        (re.compile(r"""document\.(?:URL|documentURI|referrer|baseURI)"""), "source", "url", "document URL"),
        (re.compile(r"""(?:URLSearchParams|new\s+URL)\s*\("""), "source", "url", "URL parsing"),
        (re.compile(r"""document\.cookie(?:\s|[;,])"""), "source", "cookie", "document.cookie read"),
        (re.compile(r"""(?:localStorage|sessionStorage)\.getItem"""), "source", "storage", "Web Storage read"),
        (re.compile(r"""addEventListener\s*\(\s*["']message["']"""), "source", "postmessage", "postMessage listener"),
        (re.compile(r"""\.(?:value|innerText|textContent)\b"""), "source", "dom", "DOM element value"),
        (re.compile(r"""(?:FormData|new\s+FormData)"""), "source", "form", "FormData"),
        (re.compile(r"""(?:params|query|searchParams)\.get\s*\("""), "source", "url", "query parameter"),
    ]

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        for pattern, stype, cat, name in SINKS + SOURCES:
            m = pattern.search(line)
            if m:
                # Try to extract data flow hint
                flow_hint = ""
                if m.lastindex and m.group(1):
                    flow_hint = m.group(1).strip()[:80]

                results.append(SinkSource(
                    type=stype,
                    category=cat,
                    name=name,
                    line=i,
                    context=stripped[:200],
                    data_flow_hint=flow_hint,
                ))

    return results


# ════════════════════════════════════════════
# PIPELINE ORCHESTRATOR
# ════════════════════════════════════════════

@dataclass
class PreprocessResult:
    """All deterministic findings for a single file."""
    content_deobfuscated: str = ""
    content_beautified: str = ""
    ast_info: ASTInfo = field(default_factory=ASTInfo)
    endpoints: list = field(default_factory=list)
    dependencies: list = field(default_factory=list)
    sinks_sources: list = field(default_factory=list)
    # signature findings come from signatures.py separately


def preprocess_file(content: str, file_type: str, url: str = "") -> PreprocessResult:
    """Run the full deterministic preprocessing pipeline on a single file."""
    result = PreprocessResult()

    # 1. Deobfuscate
    result.content_deobfuscated = deobfuscate(content, file_type)

    # 2. Beautify
    result.content_beautified = beautify(result.content_deobfuscated, file_type)

    # Use beautified content for all further analysis
    clean = result.content_beautified

    # 3. AST extraction
    result.ast_info = extract_ast_info(clean, file_type)

    # 4. Endpoint extraction
    result.endpoints = extract_endpoints(clean, file_type)

    # 5. Dependency detection
    result.dependencies = detect_dependencies(clean, file_type)

    # 6. Sink/source mapping
    result.sinks_sources = map_sinks_sources(clean, file_type)

    return result


def format_briefing_for_llm(preprocess: PreprocessResult, sig_findings: list) -> str:
    """Format all deterministic findings into a structured briefing for the LLM."""
    sections = []

    # Signature findings
    if sig_findings:
        lines = []
        for f in sig_findings[:20]:
            lines.append(f"  [{f['severity']}] {f['description']}: {f['evidence'][:80]}")
        sections.append("REGEX FINDINGS:\n" + "\n".join(lines))

    # Endpoints
    if preprocess.endpoints:
        lines = [f"  {ep.method:8s} {ep.url}  (via {ep.context}, line {ep.line})" for ep in preprocess.endpoints[:30]]
        sections.append("ENDPOINTS EXTRACTED:\n" + "\n".join(lines))

    # Dependencies
    if preprocess.dependencies:
        lines = []
        for d in preprocess.dependencies:
            vuln_tag = f" ⚠ VULNERABLE ({d.cve})" if d.vulnerable else ""
            lines.append(f"  {d.name} {d.version} [{d.source}]{vuln_tag}")
        sections.append("DEPENDENCIES:\n" + "\n".join(lines[:20]))

    # Sinks & Sources
    sinks = [s for s in preprocess.sinks_sources if s.type == "sink"]
    sources = [s for s in preprocess.sinks_sources if s.type == "source"]
    if sinks:
        lines = [f"  SINK [{s.category}] {s.name} (line {s.line}): {s.context[:100]}" for s in sinks[:20]]
        sections.append("DANGEROUS SINKS:\n" + "\n".join(lines))
    if sources:
        lines = [f"  SOURCE [{s.category}] {s.name} (line {s.line}): {s.context[:100]}" for s in sources[:20]]
        sections.append("USER-CONTROLLED SOURCES:\n" + "\n".join(lines))

    # AST summary
    ast = preprocess.ast_info
    if ast.functions or ast.classes or ast.variables or ast.routes:
        lines = []
        if ast.routes:
            lines.append(f"  Route definitions: {len(ast.routes)}")
            for r in ast.routes[:10]:
                lines.append(f"    {r['method']} {r['path']} (line {r['line']})")
        if ast.variables:
            lines.append(f"  Interesting variables: {len(ast.variables)}")
            for v in ast.variables[:10]:
                lines.append(f"    {v['name']} = {v['value_hint'][:80]} (line {v['line']})")
        if ast.functions:
            lines.append(f"  Functions: {len(ast.functions)} ({', '.join(f['name'] for f in ast.functions[:15])})")
        if ast.classes:
            lines.append(f"  Classes: {', '.join(c['name'] for c in ast.classes[:10])}")
        if ast.event_listeners:
            events = set(e['event'] for e in ast.event_listeners)
            lines.append(f"  Event listeners: {', '.join(sorted(events))}")
        sections.append("CODE STRUCTURE:\n" + "\n".join(lines))

    if not sections:
        return "(No deterministic findings)"

    return "\n\n".join(sections)