"""
Deterministic signature-based detection.
Runs BEFORE LLM analysis — regex patterns that cannot miss.
"""

import re
from dataclasses import dataclass, field


@dataclass
class Finding:
    severity: str
    category: str
    description: str
    evidence: str
    impact: str
    recommendation: str
    source_url: str = ""
    file_type: str = ""
    line_number: int = 0
    detector: str = "signature"


# ────────────────────────────────────────────
# 1. SECRET / CREDENTIAL PATTERNS
# ────────────────────────────────────────────

SECRET_PATTERNS = [
    # AWS
    {
        "name": "AWS Access Key ID",
        "pattern": r"(?:^|[\"'\s=:,])(?P<match>AKIA[0-9A-Z]{16})(?:[\"'\s,;]|$)",
        "severity": "CRITICAL",
        "category": "Hardcoded credentials",
        "impact": "Full access to AWS resources. Account takeover, data exfiltration, resource abuse.",
        "recommendation": "Rotate the key immediately in AWS IAM. Use environment variables or AWS Secrets Manager.",
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": r"""(?:aws_secret_access_key|aws_secret|secret_key|secretAccessKey)[\s]*[=:]\s*[\"']?(?P<match>[A-Za-z0-9/+=]{40})[\"']?""",
        "severity": "CRITICAL",
        "category": "Hardcoded credentials",
        "impact": "Combined with Access Key ID, provides full AWS access.",
        "recommendation": "Rotate immediately. Never embed secrets in client-side code.",
    },
    # Google
    {
        "name": "Google API Key",
        "pattern": r"""(?:^|[\"'\s=:,])(?P<match>AIza[0-9A-Za-z_-]{35})(?:[\"'\s,;]|$)""",
        "severity": "HIGH",
        "category": "Hardcoded credentials",
        "impact": "Unauthorized use of Google Cloud APIs. Quota abuse, billing impact, data access depending on API scope.",
        "recommendation": "Restrict the API key by HTTP referrer and API scope. Rotate and move to server-side.",
    },
    {
        "name": "Google OAuth Client Secret",
        "pattern": r"""(?:client_secret|clientSecret)[\s]*[=:]\s*[\"']?(?P<match>GOCSPX-[A-Za-z0-9_-]{28,})""",
        "severity": "CRITICAL",
        "category": "Hardcoded credentials",
        "impact": "OAuth flow hijacking, impersonation of the application.",
        "recommendation": "Regenerate client secret. Move to server-side OAuth flow.",
    },
    # Firebase
    {
        "name": "Firebase Config Exposed",
        "pattern": r"""(?P<match>(?:apiKey|authDomain|databaseURL|storageBucket|messagingSenderId|appId)[\s]*[=:]\s*[\"'][^\"']{8,}[\"'])""",
        "severity": "MEDIUM",
        "category": "Information disclosure",
        "impact": "Firebase config alone isn't a full compromise, but combined with misconfigured Firestore/RTDB rules, allows unauthorized data access.",
        "recommendation": "Verify Firebase security rules are restrictive. Consider App Check.",
    },
    # Supabase
    {
        "name": "Supabase Anon/Service Key",
        "pattern": r"""(?:supabase|SUPABASE)[\w]*(?:KEY|key|Key|_key|_KEY)[\s]*[=:]\s*[\"']?(?P<match>eyJ[A-Za-z0-9_-]{100,})""",
        "severity": "HIGH",
        "category": "Hardcoded credentials",
        "impact": "If service role key: full database access bypassing RLS. If anon key: depends on RLS policies.",
        "recommendation": "Never expose service role key client-side. Verify RLS policies for anon key.",
    },
    # GitHub
    {
        "name": "GitHub Token",
        "pattern": r"""(?:^|[\"'\s=:,])(?P<match>gh[pousr]_[A-Za-z0-9_]{36,255})(?:[\"'\s,;]|$)""",
        "severity": "CRITICAL",
        "category": "Hardcoded credentials",
        "impact": "Repository access, code modification, CI/CD pipeline compromise depending on token scope.",
        "recommendation": "Revoke the token on GitHub. Use fine-grained PATs with minimal scope.",
    },
    {
        "name": "GitHub App Token",
        "pattern": r"""(?:^|[\"'\s=:,])(?P<match>ghu_[A-Za-z0-9]{36,})""",
        "severity": "CRITICAL",
        "category": "Hardcoded credentials",
        "impact": "GitHub App installation access.",
        "recommendation": "Revoke immediately.",
    },
    # GitLab
    {
        "name": "GitLab Token",
        "pattern": r"""(?:^|[\"'\s=:,])(?P<match>glpat-[A-Za-z0-9_-]{20,})""",
        "severity": "CRITICAL",
        "category": "Hardcoded credentials",
        "impact": "GitLab API access, repository manipulation.",
        "recommendation": "Revoke the token in GitLab settings.",
    },
    # Stripe
    {
        "name": "Stripe Secret Key",
        "pattern": r"""(?:^|[\"'\s=:,])(?P<match>sk_live_[A-Za-z0-9]{24,})""",
        "severity": "CRITICAL",
        "category": "Hardcoded credentials",
        "impact": "Full Stripe account access: read/write customers, charges, refunds. Financial fraud.",
        "recommendation": "Rotate key immediately in Stripe dashboard. Use restricted keys server-side only.",
    },
    {
        "name": "Stripe Publishable Key (live)",
        "pattern": r"""(?:^|[\"'\s=:,])(?P<match>pk_live_[A-Za-z0-9]{24,})""",
        "severity": "INFO",
        "category": "Information disclosure",
        "impact": "Publishable keys are meant to be public, but confirm it's intentional.",
        "recommendation": "Verify this is the intended key and not a test key leaking environment info.",
    },
    # Slack
    {
        "name": "Slack Bot/User Token",
        "pattern": r"""(?:^|[\"'\s=:,])(?P<match>xox[bpoas]-[A-Za-z0-9-]{10,})""",
        "severity": "CRITICAL",
        "category": "Hardcoded credentials",
        "impact": "Slack workspace access: read messages, post, access files.",
        "recommendation": "Revoke the token in Slack app management.",
    },
    {
        "name": "Slack Webhook URL",
        "pattern": r"""(?P<match>https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,})""",
        "severity": "HIGH",
        "category": "Hardcoded credentials",
        "impact": "Attacker can post messages to the Slack channel. Social engineering, phishing.",
        "recommendation": "Rotate the webhook URL. Move to server-side.",
    },
    # Twilio
    {
        "name": "Twilio API Key",
        "pattern": r"""(?:^|[\"'\s=:,])(?P<match>SK[0-9a-fA-F]{32})(?:[\"'\s,;]|$)""",
        "severity": "HIGH",
        "category": "Hardcoded credentials",
        "impact": "SMS/voice API abuse, billing impact.",
        "recommendation": "Rotate the key in Twilio console.",
    },
    # SendGrid
    {
        "name": "SendGrid API Key",
        "pattern": r"""(?:^|[\"'\s=:,])(?P<match>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})""",
        "severity": "CRITICAL",
        "category": "Hardcoded credentials",
        "impact": "Send emails from the organization's domain. Phishing, spam, reputation damage.",
        "recommendation": "Revoke and regenerate in SendGrid.",
    },
    # Mailgun
    {
        "name": "Mailgun API Key",
        "pattern": r"""(?:^|[\"'\s=:,])(?P<match>key-[A-Za-z0-9]{32})(?:[\"'\s,;]|$)""",
        "severity": "HIGH",
        "category": "Hardcoded credentials",
        "impact": "Email sending abuse.",
        "recommendation": "Rotate in Mailgun dashboard.",
    },
    # JWT
    {
        "name": "JSON Web Token",
        "pattern": r"""(?:^|[\"'\s=:,])(?P<match>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})""",
        "severity": "HIGH",
        "category": "Hardcoded credentials",
        "impact": "Session hijacking if token is valid. Decode to check claims and expiration.",
        "recommendation": "Remove hardcoded JWTs. Verify the token is expired. Check for sensitive claims.",
    },
    # Private keys
    {
        "name": "Private Key (PEM)",
        "pattern": r"""(?P<match>-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)""",
        "severity": "CRITICAL",
        "category": "Hardcoded credentials",
        "impact": "Full cryptographic identity compromise. TLS impersonation, signing abuse.",
        "recommendation": "Revoke and regenerate the key pair. Never include private keys in client-side code.",
    },
    # Generic password patterns
    {
        "name": "Hardcoded Password",
        "pattern": r"""(?:password|passwd|pwd|pass)[\s]*[=:]\s*[\"'](?P<match>[^\"']{4,})[\"']""",
        "severity": "HIGH",
        "category": "Hardcoded credentials",
        "impact": "Direct credential exposure. Credential stuffing if reused.",
        "recommendation": "Remove hardcoded passwords. Use environment variables or a secrets manager.",
    },
    {
        "name": "Hardcoded Secret/Token",
        "pattern": r"""(?:secret|token|api_key|apikey|api[-_]?secret|access[-_]?token|auth[-_]?token|client[-_]?secret)[\s]*[=:]\s*[\"'](?P<match>[^\"']{8,})[\"']""",
        "severity": "HIGH",
        "category": "Hardcoded credentials",
        "impact": "Credential or API access exposure.",
        "recommendation": "Move secrets to server-side configuration.",
    },
    # Heroku
    {
        "name": "Heroku API Key",
        "pattern": r"""(?:HEROKU_API_KEY|heroku.*api.*key)[\s]*[=:]\s*[\"']?(?P<match>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})""",
        "severity": "CRITICAL",
        "category": "Hardcoded credentials",
        "impact": "Full Heroku account access.",
        "recommendation": "Regenerate API key.",
    },
    # Azure
    {
        "name": "Azure Storage Account Key",
        "pattern": r"""(?:AccountKey|account_key|storage_key)[\s]*[=:]\s*[\"']?(?P<match>[A-Za-z0-9+/=]{86,88})""",
        "severity": "CRITICAL",
        "category": "Hardcoded credentials",
        "impact": "Full Azure Storage access: read/write/delete blobs, tables, queues.",
        "recommendation": "Rotate keys. Use SAS tokens with limited scope.",
    },
    # Shopify
    {
        "name": "Shopify Access Token",
        "pattern": r"""(?:^|[\"'\s=:,])(?P<match>shpat_[a-fA-F0-9]{32})""",
        "severity": "CRITICAL",
        "category": "Hardcoded credentials",
        "impact": "Shopify store admin access.",
        "recommendation": "Revoke token in Shopify admin.",
    },
    # Square
    {
        "name": "Square Access Token",
        "pattern": r"""(?:^|[\"'\s=:,])(?P<match>sq0atp-[A-Za-z0-9_-]{22,})""",
        "severity": "CRITICAL",
        "category": "Hardcoded credentials",
        "impact": "Payment processing access.",
        "recommendation": "Rotate in Square developer dashboard.",
    },
    # Telegram
    {
        "name": "Telegram Bot Token",
        "pattern": r"""(?:^|[\"'\s=:,])(?P<match>[0-9]{8,10}:AA[0-9A-Za-z_-]{33})""",
        "severity": "HIGH",
        "category": "Hardcoded credentials",
        "impact": "Bot control, message interception.",
        "recommendation": "Revoke via @BotFather.",
    },
    # Discord
    {
        "name": "Discord Bot Token",
        "pattern": r"""(?:^|[\"'\s=:,])(?P<match>[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,})""",
        "severity": "CRITICAL",
        "category": "Hardcoded credentials",
        "impact": "Full bot control, server manipulation.",
        "recommendation": "Regenerate token in Discord developer portal.",
    },
    # Basic Auth in URLs
    {
        "name": "Credentials in URL",
        "pattern": r"""(?P<match>https?://[^/\s:]+:[^/\s@]+@[^/\s]+)""",
        "severity": "HIGH",
        "category": "Hardcoded credentials",
        "impact": "Plaintext credentials in URL, logged in browser history and server logs.",
        "recommendation": "Remove credentials from URLs. Use proper authentication.",
    },
]


# ────────────────────────────────────────────
# 2. NETWORK / INFRASTRUCTURE PATTERNS
# ────────────────────────────────────────────

NETWORK_PATTERNS = [
    {
        "name": "Internal IP Address (RFC 1918)",
        "pattern": r"""(?:^|[\"'\s=:,/(])(?P<match>(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}))(?:[\"'\s,;:)\]/>]|$)""",
        "severity": "LOW",
        "category": "Information disclosure",
        "impact": "Internal network topology exposure aids reconnaissance for lateral movement.",
        "recommendation": "Remove internal IPs from client-side code.",
    },
    {
        "name": "Localhost / Loopback Reference",
        "pattern": r"""(?P<match>https?://(?:localhost|127\.0\.0\.1)(?::\d+)?(?:/[^\s\"'<>]*)?)""",
        "severity": "LOW",
        "category": "Information disclosure",
        "impact": "Development/debug endpoint reference. May indicate SSRF potential or debug mode.",
        "recommendation": "Remove localhost references from production code.",
    },
    {
        "name": "S3 Bucket URL",
        "pattern": r"""(?P<match>(?:https?://)?(?:[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.)?s3(?:[.-](?:us|eu|ap|sa|ca|me|af)-[a-z]+-\d)?\.amazonaws\.com(?:/[^\s\"'<>]*)?)""",
        "severity": "MEDIUM",
        "category": "Information disclosure",
        "impact": "S3 bucket enumeration. Check for public listing, unauthorized read/write.",
        "recommendation": "Verify bucket ACLs and policies. Block public access if not needed.",
    },
    {
        "name": "S3 Bucket (path-style)",
        "pattern": r"""(?P<match>s3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9](?:/[^\s\"'<>]*)?)""",
        "severity": "MEDIUM",
        "category": "Information disclosure",
        "impact": "S3 bucket name exposure.",
        "recommendation": "Remove from client-side code. Verify bucket access controls.",
    },
    {
        "name": "GCS Bucket URL",
        "pattern": r"""(?P<match>(?:https?://)?storage\.googleapis\.com/[a-z0-9][a-z0-9._-]{1,61}[a-z0-9](?:/[^\s\"'<>]*)?)""",
        "severity": "MEDIUM",
        "category": "Information disclosure",
        "impact": "Google Cloud Storage bucket enumeration.",
        "recommendation": "Verify bucket IAM policies.",
    },
    {
        "name": "Azure Blob Storage URL",
        "pattern": r"""(?P<match>https?://[a-z0-9]{3,24}\.blob\.core\.windows\.net(?:/[^\s\"'<>]*)?)""",
        "severity": "MEDIUM",
        "category": "Information disclosure",
        "impact": "Azure storage account enumeration.",
        "recommendation": "Verify container access level and SAS token policies.",
    },
    {
        "name": "Internal/Staging Hostname",
        "pattern": r"""(?P<match>https?://[a-z0-9-]+\.(?:internal|local|staging|stage|dev|test|qa|uat|preprod|sandbox)\.[a-z]{2,}(?::\d+)?(?:/[^\s\"'<>]*)?)""",
        "severity": "MEDIUM",
        "category": "Information disclosure",
        "impact": "Internal environment exposure. Aids targeted attacks against non-hardened systems.",
        "recommendation": "Remove internal hostnames from production assets.",
    },
    {
        "name": "GraphQL Endpoint",
        "pattern": r"""(?P<match>https?://[^\s\"'<>]+/graphql(?:/?|\?[^\s\"'<>]*)?)""",
        "severity": "INFO",
        "category": "Sensitive endpoints",
        "impact": "GraphQL endpoint discovered. Test for introspection, authorization bypass, injection.",
        "recommendation": "Disable introspection in production. Enforce authorization on all resolvers.",
    },
]


# ────────────────────────────────────────────
# 3. CLIENT-SIDE VULNERABILITY SINKS
# ────────────────────────────────────────────

JS_SINK_PATTERNS = [
    {
        "name": "innerHTML Assignment",
        "pattern": r"""(?P<match>\.innerHTML\s*[=+])""",
        "severity": "MEDIUM",
        "category": "Client-side vulnerabilities",
        "impact": "DOM XSS if user-controlled data flows into innerHTML.",
        "recommendation": "Use textContent or a sanitization library (DOMPurify).",
    },
    {
        "name": "outerHTML Assignment",
        "pattern": r"""(?P<match>\.outerHTML\s*[=+])""",
        "severity": "MEDIUM",
        "category": "Client-side vulnerabilities",
        "impact": "DOM XSS via outerHTML injection.",
        "recommendation": "Avoid outerHTML with dynamic data. Use safe DOM APIs.",
    },
    {
        "name": "document.write",
        "pattern": r"""(?P<match>document\.write(?:ln)?\s*\()""",
        "severity": "MEDIUM",
        "category": "Client-side vulnerabilities",
        "impact": "DOM XSS if user input reaches document.write.",
        "recommendation": "Replace with DOM manipulation methods.",
    },
    {
        "name": "eval() Usage",
        "pattern": r"""(?P<match>(?:^|[^.\w])eval\s*\()""",
        "severity": "HIGH",
        "category": "Client-side vulnerabilities",
        "impact": "Arbitrary code execution if user-controlled data reaches eval.",
        "recommendation": "Remove eval. Use JSON.parse for data, safe alternatives for dynamic code.",
    },
    {
        "name": "Function() Constructor",
        "pattern": r"""(?P<match>(?:new\s+)?Function\s*\([\"'`])""",
        "severity": "HIGH",
        "category": "Client-side vulnerabilities",
        "impact": "Equivalent to eval. Code injection risk.",
        "recommendation": "Avoid dynamic Function construction.",
    },
    {
        "name": "setTimeout/setInterval with String",
        "pattern": r"""(?P<match>(?:setTimeout|setInterval)\s*\(\s*[\"'`])""",
        "severity": "MEDIUM",
        "category": "Client-side vulnerabilities",
        "impact": "String argument to setTimeout/setInterval is eval'd. Code injection risk.",
        "recommendation": "Pass a function reference instead of a string.",
    },
    {
        "name": "postMessage without Origin Check",
        "pattern": r"""(?P<match>addEventListener\s*\(\s*[\"']message[\"']\s*,)""",
        "severity": "MEDIUM",
        "category": "Client-side vulnerabilities",
        "impact": "If origin is not validated, attacker can send messages from any domain. XSS or logic bypass.",
        "recommendation": "Always check event.origin before processing postMessage data.",
    },
    {
        "name": "postMessage to Wildcard",
        "pattern": r"""(?P<match>\.postMessage\s*\([^)]+,\s*[\"']\*[\"']\s*\))""",
        "severity": "HIGH",
        "category": "Client-side vulnerabilities",
        "impact": "Data sent to any origin. Sensitive data leakage to malicious frames.",
        "recommendation": "Specify the exact target origin instead of '*'.",
    },
    {
        "name": "location.href/assign/replace with Variable",
        "pattern": r"""(?P<match>(?:location\.(?:href|assign|replace))\s*=\s*(?!['"][^'"]*['"])[\w])""",
        "severity": "MEDIUM",
        "category": "Client-side vulnerabilities",
        "impact": "Open redirect or javascript: URI injection if user-controlled.",
        "recommendation": "Validate and whitelist redirect targets.",
    },
    {
        "name": "jQuery html() with Variable",
        "pattern": r"""(?P<match>\.\$\(.*\)\.html\s*\((?!['"]<))""",
        "severity": "MEDIUM",
        "category": "Client-side vulnerabilities",
        "impact": "DOM XSS via jQuery .html() with unsanitized input.",
        "recommendation": "Use .text() for user data, or sanitize with DOMPurify.",
    },
    {
        "name": "Prototype Pollution Gadget",
        "pattern": r"""(?P<match>(?:__proto__|constructor\s*\[\s*[\"']prototype[\"']\]|Object\.assign\s*\(\s*\{\},?\s*(?:req|params|query|body|input)))""",
        "severity": "HIGH",
        "category": "Client-side vulnerabilities",
        "impact": "Prototype pollution can lead to XSS, privilege escalation, or RCE depending on context.",
        "recommendation": "Freeze prototypes. Validate and sanitize object keys. Avoid recursive merge of user input.",
    },
    {
        "name": "JSONP Callback",
        "pattern": r"""(?P<match>(?:callback|jsonp|cb)\s*=\s*[A-Za-z_]\w*)""",
        "severity": "MEDIUM",
        "category": "Client-side vulnerabilities",
        "impact": "JSONP endpoints can be abused for data exfiltration cross-origin.",
        "recommendation": "Migrate to CORS-based JSON APIs. If JSONP is required, validate callback name strictly.",
    },
    {
        "name": "localStorage/sessionStorage Sensitive Data",
        "pattern": r"""(?P<match>(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*[\"'](?:token|auth|session|password|secret|jwt|api[_-]?key|access[_-]?token|refresh[_-]?token)[\"'])""",
        "severity": "MEDIUM",
        "category": "Client-side vulnerabilities",
        "impact": "Sensitive data in browser storage is accessible via XSS.",
        "recommendation": "Use httpOnly cookies for tokens. Avoid storing secrets in localStorage/sessionStorage.",
    },
]


# ────────────────────────────────────────────
# 4. INFORMATION DISCLOSURE
# ────────────────────────────────────────────

INFO_DISCLOSURE_PATTERNS = [
    {
        "name": "Source Map File",
        "pattern": r"""(?P<match>//[#@]\s*sourceMappingURL\s*=\s*\S+\.map)""",
        "severity": "MEDIUM",
        "category": "Information disclosure",
        "impact": "Source maps expose original unminified source code, comments, and file structure.",
        "recommendation": "Remove sourceMappingURL from production builds. Don't deploy .map files.",
    },
    {
        "name": "HTML/JS Comment with Sensitive Keyword",
        "pattern": r"""(?P<match>(?://|/\*|<!--)\s*(?:TODO|FIXME|HACK|BUG|XXX|TEMP|DEPRECATED|SECURITY|VULNERABILITY|WORKAROUND|PASSWORD|CREDENTIAL|SECRET|ADMIN|BACKDOOR|BYPASS|DISABLE.*AUTH)[^\n*/>]{0,200})""",
        "severity": "LOW",
        "category": "Information disclosure",
        "impact": "Developer comments may reveal security concerns, workarounds, or debug info.",
        "recommendation": "Strip comments from production builds.",
    },
    {
        "name": "Debug Mode / Console Logging Sensitive Data",
        "pattern": r"""(?P<match>(?:debug|DEBUG|verbose)\s*[=:]\s*(?:true|1|[\"']true[\"']))""",
        "severity": "LOW",
        "category": "Misconfigurations",
        "impact": "Debug mode may expose verbose errors, stack traces, or internal state.",
        "recommendation": "Disable debug mode in production.",
    },
    {
        "name": "Stack Trace / Error Path Disclosure",
        "pattern": r"""(?P<match>(?:at\s+\S+\s+\()?(?:[A-Z]:\\(?:Users|home|var|src|app)[\\/][^\s\"'<>]{10,}|/(?:home|var|src|app|opt|usr)/[^\s\"'<>]{10,}\.(?:js|ts|py|java|rb|php|go|cs))(?::\d+:\d+\))?)""",
        "severity": "LOW",
        "category": "Information disclosure",
        "impact": "Server file paths reveal OS, framework, directory structure.",
        "recommendation": "Sanitize error output. Use generic error messages in production.",
    },
    {
        "name": "Email Address",
        "pattern": r"""(?P<match>[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(?:com|org|net|edu|gov|io|co|dev|info|biz))""",
        "severity": "INFO",
        "category": "Information disclosure",
        "impact": "Email addresses enable phishing, social engineering, and account enumeration.",
        "recommendation": "Remove personal/internal email addresses from client-side code.",
    },
    {
        "name": "Version Comment / Header",
        "pattern": r"""(?P<match>(?:version|ver|v)\s*[=:]\s*[\"']?\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.]+)?)""",
        "severity": "INFO",
        "category": "Information disclosure",
        "impact": "Version numbers help attackers find known CVEs for specific versions.",
        "recommendation": "Remove version strings from client-facing code.",
    },
    {
        "name": "Webpack Chunk / Bundle Info",
        "pattern": r"""(?P<match>(?:webpackChunk|__webpack_require__|webpackJsonp)\s*[\[(=])""",
        "severity": "INFO",
        "category": "Information disclosure",
        "impact": "Webpack internals reveal module structure. Chunk names can enumerate additional JS bundles.",
        "recommendation": "Use content hashing for chunk names. Minimize exposed module IDs.",
    },
    {
        "name": "Service Worker Registration",
        "pattern": r"""(?P<match>navigator\.serviceWorker\.register\s*\(\s*[\"']([^\"']+)[\"'])""",
        "severity": "INFO",
        "category": "Information disclosure",
        "impact": "Service worker script location. Review for cache poisoning, request interception.",
        "recommendation": "Audit the service worker for security issues.",
    },
]


# ────────────────────────────────────────────
# 5. MISCONFIGURATION PATTERNS
# ────────────────────────────────────────────

MISCONFIG_PATTERNS = [
    {
        "name": "CORS Wildcard",
        "pattern": r"""(?P<match>Access-Control-Allow-Origin\s*[=:]\s*[\"']?\*)""",
        "severity": "MEDIUM",
        "category": "Misconfigurations",
        "impact": "Any origin can make authenticated requests if credentials are allowed.",
        "recommendation": "Whitelist specific origins. Never combine '*' with credentials.",
    },
    {
        "name": "CSP Unsafe-Inline/Eval",
        "pattern": r"""(?P<match>(?:Content-Security-Policy|CSP)[^;]*(?:unsafe-inline|unsafe-eval))""",
        "severity": "MEDIUM",
        "category": "Misconfigurations",
        "impact": "CSP bypass — unsafe-inline/eval allow XSS payloads to execute.",
        "recommendation": "Use nonces or hashes instead of unsafe-inline. Remove unsafe-eval.",
    },
    {
        "name": "WebSocket Endpoint",
        "pattern": r"""(?P<match>wss?://[^\s\"'<>]+)""",
        "severity": "INFO",
        "category": "Sensitive endpoints",
        "impact": "WebSocket endpoint for further testing: auth bypass, injection, CSWSH.",
        "recommendation": "Test WebSocket for authentication, input validation, and origin checks.",
    },
    {
        "name": "Hardcoded API Base URL (Non-production)",
        "pattern": r"""(?P<match>(?:baseURL|base_url|apiUrl|api_url|API_URL|endpoint)[\s]*[=:]\s*[\"']https?://[^\s\"'<>]*(?:staging|stage|dev|test|qa|sandbox|preprod|localhost)[^\s\"'<>]*[\"'])""",
        "severity": "MEDIUM",
        "category": "Misconfigurations",
        "impact": "Non-production API endpoint in code. May be less hardened, contain test data.",
        "recommendation": "Ensure production builds point to production endpoints only.",
    },
]


# ────────────────────────────────────────────
# EXPANDED PATH PROBES
# ────────────────────────────────────────────

PROBE_PATHS = [
    # Common sensitive files
    "/robots.txt",
    "/sitemap.xml",
    "/.env",
    "/.env.local",
    "/.env.development",
    "/.env.production",
    "/.env.staging",
    "/.env.bak",
    "/.env.old",
    "/.env.example",
    "/config.json",
    "/config.yml",
    "/config.yaml",
    "/manifest.json",
    "/package.json",
    "/package-lock.json",
    "/composer.json",
    "/composer.lock",
    "/yarn.lock",

    # API documentation
    "/swagger.json",
    "/swagger.yaml",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs/swagger.json",
    "/redoc",
    "/graphql",
    "/graphiql",
    "/playground",
    "/altair",
    "/__graphql",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/docs",
    "/api/schema",

    # Source control
    "/.git/config",
    "/.git/HEAD",
    "/.git/index",
    "/.gitignore",
    "/.svn/entries",
    "/.svn/wc.db",
    "/.hg/store",
    "/.bzr/README",
    "/.DS_Store",

    # Build artifacts / source maps
    "/webpack-stats.json",
    "/stats.json",
    "/build-info.json",
    "/asset-manifest.json",
    "/precache-manifest.json",
    "/service-worker.js",
    "/sw.js",
    "/workbox-*.js",

    # Spring Boot Actuator
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/info",
    "/actuator/metrics",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/configprops",
    "/actuator/heapdump",
    "/actuator/threaddump",
    "/actuator/loggers",
    "/actuator/httptrace",
    "/actuator/scheduledtasks",
    "/actuator/caches",
    "/actuator/conditions",
    "/health",
    "/info",
    "/metrics",
    "/env",

    # Debug consoles & profilers
    "/debug",
    "/console",
    "/debug/default/view",
    "/_debug_toolbar/",
    "/_debugbar/open",
    "/_profiler/",
    "/elmah.axd",
    "/trace.axd",
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/server-info",
    "/.well-known/openid-configuration",

    # Common admin / management
    "/admin",
    "/admin/",
    "/administrator",
    "/wp-admin",
    "/wp-login.php",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/wp-config.php.orig",
    "/wp-config.php~",
    "/wp-json/wp/v2/users",
    "/.htaccess",
    "/.htpasswd",
    "/web.config",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/humans.txt",

    # Backup / temp files
    "/backup.sql",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/database.sql",
    "/dump.sql",
    "/.backup",

    # Node.js specific
    "/node_modules/.package-lock.json",
    "/.npmrc",
    "/.yarnrc",
    "/.babelrc",
    "/tsconfig.json",
    "/next.config.js",
    "/nuxt.config.js",
    "/vite.config.js",
    "/vue.config.js",
    "/angular.json",

    # Docker / CI
    "/Dockerfile",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/.dockerenv",
    "/.gitlab-ci.yml",
    "/.github/workflows/",
    "/Jenkinsfile",
    "/.circleci/config.yml",

    # Error pages that leak info
    "/404",
    "/500",
    "/error",
    "/errors",
]


# ────────────────────────────────────────────
# GraphQL introspection query
# ────────────────────────────────────────────

GRAPHQL_INTROSPECTION_QUERY = '{"query":"{ __schema { types { name fields { name } } } }"}'


# ────────────────────────────────────────────
# ENGINE
# ────────────────────────────────────────────

ALL_PATTERNS = (
    SECRET_PATTERNS
    + NETWORK_PATTERNS
    + JS_SINK_PATTERNS
    + INFO_DISCLOSURE_PATTERNS
    + MISCONFIG_PATTERNS
)

# Compile all patterns once
_COMPILED = []
for p in ALL_PATTERNS:
    try:
        _COMPILED.append((re.compile(p["pattern"], re.IGNORECASE | re.MULTILINE), p))
    except re.error:
        pass


def scan_content(content: str, source_url: str = "", file_type: str = "") -> list[Finding]:
    """Run all regex patterns against content. Returns list of Findings."""
    findings = []
    seen = set()  # deduplicate by (pattern_name, evidence)

    lines = content.split("\n")

    for compiled_re, pattern_info in _COMPILED:
        for i, line in enumerate(lines, 1):
            for match in compiled_re.finditer(line):
                try:
                    evidence = match.group("match")
                except IndexError:
                    evidence = match.group(0)

                # Truncate long evidence
                if len(evidence) > 300:
                    evidence = evidence[:300] + "..."

                dedup_key = (pattern_info["name"], evidence[:100])
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                findings.append(Finding(
                    severity=pattern_info["severity"],
                    category=pattern_info["category"],
                    description=f"{pattern_info['name']} detected",
                    evidence=evidence,
                    impact=pattern_info["impact"],
                    recommendation=pattern_info["recommendation"],
                    source_url=source_url,
                    file_type=file_type,
                    line_number=i,
                    detector="signature",
                ))

    return findings


def finding_to_dict(f: Finding) -> dict:
    return {
        "severity": f.severity,
        "category": f.category,
        "description": f.description,
        "evidence": f.evidence,
        "impact": f.impact,
        "recommendation": f.recommendation,
        "source_url": f.source_url,
        "file_type": f.file_type,
        "line_number": f.line_number,
        "detector": f.detector,
    }