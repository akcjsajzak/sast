"""PHP rule set: raw PHP, Laravel and Symfony aware."""
from __future__ import annotations

from .base import RuleSet, TaintSource, SinkRule, SanitizerRule, PatternRule

# Taint tag vocabulary (mapped to human labels in the report).
TAG_LABELS = {
    "sql": "SQL Injection",
    "xss": "Cross-Site Scripting",
    "cmd": "Command Injection",
    "ssrf": "Server-Side Request Forgery",
    "lfi": "File Inclusion / Path Traversal",
    "deser": "Insecure Deserialization",
    "xxe": "XML External Entity",
    "ldap": "LDAP Injection",
    "redirect": "Open Redirect / Header Injection",
    "email": "Email Header Injection",
    "path": "Path Traversal",
    "upload": "Unrestricted File Upload",
    "code": "Code Injection",
    "mass": "Mass Assignment",
    "log": "Log Injection",
    "ssti": "Server-Side Template Injection",
    "jndi": "JNDI Injection",
    "el": "Expression Language Injection",
    "xpath": "XPath Injection",
    "redos": "ReDoS (Regular Expression Denial of Service)",
    "session": "Session Fixation",
    "csv": "Formula (CSV) Injection",
}

_ALL_TAGS = ["sql", "xss", "cmd", "ssrf", "lfi", "deser", "xxe", "ldap",
             "redirect", "path", "upload", "code", "mass", "log",
             "ssti", "el", "xpath", "redos", "session", "csv"]

_SQL = ["sql"]
_XSS = ["xss"]
_CMD = ["cmd"]
_SSRF = ["ssrf"]
_LFI = ["lfi", "path"]
_DESER = ["deser"]
_XXE = ["xxe"]
_LDAP = ["ldap"]
_REDIR = ["redirect"]
_LOG = ["log"]
_PATH = ["path", "lfi"]


# $_SERVER keys that carry attacker-controlled data. Every HTTP_* entry is a
# verbatim request header; the rest are derived from the request line or from
# client-supplied credentials. Keys NOT listed here (DOCUMENT_ROOT,
# SCRIPT_FILENAME, SERVER_NAME, REMOTE_ADDR, ...) are set by the server and are
# deliberately not treated as taint sources.
_SERVER_TAINTED_KEYS = (
    "HTTP_*",            # every inbound request header
    "QUERY_STRING",
    "REQUEST_URI",
    "PATH_INFO",
    "ORIG_PATH_INFO",
    "PATH_TRANSLATED",
    "CONTENT_TYPE",
    "PHP_AUTH_USER",
    "PHP_AUTH_PW",
    "PHP_AUTH_DIGEST",
    "AUTH_TYPE",
)


def _sources() -> list[TaintSource]:
    s = []
    # Superglobals that are wholly attacker-controlled.
    for name in ("_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES"):
        s.append(TaintSource(
            kind="superglobal", match=name, tags=_ALL_TAGS,
            description=f"Untrusted data from superglobal ${name}",
        ))

    # $_SERVER is mixed: only request-derived keys are attacker-controlled.
    s.append(TaintSource(
        kind="superglobal", match="_SERVER", tags=_ALL_TAGS,
        keys=_SERVER_TAINTED_KEYS,
        description="Untrusted data from a request-controlled $_SERVER key",
    ))

    # Second-order sources: attacker data can reach these, but only if it was
    # stored earlier. Reported at lower confidence so they can be filtered out.
    s.append(TaintSource(
        kind="superglobal", match="_SESSION", tags=_ALL_TAGS, confidence="low",
        description="Session data in $_SESSION (second-order: tainted only if "
                    "attacker-controlled input was stored there)",
    ))
    s.append(TaintSource(
        kind="superglobal", match="_ENV", tags=_ALL_TAGS, confidence="low",
        description="Environment data in $_ENV (second-order: attacker-controlled "
                    "only if the environment is externally influenced)",
    ))

    # Raw request body and environment.
    s.append(TaintSource(
        kind="function", match="file_get_contents", tags=_ALL_TAGS,
        description="Raw HTTP request body read via file_get_contents('php://input')",
        arg_literal=(0, "php://input"),
    ))
    s.append(TaintSource(
        kind="function", match="getenv", tags=_ALL_TAGS, confidence="low",
        description="Environment variable (potentially attacker influenced)",
    ))
    for fn in ("getallheaders", "apache_request_headers"):
        s.append(TaintSource(
            kind="function", match=fn, tags=_ALL_TAGS,
            description=f"Untrusted data from HTTP request headers via {fn}()",
        ))

    # Laravel request accessors.
    laravel = ("Laravel",)
    for m in ("input", "query", "all", "get", "post", "json", "cookie", "header"):
        s.append(TaintSource(
            kind="method", match=m, tags=_ALL_TAGS, frameworks=laravel,
            description=f"Untrusted data from Laravel request accessor ->{m}()",
        ))
    s.append(TaintSource(
        kind="method", match="file", tags=["upload", "path", "lfi", "xss"], frameworks=laravel,
        description="Uploaded file from Laravel request ->file()",
    ))
    s.append(TaintSource(
        kind="static", match="input", cls="Request", tags=_ALL_TAGS, frameworks=laravel,
        description="Untrusted data from Laravel facade Request::input()",
    ))
    s.append(TaintSource(
        kind="static", match="get", cls="Input", tags=_ALL_TAGS, frameworks=laravel,
        description="Untrusted data from Laravel facade Input::get()",
    ))
    s.append(TaintSource(
        kind="function", match="request", tags=_ALL_TAGS, frameworks=laravel,
        description="Untrusted data from Laravel request() helper",
    ))
    s.append(TaintSource(
        kind="function", match="old", tags=_ALL_TAGS, frameworks=laravel,
        description="Untrusted data from Laravel old() helper (flashed input)",
    ))

    # Symfony request accessors.
    symfony = ("Symfony",)
    for m in ("get", "post", "query", "cookies", "headers", "files", "server", "request"):
        s.append(TaintSource(
            kind="method", match=m, tags=_ALL_TAGS, frameworks=symfony,
            description=f"Untrusted data from Symfony request ->{m}->get()/->all()",
        ))
    s.append(TaintSource(
        kind="function", match="getParameter", tags=_ALL_TAGS, frameworks=symfony,
        description="Untrusted data from Symfony container parameter",
    ))
    return s


def _sinks() -> list[SinkRule]:
    k = []
    A03 = "A03:2021 — Injection"
    A10 = "A10:2021 — Server-Side Request Forgery (SSRF)"

    # --- SQL injection (raw PHP) ---
    for fn in ("mysqli_query", "mysql_query", "mysqli_real_query", "pg_query",
               "pg_send_query", "sqlite_query", "mssql_query", "odbc_exec",
               "db2_exec", "mysqli_prepare", "mysqli_stmt_prepare"):
        k.append(SinkRule(
            rule_id=f"php-sqli-{fn}", kind="function", match=fn,
            title=f"SQL injection via {fn}()",
            severity="high", cwe="CWE-89", owasp=A03, category="sql-injection",
            description=f"Untrusted data flows into the SQL statement passed to {fn}() without parameterization.",
            remediation="Use prepared statements with bound parameters (e.g. PDO::prepare/execute).",
            tags=_SQL,
        ))
    # PDO object methods.
    for m, idx in (("query", 0), ("exec", 0), ("prepare", 0)):
        k.append(SinkRule(
            rule_id=f"php-sqli-pdo-{m}", kind="method", match=m,
            title=f"SQL injection via PDO->{m}()",
            severity="high", cwe="CWE-89", owasp=A03, category="sql-injection",
            description=f"Untrusted data flows into the SQL passed to PDO->{m}() without parameterization.",
            remediation="Use PDO::prepare() with bound parameters.",
            tags=_SQL, arg_index=idx,
        ))

    # --- SQL injection (Laravel) ---
    laravel = ("Laravel",)
    for m in ("select", "insert", "update", "delete", "statement", "unprepared", "raw"):
        k.append(SinkRule(
            rule_id=f"laravel-sqli-DB-{m}", kind="static", match=m, cls="DB",
            title=f"SQL injection via DB::{m}()",
            severity="high", cwe="CWE-89", owasp=A03, category="sql-injection",
            description=f"Untrusted data flows into DB::{m}() which executes raw SQL.",
            remediation="Use the query builder / Eloquent with parameter binding.",
            tags=_SQL, frameworks=laravel,
        ))
    for m in ("whereRaw", "orWhereRaw", "havingRaw", "orHavingRaw",
              "orderByRaw", "groupByRaw", "selectRaw"):
        k.append(SinkRule(
            rule_id=f"laravel-sqli-{m}", kind="method", match=m,
            title=f"SQL injection via query builder ->{m}()",
            severity="high", cwe="CWE-89", owasp=A03, category="sql-injection",
            description=f"Untrusted data flows into ->{m}() which accepts a raw SQL expression.",
            remediation="Use parameterized where()/orderBy() with separate binding values.",
            tags=_SQL, frameworks=laravel,
        ))

    # --- Mass assignment (Laravel) ---
    for m in ("create", "fill", "forceFill", "forceCreate", "updateOrCreate",
              "firstOrCreate", "update"):
        k.append(SinkRule(
            rule_id=f"laravel-mass-{m}", kind="method", match=m,
            title=f"Mass assignment via ->{m}()",
            severity="medium", cwe="CWE-915", owasp="A04:2021 — Insecure Design",
            category="mass-assignment",
            description=f"Untrusted request data flows into ->{m}(), which may mass-assign model attributes not listed in $fillable.",
            remediation="Use request->only([...]) with an explicit allow-list and keep $fillable/$guarded strict.",
            tags=["mass"], frameworks=laravel, confidence="low",
        ))
    for m in ("create", "forceCreate", "updateOrCreate", "firstOrCreate", "update"):
        k.append(SinkRule(
            rule_id=f"laravel-mass-static-{m}", kind="static", match=m,
            title=f"Mass assignment via Model::{m}()",
            severity="medium", cwe="CWE-915", owasp="A04:2021 — Insecure Design",
            category="mass-assignment",
            description=f"Untrusted request data flows into Model::{m}(), which may mass-assign model attributes not listed in $fillable.",
            remediation="Use request->only([...]) with an explicit allow-list and keep $fillable/$guarded strict.",
            tags=["mass"], frameworks=laravel, confidence="low",
        ))

    # --- SQL injection (Symfony Doctrine) ---
    k.append(SinkRule(
        rule_id="symfony-sqli-where", kind="method", match="where",
        title="SQL/DQL injection via Doctrine query builder ->where()",
        severity="high", cwe="CWE-89", owasp=A03, category="sql-injection",
        description="Untrusted data flows into a raw DQL expression passed to ->where().",
        remediation="Use parameter placeholders (e.g. ->where('x = :val')->setParameter('val', $value)).",
        tags=_SQL, frameworks=("Symfony",),
    ))

    # --- Command injection ---
    for fn in ("exec", "shell_exec", "system", "passthru", "popen", "proc_open",
               "pcntl_exec", "expect_popen"):
        k.append(SinkRule(
            rule_id=f"php-cmdi-{fn}", kind="function", match=fn,
            title=f"Command injection via {fn}()",
            severity="critical", cwe="CWE-78", owasp=A03, category="command-injection",
            description=f"Untrusted data flows into a shell command executed by {fn}().",
            remediation="Avoid shell execution with untrusted input; use escapeshellarg() and whitelist commands.",
            tags=_CMD,
        ))
    k.append(SinkRule(
        rule_id="php-cmdi-backtick", kind="shell", match="",
        title="Command injection via backtick shell execution",
        severity="critical", cwe="CWE-78", owasp=A03, category="command-injection",
        description="Untrusted data flows into a command executed via the backtick operator.",
        remediation="Avoid backtick execution; use escapeshellarg() and whitelist commands.",
        tags=_CMD,
    ))

    # --- XSS ---
    k.append(SinkRule(
        rule_id="php-xss-echo", kind="echo", match="",
        title="Reflected cross-site scripting via echo",
        severity="medium", cwe="CWE-79", owasp=A03, category="xss",
        description="Untrusted data is written to the response without HTML encoding.",
        remediation="Encode output with htmlspecialchars($data, ENT_QUOTES, 'UTF-8') or a template auto-escaper.",
        tags=_XSS,
    ))
    k.append(SinkRule(
        rule_id="php-xss-print", kind="print", match="",
        title="Reflected cross-site scripting via print",
        severity="medium", cwe="CWE-79", owasp=A03, category="xss",
        description="Untrusted data is written to the response without HTML encoding.",
        remediation="Encode output with htmlspecialchars() or a template auto-escaper.",
        tags=_XSS,
    ))
    k.append(SinkRule(
        rule_id="php-xss-printf", kind="function", match="printf",
        title="Cross-site scripting via printf()",
        severity="medium", cwe="CWE-79", owasp=A03, category="xss",
        description="Untrusted data is written to the response without HTML encoding.",
        remediation="Encode output before passing it to printf().",
        tags=_XSS,
    ))

    # --- File inclusion / LFI ---
    k.append(SinkRule(
        rule_id="php-lfi-include", kind="include", match="",
        title="Local file inclusion / arbitrary file read",
        severity="high", cwe="CWE-98", owasp=A03, category="file-inclusion",
        description="Untrusted data influences an include/require path.",
        remediation="Never include files using untrusted input; use a fixed whitelist of allowed files.",
        tags=_LFI,
    ))

    # --- SSRF ---
    for fn in ("curl_exec", "get_headers", "fopen", "readfile", "file",
               "fsockopen", "pfsockopen", "stream_socket_client"):
        k.append(SinkRule(
            rule_id=f"php-ssrf-{fn}", kind="function", match=fn,
            title=f"Server-side request forgery via {fn}()",
            severity="high", cwe="CWE-918", owasp=A10, category="ssrf",
            description=f"Untrusted data controls the URL passed to {fn}(), allowing requests to internal resources.",
            remediation="Validate and whitelist destination URLs; block loopback and private ranges.",
            tags=_SSRF,
        ))
    k.append(SinkRule(
        rule_id="php-ssrf-curl_setopt", kind="function", match="curl_setopt",
        title="Server-side request forgery via curl_setopt()",
        severity="high", cwe="CWE-918", owasp=A10, category="ssrf",
        description="Untrusted data controls a cURL option (e.g. CURLOPT_URL).",
        remediation="Validate and whitelist destination URLs.",
        tags=_SSRF,
    ))
    k.append(SinkRule(
        rule_id="php-ssrf-file_get_contents", kind="function", match="file_get_contents",
        title="SSRF / arbitrary file read via file_get_contents()",
        severity="high", cwe="CWE-918", owasp=A10, category="ssrf",
        description="Untrusted data controls the URL/path passed to file_get_contents().",
        remediation="Validate and whitelist URLs/paths; use CURLOPT_PROTOCOLS restrictions.",
        tags=_SSRF + ["lfi"],
    ))

    # --- Deserialization ---
    k.append(SinkRule(
        rule_id="php-deser-unserialize", kind="function", match="unserialize",
        title="Insecure deserialization via unserialize()",
        severity="high", cwe="CWE-502", owasp="A08:2021 — Software and Data Integrity Failures",
        category="insecure-deserialization",
        description="Untrusted data is passed to unserialize(), enabling object injection (POP chains).",
        remediation="Never unserialize untrusted data; use JSON with schema validation.",
        tags=_DESER,
    ))

    # --- XXE ---
    for fn in ("simplexml_load_string", "simplexml_load_file", "simplexml_import_dom"):
        k.append(SinkRule(
            rule_id=f"php-xxe-{fn}", kind="function", match=fn,
            title=f"XML external entity (XXE) via {fn}()",
            severity="high", cwe="CWE-611", owasp="A05:2021 — Security Misconfiguration",
            category="xxe",
            description=f"Untrusted XML is parsed by {fn}() which may resolve external entities by default.",
            remediation="Disable external entity loading (LIBXML_NONET) and DTDs before parsing.",
            tags=_XXE,
        ))
    for m in ("loadXML", "load"):
        k.append(SinkRule(
            rule_id=f"php-xxe-dom-{m}", kind="method", match=m,
            title=f"XML external entity (XXE) via DOMDocument->{m}()",
            severity="high", cwe="CWE-611", owasp="A05:2021 — Security Misconfiguration",
            category="xxe",
            description=f"Untrusted XML is parsed by DOMDocument->{m}() which may resolve external entities.",
            remediation="Disable external entity loading (libxml_disable_entity_loader, LIBXML_NONET).",
            tags=_XXE,
        ))

    # --- LDAP injection ---
    for fn in ("ldap_search", "ldap_list", "ldap_read"):
        k.append(SinkRule(
            rule_id=f"php-ldap-{fn}", kind="function", match=fn,
            title=f"LDAP injection via {fn}()",
            severity="high", cwe="CWE-90", owasp=A03, category="ldap-injection",
            description=f"Untrusted data flows into the LDAP filter passed to {fn}().",
            remediation="Escape LDAP filter values (ldap_escape) and use whitelisted attributes.",
            tags=_LDAP,
        ))

    # --- Header injection / open redirect ---
    k.append(SinkRule(
        rule_id="php-redirect-header", kind="function", match="header",
        title="Open redirect / header injection via header()",
        severity="medium", cwe="CWE-601", owasp="A01:2021 — Broken Access Control",
        category="open-redirect",
        description="Untrusted data flows into a header() call (e.g. Location or CRLF injection).",
        remediation="Whitelist redirect targets and strip CR/LF from header values.",
        tags=_REDIR,
    ))

    # --- Email header injection ---
    k.append(SinkRule(
        rule_id="php-email-mail", kind="function", match="mail",
        title="Email header injection via mail()",
        severity="medium", cwe="CWE-93", owasp=A03, category="email-header-injection",
        description="Untrusted data flows into mail() headers/subject, allowing header injection.",
        remediation="Validate and strip CR/LF from all mail() inputs.",
        tags=["email"],
    ))

    # --- SSRF (additional transports) ---
    k.append(SinkRule(
        rule_id="php-ssrf-curl_init", kind="function", match="curl_init",
        title="Server-side request forgery via curl_init()",
        severity="high", cwe="CWE-918", owasp=A10, category="ssrf",
        description="Untrusted data controls the URL passed to curl_init().",
        remediation="Validate and whitelist destination URLs.",
        tags=_SSRF,
    ))
    for m in ("get", "post", "put", "delete", "patch", "request", "head"):
        k.append(SinkRule(
            rule_id=f"php-ssrf-http-{m}", kind="static", match=m, cls="Http",
            title=f"Server-side request forgery via Http::{m}()",
            severity="high", cwe="CWE-918", owasp=A10, category="ssrf",
            description=f"Untrusted data controls the URL passed to Laravel Http::{m}().",
            remediation="Validate and whitelist destination URLs.",
            tags=_SSRF, frameworks=laravel,
        ))
    k.append(SinkRule(
        rule_id="php-ssrf-guzzle-request", kind="method", match="request",
        title="Server-side request forgery via Guzzle ->request()",
        severity="high", cwe="CWE-918", owasp=A10, category="ssrf",
        description="Untrusted data controls the URL passed to a Guzzle HTTP client.",
        remediation="Validate and whitelist destination URLs.",
        tags=_SSRF,
    ))

    # --- Open redirect (framework helpers) ---
    k.append(SinkRule(
        rule_id="php-redirect-fn", kind="function", match="redirect",
        title="Open redirect via redirect() helper",
        severity="medium", cwe="CWE-601", owasp="A01:2021 — Broken Access Control",
        category="open-redirect",
        description="Untrusted data flows into a redirect() target.",
        remediation="Whitelist redirect targets.",
        tags=_REDIR,
    ))
    k.append(SinkRule(
        rule_id="php-redirect-away", kind="method", match="away",
        title="Open redirect via redirect()->away()",
        severity="medium", cwe="CWE-601", owasp="A01:2021 — Broken Access Control",
        category="open-redirect",
        description="Untrusted data flows into an external redirect target via ->away().",
        remediation="Whitelist redirect targets; avoid redirecting to user-controlled URLs.",
        tags=_REDIR,
    ))
    k.append(SinkRule(
        rule_id="php-redirect-response", kind="object_create", match="RedirectResponse",
        title="Open redirect via RedirectResponse",
        severity="medium", cwe="CWE-601", owasp="A01:2021 — Broken Access Control",
        category="open-redirect",
        description="Untrusted data controls a RedirectResponse target.",
        remediation="Whitelist redirect targets.",
        tags=_REDIR, frameworks=("Symfony",),
    ))

    # --- Path traversal / arbitrary file access ---
    for fn in ("file_put_contents", "fopen", "readfile", "file", "copy", "rename",
               "unlink", "rmdir"):
        k.append(SinkRule(
            rule_id=f"php-path-{fn}", kind="function", match=fn,
            title=f"Path traversal via {fn}()",
            severity="high", cwe="CWE-22", owasp="A01:2021 — Broken Access Control",
            category="path-traversal",
            description=f"Untrusted data controls a filesystem path passed to {fn}().",
            remediation="Canonicalize and validate paths against an allow-list directory.",
            tags=_PATH,
        ))
    k.append(SinkRule(
        rule_id="php-path-move_uploaded_file", kind="function", match="move_uploaded_file",
        title="Path traversal via move_uploaded_file()",
        severity="high", cwe="CWE-22", owasp="A01:2021 — Broken Access Control",
        category="path-traversal",
        description="Untrusted data controls the destination path of an uploaded file.",
        remediation="Generate the destination filename server-side; never trust the client name.",
        tags=_PATH, arg_index=1,
    ))

    # --- Log injection ---
    for fn in ("error_log", "syslog", "trigger_error"):
        k.append(SinkRule(
            rule_id=f"php-log-{fn}", kind="function", match=fn,
            title=f"Log injection via {fn}()",
            severity="low", cwe="CWE-117", owasp="A09:2021 — Security Logging and Monitoring Failures",
            category="log-injection",
            description=f"Untrusted data is written to logs via {fn}(), allowing log-forging/CRLF injection.",
            remediation="Strip CR/LF and sanitize untrusted values before logging.",
            tags=_LOG,
        ))

    # --- Server-side template injection (Twig) ---
    for kind in ("function", "method"):
        k.append(SinkRule(
            rule_id=f"php-ssti-createTemplate-{kind}", kind=kind, match="createTemplate",
            title="Server-side template injection via Twig createTemplate()",
            severity="high", cwe="CWE-1336", owasp=A03, category="ssti",
            description="Untrusted data is compiled as a Twig template, enabling template code execution.",
            remediation="Never build templates from untrusted input; use static templates.",
            tags=["ssti"],
        ))

    # --- XPath injection ---
    k.append(SinkRule(
        rule_id="php-xpath-xpath", kind="method", match="xpath",
        title="XPath injection via ->xpath()",
        severity="high", cwe="CWE-643", owasp=A03, category="xpath-injection",
        description="Untrusted data flows into an XPath query.",
        remediation="Use parameterized XPath (DOMXPath::query with registerPhpFunctions) and whitelist expressions.",
        tags=["xpath"],
    ))
    k.append(SinkRule(
        rule_id="php-xpath-evaluate", kind="method", match="evaluate",
        title="XPath injection via DOMXPath->evaluate()",
        severity="high", cwe="CWE-643", owasp=A03, category="xpath-injection",
        description="Untrusted data flows into an XPath expression.",
        remediation="Whitelist XPath expressions; never build them from untrusted input.",
        tags=["xpath"],
    ))

    # --- ReDoS (tainted regex pattern) ---
    for fn in ("preg_match", "preg_match_all", "preg_replace", "preg_split"):
        k.append(SinkRule(
            rule_id=f"php-redos-{fn}", kind="function", match=fn,
            title=f"ReDoS via {fn}() with untrusted pattern",
            severity="low", cwe="CWE-1333", owasp="A04:2021 — Insecure Design",
            category="redos",
            description=f"An untrusted value is used as the regex pattern in {fn}(), enabling catastrophic backtracking.",
            remediation="Never use untrusted regex; escape with preg_quote() and bound backtracking.",
            tags=["redos"], arg_index=0,
        ))

    # --- Session fixation ---
    k.append(SinkRule(
        rule_id="php-session-id", kind="function", match="session_id",
        title="Session fixation via session_id()",
        severity="medium", cwe="CWE-384", owasp="A07:2021 — Identification and Authentication Failures",
        category="session-fixation",
        description="Untrusted data sets the session identifier.",
        remediation="Never set session_id() from user input; call session_regenerate_id() on privilege change.",
        tags=["session"], arg_index=0,
    ))

    # --- Formula / CSV injection ---
    k.append(SinkRule(
        rule_id="php-csv-fputcsv", kind="function", match="fputcsv",
        title="Formula injection via fputcsv()",
        severity="low", cwe="CWE-1236", owasp="A03:2021 — Injection",
        category="formula-injection",
        description="Untrusted data written to a CSV/Excel export can begin with =, +, -, @ and execute as a formula.",
        remediation="Prefix untrusted cells that start with =,+,-,@ with a single quote.",
        tags=["csv"],
    ))

    # --- Variable injection ---
    for fn in ("extract", "parse_str"):
        k.append(SinkRule(
            rule_id=f"php-varinject-{fn}", kind="function", match=fn,
            title=f"Variable injection via {fn}()",
            severity="high", cwe="CWE-915", owasp=A03, category="code-injection",
            description=f"Untrusted data passed to {fn}() can overwrite local variables.",
            remediation=f"Avoid {fn}() with untrusted data; use explicit variable assignment.",
            tags=["code"],
        ))

    return k


def _sanitizers() -> list[SanitizerRule]:
    s = []
    # HTML escaping neutralizes XSS.
    for fn in ("htmlspecialchars", "htmlentities", "strip_tags"):
        s.append(SanitizerRule(kind="function", match=fn, neutralize=["xss"]))
    # Laravel's e() helper.
    s.append(SanitizerRule(kind="function", match="e", neutralize=["xss"], frameworks=("Laravel",)))
    s.append(SanitizerRule(kind="function", match="htmlspecialchars", neutralize=["xss"]))
    # SQL escaping.
    for fn in ("addslashes", "mysqli_real_escape_string", "mysql_real_escape_string",
               "pg_escape_string", "pg_escape_literal", "sqlite_escape_string"):
        s.append(SanitizerRule(kind="function", match=fn, neutralize=["sql"]))
    s.append(SanitizerRule(kind="method", match="quote", neutralize=["sql"], cls="PDO"))
    # Command escaping.
    for fn in ("escapeshellarg", "escapeshellcmd"):
        s.append(SanitizerRule(kind="function", match=fn, neutralize=["cmd"]))
    # Numeric coercion neutralizes string injection.
    for fn in ("intval", "floatval", "doubleval", "abs"):
        s.append(SanitizerRule(kind="function", match=fn, neutralize=["sql", "cmd", "xss", "ssrf", "lfi", "xxe", "ldap"]))
    # filter_var with sanitize/validate filters.
    s.append(SanitizerRule(kind="function", match="filter_var", neutralize=["sql", "cmd", "xss", "ssrf", "lfi", "ldap"]))
    # URL encoding.
    s.append(SanitizerRule(kind="function", match="urlencode", neutralize=["redirect"]))
    s.append(SanitizerRule(kind="function", match="rawurlencode", neutralize=["redirect"]))
    # Regex escaping.
    s.append(SanitizerRule(kind="function", match="preg_quote", neutralize=["redos"]))
    # Symfony/Laravel escaping helpers.
    s.append(SanitizerRule(kind="method", match="escape", neutralize=["xss"], frameworks=("Symfony",)))
    return s


def _patterns() -> list[PatternRule]:
    p = []
    p.append(PatternRule(
        rule_id="php-code-eval", node_type="function_call_expression", match="eval",
        match_field="callee", title="Code injection via eval()",
        severity="critical", cwe="CWE-95", owasp="A03:2021 — Injection",
        category="code-injection",
        description="eval() executes a string as PHP code. If any part is influenced by user input this is arbitrary code execution.",
        remediation="Remove eval() and use explicit, whitelisted logic.",
    ))
    p.append(PatternRule(
        rule_id="php-code-assert", node_type="function_call_expression", match="assert",
        match_field="callee", title="Code injection via assert()",
        severity="high", cwe="CWE-95", owasp="A03:2021 — Injection",
        category="code-injection",
        description="assert() with a string argument evaluates it as PHP code.",
        remediation="Remove assert() in production code.",
    ))
    p.append(PatternRule(
        rule_id="php-crypto-md5", node_type="function_call_expression", match="md5",
        match_field="callee", title="Weak cryptographic hash (MD5)",
        severity="low", cwe="CWE-328", owasp="A02:2021 — Cryptographic Failures",
        category="weak-crypto",
        description="MD5 is cryptographically broken. If used for passwords or integrity this is a weakness.",
        remediation="Use password_hash()/password_verify() for passwords and SHA-256+ for integrity.",
    ))
    return p


def build_php_rules() -> RuleSet:
    return RuleSet(
        sources=_sources(),
        sinks=_sinks(),
        sanitizers=_sanitizers(),
        patterns=_patterns(),
    )
