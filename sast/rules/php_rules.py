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
             "ssti", "el", "xpath", "redos", "session", "csv",
             # `email` was used by the mail() rule but never produced by any
             # source, so that rule could not fire at all.
             "email"]

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

    # Raw request body and environment. This arg_literal rule is listed before
    # the generic file-read source below so php://input keeps high confidence.
    s.append(TaintSource(
        kind="function", match="file_get_contents", tags=_ALL_TAGS,
        description="Raw HTTP request body read via file_get_contents('php://input')",
        arg_literal=(0, "php://input"),
    ))

    # --- Second-order sources -------------------------------------------
    # Data read back out of storage. It is attacker-controlled whenever
    # attacker input was written there earlier, which is exactly the shape of
    # stored XSS and second-order SQL injection. Reported at low confidence
    # because that depends on a write the scan may never see.
    for fn in ("mysqli_fetch_assoc", "mysqli_fetch_array", "mysqli_fetch_row",
               "mysqli_fetch_object", "mysqli_fetch_all", "pg_fetch_assoc",
               "pg_fetch_array", "pg_fetch_row", "pg_fetch_object",
               "pg_fetch_all", "pg_fetch_result", "sqlite_fetch_array",
               "odbc_fetch_array", "odbc_result"):
        s.append(TaintSource(
            kind="function", match=fn, tags=_ALL_TAGS, confidence="low",
            description=f"Row read back from the database via {fn}() "
                        "(second-order: tainted if attacker data was stored)",
        ))
    for m in ("fetch", "fetchAll", "fetchColumn", "fetchObject"):
        s.append(TaintSource(
            kind="method", match=m, tags=_ALL_TAGS, confidence="low",
            description=f"Row read back from the database via PDO ->{m}() "
                        "(second-order: tainted if attacker data was stored)",
        ))
    for fn in ("file_get_contents", "file", "fgets", "fread", "fgetss",
               "fscanf", "readfile", "stream_get_contents", "fgetcsv",
               "parse_ini_file", "simplexml_load_file"):
        s.append(TaintSource(
            kind="function", match=fn, tags=_ALL_TAGS, confidence="low",
            description=f"Data read from an external file or stream via {fn}() "
                        "(trusted only if the file is)",
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
    A01 = "A01:2021 — Broken Access Control"
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

    # --- Dynamically chosen code ---
    # An attacker who picks which function runs has arbitrary code execution
    # against whatever is loaded, without needing eval().
    for fn, idx in (("call_user_func", 0), ("call_user_func_array", 0),
                    ("forward_static_call", 0),
                    ("forward_static_call_array", 0),
                    ("array_map", 0), ("array_filter", 1),
                    ("array_walk", 1), ("usort", 1),
                    ("register_shutdown_function", 0),
                    ("set_error_handler", 0)):
        k.append(SinkRule(
            rule_id=f"php-code-{fn}", kind="function", match=fn,
            title=f"Attacker-controlled callable passed to {fn}()",
            severity="critical", cwe="CWE-470", owasp=A03,
            category="unsafe-reflection",
            description="The function to call is chosen by untrusted input, "
                        "so the attacker decides which code runs.",
            remediation="Map the input through a fixed allow-list of callables.",
            tags=["code", "cmd"], arg_index=idx,
        ))
    k.append(SinkRule(
        rule_id="php-code-create_function", kind="function",
        match="create_function",
        title="Code injection via create_function()",
        severity="critical", cwe="CWE-95", owasp=A03, category="code-injection",
        description="create_function() compiles its body as PHP, so untrusted "
                    "input there is arbitrary code execution. It was removed "
                    "in PHP 8.",
        remediation="Use a closure, and never build one from input.",
        tags=["code"], arg_index=1,
    ))
    k.append(SinkRule(
        rule_id="php-code-dynamic-call", kind="dynamic_call", match="",
        title="Call through an attacker-controlled function name",
        severity="critical", cwe="CWE-470", owasp=A03,
        category="unsafe-reflection",
        description="The name of the function being called comes from "
                    "untrusted input, so the attacker chooses which code runs.",
        remediation="Dispatch through a fixed map of allowed names.",
        tags=["code", "cmd"],
    ))

    # --- Variable variables ---
    # `$$name = x` writes to a variable the attacker names, which can
    # overwrite anything in scope. `extract()` has the same effect and is
    # already covered; this is the explicit form.
    k.append(SinkRule(
        rule_id="php-mass-variable-variable", kind="variable_variable",
        match="",
        title="Write to an attacker-named variable",
        severity="high", cwe="CWE-621", owasp=A03,
        category="variable-overwrite",
        description="A variable variable lets untrusted input choose which "
                    "variable is written, so any value in scope — including "
                    "one a later security check reads — can be overwritten.",
        remediation="Use an array keyed by the input instead of naming a "
                    "variable with it.",
        tags=["mass", "code"],
    ))

    # --- Directory listing by an attacker-controlled path ---
    for fn in ("scandir", "opendir", "glob", "dir", "rmdir", "mkdir",
               "is_dir", "disk_free_space"):
        k.append(SinkRule(
            rule_id=f"php-path-{fn}", kind="function", match=fn,
            title=f"Path traversal via {fn}()",
            severity="medium", cwe="CWE-22", owasp=A01,
            category="path-traversal",
            description="An attacker-controlled path lets the caller reach "
                        "directories outside the intended root, which "
                        "discloses the layout of the filesystem.",
            remediation="Resolve the path with realpath() and verify it stays "
                        "inside an allow-listed root.",
            tags=_LFI, arg_index=0, confidence="medium",
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
    # HTML escaping. Order matters: the first rule whose preconditions hold
    # wins, so the sound variants are listed before the weak fallbacks.

    # htmlspecialchars/htmlentities are treated as sound for XSS. Since PHP
    # 8.1 the default flags are ENT_QUOTES|ENT_SUBSTITUTE, so single quotes
    # are escaped without being asked for; requiring an explicit ENT_QUOTES
    # would flag correct modern code. What remains unsound is the *context*
    # (inside <script>, or an unquoted attribute), which needs template
    # analysis the engine does not have — see README "Limitations".
    for fn in ("htmlspecialchars", "htmlentities"):
        s.append(SanitizerRule(kind="function", match=fn, neutralize=["xss"]))
    # strip_tags removes tags but escapes nothing, so quotes and event-handler
    # payloads survive in any attribute context — unsound at any PHP version.
    s.append(SanitizerRule(
        kind="function", match="strip_tags", neutralize=["xss"], weak=True,
        note="strip_tags() does not escape quotes; unsafe in an attribute context",
    ))
    # Laravel's e() defaults to ENT_QUOTES.
    s.append(SanitizerRule(kind="function", match="e", neutralize=["xss"],
                           frameworks=("Laravel",)))

    # SQL escaping. The driver-aware functions are sound; addslashes is not.
    for fn in ("mysqli_real_escape_string", "mysql_real_escape_string",
               "pg_escape_string", "pg_escape_literal", "sqlite_escape_string"):
        s.append(SanitizerRule(kind="function", match=fn, neutralize=["sql"]))
    s.append(SanitizerRule(
        kind="function", match="addslashes", neutralize=["sql"], weak=True,
        note="addslashes() is not connection-charset aware and is bypassable "
             "under multibyte charsets (e.g. GBK); use prepared statements",
    ))
    s.append(SanitizerRule(kind="method", match="quote", neutralize=["sql"], cls="PDO"))

    # Command escaping. escapeshellarg quotes a single argument correctly;
    # escapeshellcmd only escapes shell metacharacters and still permits
    # argument injection (e.g. a leading "-" turning into a flag).
    s.append(SanitizerRule(kind="function", match="escapeshellarg", neutralize=["cmd"]))
    s.append(SanitizerRule(
        kind="function", match="escapeshellcmd", neutralize=["cmd"], weak=True,
        note="escapeshellcmd() does not quote individual arguments and still "
             "allows argument injection; use escapeshellarg() per argument",
    ))

    # Numeric coercion neutralizes string injection.
    for fn in ("intval", "floatval", "doubleval", "abs"):
        s.append(SanitizerRule(kind="function", match=fn, neutralize=["sql", "cmd", "xss", "ssrf", "lfi", "xxe", "ldap"]))
    # filter_var only filters when a filter is actually supplied; the
    # single-argument form defaults to FILTER_DEFAULT, which does nothing.
    s.append(SanitizerRule(
        kind="function", match="filter_var",
        neutralize=["sql", "cmd", "xss", "ssrf", "lfi", "ldap"],
        min_args=2,
    ))
    # URL encoding.
    s.append(SanitizerRule(kind="function", match="urlencode", neutralize=["redirect"]))
    s.append(SanitizerRule(kind="function", match="rawurlencode", neutralize=["redirect"]))
    # Regex escaping.
    s.append(SanitizerRule(kind="function", match="preg_quote", neutralize=["redos"]))
    # Symfony/Laravel escaping helpers.
    s.append(SanitizerRule(kind="method", match="escape", neutralize=["xss"], frameworks=("Symfony",)))
    return s


A03_P = "A03:2021 — Injection"


def _patterns() -> list[PatternRule]:
    A02 = "A02:2021 — Cryptographic Failures"
    A05 = "A05:2021 — Security Misconfiguration"
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
    p.append(PatternRule(
        rule_id="php-crypto-sha1", node_type="function_call_expression", match="sha1",
        match_field="callee", title="Weak cryptographic hash (SHA-1)",
        severity="low", cwe="CWE-328", owasp=A02, category="weak-crypto",
        description="SHA-1 is collision-prone and unsuitable for signatures, "
                    "integrity checks or password storage.",
        remediation="Use password_hash()/password_verify() for passwords and SHA-256+ otherwise.",
    ))
    for fn in ("rand", "mt_rand", "lcg_value", "uniqid", "shuffle", "str_shuffle",
               "array_rand", "mt_srand", "srand"):
        p.append(PatternRule(
            rule_id=f"php-weak-random-{fn}", node_type="function_call_expression",
            match=fn, match_field="callee",
            title="Predictable random number generator",
            severity="medium", cwe="CWE-338", owasp=A02, category="weak-random",
            description=f"{fn}() is not cryptographically secure. Using it for tokens, "
                        "session identifiers, password resets or nonces makes them guessable.",
            remediation="Use random_bytes() or random_int() for anything security-relevant.",
            confidence="medium",
        ))
    p.append(PatternRule(
        rule_id="php-tls-verify-disabled", node_type="function_call_expression",
        match=r"CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0|FALSE)",
        match_field="text", regex=True,
        title="TLS certificate verification disabled",
        severity="high", cwe="CWE-295", owasp=A02, category="insecure-transport",
        description="Disabling CURLOPT_SSL_VERIFYPEER/VERIFYHOST accepts any certificate, "
                    "making the connection trivially machine-in-the-middle-able.",
        remediation="Leave verification enabled and fix the trust store instead.",
    ))
    p.append(PatternRule(
        rule_id="php-crypto-ecb", node_type="function_call_expression",
        match=r"['\"][a-z0-9-]*-ecb['\"]", match_field="text", regex=True,
        title="Insecure cipher mode (ECB)",
        severity="medium", cwe="CWE-327", owasp=A02, category="weak-crypto",
        description="ECB encrypts identical plaintext blocks to identical ciphertext "
                    "blocks, leaking structure in the plaintext.",
        remediation="Use an authenticated mode such as AES-GCM, or AES-CBC with a random IV and a MAC.",
    ))
    p.append(PatternRule(
        rule_id="php-cookie-insecure", node_type="function_call_expression",
        match=r"setcookie\s*\([^;]*?,\s*(?:false|0)\s*,\s*(?:false|0)\s*\)",
        match_field="text", regex=True,
        title="Cookie set without Secure and HttpOnly",
        severity="medium", cwe="CWE-1004", owasp=A05, category="security-misconfiguration",
        description="A cookie is set with both the secure and httponly flags off, so it "
                    "is sent over plaintext HTTP and is readable from JavaScript.",
        remediation="Set secure=true and httponly=true, and add SameSite.",
        confidence="medium",
    ))
    p.append(PatternRule(
        rule_id="php-xxe-entity-loader", node_type="function_call_expression",
        match=r"libxml_disable_entity_loader\s*\(\s*(?:false|0|FALSE)\s*\)",
        match_field="text", regex=True,
        title="XML external entity loading re-enabled",
        severity="high", cwe="CWE-611", owasp=A05, category="xxe",
        description="libxml_disable_entity_loader(false) re-enables external entity "
                    "resolution, exposing the parser to XXE.",
        remediation="Leave entity loading disabled, or parse without LIBXML_NOENT/LIBXML_DTDLOAD.",
    ))
    p.append(PatternRule(
        rule_id="php-xxe-noent", node_type="function_call_expression",
        match=r"LIBXML_(?:NOENT|DTDLOAD)", match_field="text", regex=True,
        title="XML parsed with external entities enabled",
        severity="high", cwe="CWE-611", owasp=A05, category="xxe",
        description="LIBXML_NOENT/LIBXML_DTDLOAD substitute external entities while "
                    "parsing, which is the XXE primitive.",
        remediation="Parse without these flags.",
    ))
    p.append(PatternRule(
        rule_id="php-code-preg-replace-eval",
        node_type="function_call_expression",
        # The modifiers sit inside the quoted pattern, after its final
        # delimiter: '/a/e', "#x#ie". Matching them outside the quotes found
        # nothing at all.
        match=r"""preg_replace\s*\(\s*(['"])[^'"]*[/#~!%|][a-zA-Z]*e[a-zA-Z]*\1""",
        match_field="text", regex=True,
        title="preg_replace() with the /e modifier",
        severity="critical", cwe="CWE-95", owasp=A03_P,
        category="code-injection",
        description="The /e modifier makes preg_replace() evaluate its "
                    "replacement as PHP, so anything reaching the replacement "
                    "— or the subject, through a backreference — is executed. "
                    "It was removed in PHP 7.",
        remediation="Use preg_replace_callback() with a fixed callback.",
    ))
    return p


def build_php_rules() -> RuleSet:
    return RuleSet(
        sources=_sources(),
        sinks=_sinks(),
        sanitizers=_sanitizers(),
        patterns=_patterns(),
    )
