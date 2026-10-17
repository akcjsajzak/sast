"""Python rule set: raw Python plus Django, Flask and FastAPI."""
from __future__ import annotations

from .base import RuleSet, TaintSource, SinkRule, SanitizerRule, PatternRule

A01 = "A01:2021 — Broken Access Control"
A02 = "A02:2021 — Cryptographic Failures"
A03 = "A03:2021 — Injection"
A05 = "A05:2021 — Security Misconfiguration"
A07 = "A07:2021 — Identification and Authentication Failures"
A08 = "A08:2021 — Software and Data Integrity Failures"
A10 = "A10:2021 — Server-Side Request Forgery (SSRF)"

_ALL = ["sql", "cmd", "xss", "ssrf", "lfi", "path", "deser", "code", "ssti",
        "redirect", "log", "xxe", "ldap", "nosql", "xpath"]
_SQL = ["sql"]
_CMD = ["cmd"]
_PATH = ["path", "lfi"]

DJANGO = ("Django",)
FLASK = ("Flask",)
FASTAPI = ("FastAPI",)


def _sources() -> list[TaintSource]:
    s: list[TaintSource] = []
    # Flask / Django / FastAPI request objects.
    for prop in ("args", "form", "values", "json", "data", "files", "cookies",
                 "headers", "query_params", "path_params", "GET", "POST",
                 "body", "stream", "url", "full_path", "query_string"):
        s.append(TaintSource(
            kind="member", match=prop, tags=_ALL, obj_hint="request",
            description=f"Untrusted data from the HTTP request (request.{prop})",
        ))
    for m in ("get_json", "get_data", "read"):
        s.append(TaintSource(
            kind="call", match=m, tags=_ALL, obj_hint="request",
            description=f"Untrusted data from the HTTP request (request.{m}())",
        ))
    # Raw CGI / WSGI / CLI.
    s.append(TaintSource(
        kind="member", match="argv", tags=_ALL, obj_hint="sys",
        description="Untrusted data from command-line arguments (sys.argv)",
    ))
    for m in ("input", "raw_input"):
        s.append(TaintSource(
            kind="call", match=m, tags=_ALL,
            description=f"Untrusted data read from stdin via {m}()",
        ))
    # Second-order.
    s.append(TaintSource(
        kind="member", match="environ", tags=_ALL, obj_hint="os", confidence="low",
        description="Environment data (os.environ) — attacker-controlled only if "
                    "the environment is",
    ))
    for m in ("fetchone", "fetchall", "fetchmany"):
        s.append(TaintSource(
            kind="call", match=m, tags=_ALL, confidence="low",
            description=f"Row read back from the database via {m}() "
                        "(second-order: tainted if attacker data was stored)",
        ))
    for m in ("read", "readline", "readlines"):
        s.append(TaintSource(
            kind="call", match=m, tags=_ALL, obj_hint="f", confidence="low",
            description=f"Data read from an external file via {m}()",
        ))
    return s


def _sinks() -> list[SinkRule]:
    k: list[SinkRule] = []

    def sink(rid, match, title, severity, cwe, owasp, category, desc, fix, tags,
             arg_index=-1, obj_hint=None, frameworks=("*",), confidence="high",
             kind="call"):
        k.append(SinkRule(rule_id=rid, kind=kind, match=match, title=title,
                          severity=severity, cwe=cwe, owasp=owasp,
                          category=category, description=desc, remediation=fix,
                          tags=tags, arg_index=arg_index, obj_hint=obj_hint,
                          frameworks=frameworks, confidence=confidence))

    # Code execution
    for fn in ("eval", "exec", "compile"):
        sink(f"py-code-{fn}", fn, f"Code injection via {fn}()", "critical",
             "CWE-95", A03, "code-injection",
             f"{fn}() executes its argument as Python. With attacker-controlled "
             "input this is arbitrary code execution.",
             "Remove the dynamic evaluation; use explicit whitelisted logic.",
             ["code"], arg_index=0)
    for fn in ("loads", "load"):
        sink(f"py-deser-pickle-{fn}", fn,
             f"Insecure deserialization via pickle.{fn}()", "critical",
             "CWE-502", A08, "insecure-deserialization",
             "pickle executes arbitrary code during deserialization; untrusted "
             "pickle data is remote code execution.",
             "Use JSON for data interchange, or sign payloads and verify first.",
             ["deser", "code"], arg_index=0, obj_hint="pickle")
    sink("py-deser-yaml-load", "load",
         "Insecure deserialization via yaml.load()", "critical", "CWE-502", A08,
         "insecure-deserialization",
         "yaml.load() without SafeLoader constructs arbitrary Python objects.",
         "Use yaml.safe_load().", ["deser", "code"], arg_index=0, obj_hint="yaml")

    # Command injection
    for fn in ("system", "popen", "spawnl", "spawnv", "execl", "execv"):
        sink(f"py-cmdi-os-{fn}", fn, f"Command injection via os.{fn}()",
             "critical", "CWE-78", A03, "command-injection",
             f"os.{fn}() runs its argument through the shell.",
             "Use subprocess.run with an argument list and shell=False.",
             _CMD, arg_index=0, obj_hint="os")
    for fn in ("run", "call", "check_call", "check_output", "Popen",
               "getoutput", "getstatusoutput"):
        sink(f"py-cmdi-subprocess-{fn}", fn,
             f"Command injection via subprocess.{fn}()", "critical", "CWE-78",
             A03, "command-injection",
             "Attacker-controlled data reaches a subprocess invocation. With "
             "shell=True this is shell injection; otherwise it still controls "
             "which binary runs.",
             "Pass an argument list, keep shell=False, and validate the program.",
             _CMD, arg_index=0, obj_hint="subprocess")

    # SQL
    for fn in ("execute", "executemany", "executescript", "raw", "text"):
        sink(f"py-sqli-{fn}", fn, f"SQL injection via {fn}()", "high",
             "CWE-89", A03, "sql-injection",
             "Untrusted data is formatted into a SQL statement instead of being "
             "bound as a parameter.",
             "Use parameterised queries: cursor.execute(sql, (params,)).",
             _SQL, arg_index=0)
    sink("py-sqli-extra", "extra", "SQL injection via Django .extra()", "high",
         "CWE-89", A03, "sql-injection",
         "QuerySet.extra() interpolates raw SQL fragments.",
         "Use the ORM's filter expressions or RawSQL with params.",
         _SQL, frameworks=DJANGO)

    # Path traversal / file access
    for fn in ("open", "remove", "unlink", "rmdir", "makedirs", "rename"):
        sink(f"py-path-{fn}", fn, f"Path traversal via {fn}()", "high",
             "CWE-22", A01, "path-traversal",
             "An attacker-controlled path allows reading or writing files "
             "outside the intended directory.",
             "Resolve the path and verify it stays inside an allow-listed root.",
             _PATH, arg_index=0)
    sink("py-path-send-file", "send_file", "Path traversal via send_file()",
         "high", "CWE-22", A01, "path-traversal",
         "The file served is chosen by attacker-controlled input.",
         "Map the input through a fixed allow-list of filenames.",
         _PATH, arg_index=0, frameworks=FLASK)

    # SSRF
    for fn in ("get", "post", "put", "delete", "head", "patch", "request"):
        sink(f"py-ssrf-requests-{fn}", fn,
             f"Server-side request forgery via requests.{fn}()", "high",
             "CWE-918", A10, "ssrf",
             "The request target is attacker-controlled, so the server can be "
             "made to reach internal hosts or cloud metadata.",
             "Validate the URL against an allow-list and block internal ranges.",
             ["ssrf"], arg_index=0, obj_hint="requests")
    sink("py-ssrf-urlopen", "urlopen",
         "Server-side request forgery via urlopen()", "high", "CWE-918", A10,
         "ssrf", "The URL opened is attacker-controlled.",
         "Validate the URL against an allow-list of hosts.",
         ["ssrf"], arg_index=0)

    # Template injection / XSS
    for fn in ("Template", "from_string", "render_template_string"):
        sink(f"py-ssti-{fn.lower()}", fn,
             "Server-side template injection", "high", "CWE-1336", A03, "ssti",
             "A template compiled from attacker-controlled input generally "
             "yields code execution in Jinja2.",
             "Render a fixed template and pass data as variables.",
             ["ssti", "code"], arg_index=0)
    for fn in ("mark_safe", "format_html"):
        sink(f"py-xss-{fn}", fn, f"XSS via {fn}()", "high", "CWE-79", A03, "xss",
             f"{fn}() marks a string as trusted HTML, disabling autoescaping.",
             "Let the template engine escape the value.",
             ["xss"], arg_index=0, frameworks=DJANGO)
    sink("py-xss-httpresponse", "HttpResponse", "Reflected XSS via HttpResponse",
         "medium", "CWE-79", A03, "xss",
         "Untrusted data is written directly into an HTTP response body.",
         "Render through a template so it is escaped.",
         ["xss"], arg_index=0, frameworks=DJANGO, confidence="medium")

    # Redirect / LDAP / XML
    sink("py-redirect", "redirect", "Open redirect", "medium", "CWE-601", A01,
         "open-redirect",
         "The redirect target comes from attacker-controlled input.",
         "Redirect only to validated relative paths.",
         ["redirect"], arg_index=0)
    sink("py-xxe-parse", "parse", "XML external entity processing", "high",
         "CWE-611", A05, "xxe",
         "Parsing untrusted XML with a resolver that honours external entities "
         "exposes local files and internal services.",
         "Use defusedxml, or disable entity resolution.",
         ["xxe"], arg_index=0, obj_hint="etree", confidence="medium")
    return k


def _sanitizers() -> list[SanitizerRule]:
    s: list[SanitizerRule] = []
    for fn in ("escape", "quote", "escape_html"):
        s.append(SanitizerRule(kind="call", match=fn, neutralize=["xss"]))
    for fn in ("int", "float", "bool"):
        s.append(SanitizerRule(
            kind="call", match=fn,
            neutralize=["sql", "cmd", "xss", "ssrf", "lfi", "path", "code"]))
    s.append(SanitizerRule(kind="call", match="quote", neutralize=["cmd"],
                           cls="shlex"))
    s.append(SanitizerRule(kind="call", match="basename", neutralize=["path", "lfi"]))
    s.append(SanitizerRule(kind="call", match="safe_load", neutralize=["deser"]))
    # Escaping that does not do what it is often assumed to.
    s.append(SanitizerRule(
        kind="call", match="normpath", neutralize=["path"], weak=True,
        note="os.path.normpath() collapses '..' but does not confine a path to "
             "a root; resolve it and check the prefix"))
    s.append(SanitizerRule(
        kind="call", match="strip_tags", neutralize=["xss"], weak=True,
        note="stripping tags does not escape quotes; unsafe in an attribute context"))
    return s


def _patterns() -> list[PatternRule]:
    p: list[PatternRule] = []

    def pat(rid, match, title, desc, fix, severity="medium", cwe="", owasp=A05,
            category="security-misconfiguration", node_type="*",
            match_field="text", confidence="high", frameworks=("*",),
            ignore_case=False):
        p.append(PatternRule(
            rule_id=rid, node_type=node_type, match=match,
            match_field=match_field, title=title, severity=severity, cwe=cwe,
            owasp=owasp, category=category, description=desc, remediation=fix,
            frameworks=frameworks, regex=True, confidence=confidence,
            ignore_case=ignore_case))

    pat("py-weak-random", r"\brandom\.(?:random|randint|choice|randrange|shuffle)\s*\(",
        "Predictable random number generator",
        "The random module is not cryptographically secure; tokens derived from "
        "it are guessable.",
        "Use the secrets module for anything security-relevant.",
        cwe="CWE-338", owasp=A02, category="weak-random", node_type="call")
    pat("py-crypto-weak-hash", r"hashlib\.(?:md5|sha1)\s*\(",
        "Weak cryptographic hash (MD5/SHA-1)",
        "MD5 and SHA-1 are broken for signatures, integrity and passwords.",
        "Use SHA-256+ for integrity and bcrypt/scrypt/argon2 for passwords.",
        severity="low", cwe="CWE-328", owasp=A02, category="weak-crypto",
        node_type="call")
    pat("py-tls-verify-disabled", r"verify\s*=\s*False",
        "TLS certificate verification disabled",
        "requests with verify=False accepts any certificate, making the "
        "connection trivially interceptable.",
        "Leave verification enabled and fix the trust store.",
        severity="high", cwe="CWE-295", owasp=A02, category="insecure-transport")
    pat("py-shell-true", r"shell\s*=\s*True",
        "subprocess invoked with shell=True",
        "shell=True passes the command through a shell, turning any "
        "interpolated value into shell syntax.",
        "Pass an argument list and leave shell=False.",
        severity="medium", cwe="CWE-78", owasp=A03, category="command-injection",
        confidence="medium")
    pat("py-django-debug", r"DEBUG\s*=\s*True",
        "Django DEBUG enabled",
        "DEBUG renders stack traces, settings and SQL to anyone who triggers an "
        "error.",
        "Set DEBUG = False in deployed environments.",
        severity="high", cwe="CWE-489", owasp=A05, confidence="medium")
    pat("py-django-allowed-hosts", r"ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*[\"']\s*\]",
        "Django ALLOWED_HOSTS accepts any host",
        "A wildcard ALLOWED_HOSTS enables Host-header poisoning, which affects "
        "password-reset links and cache keys.",
        "List the hostnames the application actually serves.",
        severity="medium", cwe="CWE-16", owasp=A05, frameworks=DJANGO)
    pat("py-flask-debug", r"\.run\s*\([^)]*debug\s*=\s*True",
        "Flask debug mode enabled",
        "The Werkzeug debugger exposes an interactive console that executes "
        "arbitrary Python.",
        "Never run with debug=True outside local development.",
        severity="critical", cwe="CWE-489", owasp=A05, frameworks=FLASK)
    pat("py-assert-auth", r"^\s*assert\s+.*(?:is_admin|is_auth|permission|role)",
        "Security check implemented with assert",
        "assert statements are removed entirely when Python runs with -O, so "
        "the check silently disappears in optimised deployments.",
        "Use an explicit if/raise.",
        severity="high", cwe="CWE-617", owasp=A01, category="broken-access-control")
    return p


def build_python_rules() -> RuleSet:
    return RuleSet(sources=_sources(), sinks=_sinks(),
                   sanitizers=_sanitizers(), patterns=_patterns())
