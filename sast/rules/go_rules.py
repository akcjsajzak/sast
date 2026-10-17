"""Go rule set: net/http, Gin, Echo, Fiber, database/sql, os/exec."""
from __future__ import annotations

from .base import RuleSet, TaintSource, SinkRule, SanitizerRule, PatternRule

A01 = "A01:2021 — Broken Access Control"
A02 = "A02:2021 — Cryptographic Failures"
A03 = "A03:2021 — Injection"
A05 = "A05:2021 — Security Misconfiguration"
A07 = "A07:2021 — Identification and Authentication Failures"
A10 = "A10:2021 — Server-Side Request Forgery (SSRF)"

_ALL = ["sql", "cmd", "xss", "ssrf", "lfi", "path", "code", "ssti", "redirect",
        "log", "xxe", "nosql", "header"]


def _sources() -> list[TaintSource]:
    s: list[TaintSource] = []
    # net/http: r.URL.Query(), r.FormValue(...), r.Header.Get(...)
    for m in ("FormValue", "PostFormValue", "Query", "Cookie", "Referer",
              "UserAgent", "ParseForm", "ParseMultipartForm", "FormFile"):
        s.append(TaintSource(
            kind="call", match=m, tags=_ALL, obj_hint="r",
            description=f"Untrusted data from the HTTP request (r.{m}())",
        ))
    for m in ("Get",):
        s.append(TaintSource(
            kind="call", match=m, tags=_ALL, obj_hint="header",
            description="Untrusted data from a request header (Header.Get())",
        ))
    for prop in ("URL", "Form", "PostForm", "Body", "Host", "RequestURI",
                 "MultipartForm"):
        s.append(TaintSource(
            kind="member", match=prop, tags=_ALL, obj_hint="r",
            description=f"Untrusted data from the HTTP request (r.{prop})",
        ))
    # Gin / Echo / Fiber context accessors.
    for m in ("Param", "Query", "DefaultQuery", "PostForm", "GetHeader",
              "QueryParam", "FormValue", "Params", "Body", "BodyParser",
              "ShouldBind", "ShouldBindJSON", "BindJSON", "Bind"):
        s.append(TaintSource(
            kind="call", match=m, tags=_ALL, obj_hint="c",
            description=f"Untrusted data from the request context (c.{m}())",
        ))
    # CLI / environment.
    s.append(TaintSource(
        kind="member", match="Args", tags=_ALL, obj_hint="os",
        description="Untrusted data from command-line arguments (os.Args)",
    ))
    s.append(TaintSource(
        kind="call", match="Getenv", tags=_ALL, obj_hint="os", confidence="low",
        description="Environment data (os.Getenv) — attacker-controlled only if "
                    "the environment is",
    ))
    for m in ("ReadFile", "ReadAll", "Scan", "Text"):
        s.append(TaintSource(
            kind="call", match=m, tags=_ALL, confidence="low",
            description=f"Data read from an external file or stream via {m}()",
        ))
    return s


def _sinks() -> list[SinkRule]:
    k: list[SinkRule] = []

    def sink(rid, match, title, severity, cwe, owasp, category, desc, fix, tags,
             arg_index=-1, obj_hint=None, confidence="high"):
        k.append(SinkRule(rule_id=rid, kind="call", match=match, title=title,
                          severity=severity, cwe=cwe, owasp=owasp,
                          category=category, description=desc, remediation=fix,
                          tags=tags, arg_index=arg_index, obj_hint=obj_hint,
                          confidence=confidence))

    # Command injection — exec.Command("sh", "-c", userInput) is the common shape.
    for m in ("Command", "CommandContext"):
        sink(f"go-cmdi-{m.lower()}", m, f"Command injection via exec.{m}()",
             "critical", "CWE-78", A03, "command-injection",
             "Attacker-controlled data reaches an executed command. With a "
             "shell wrapper (sh -c) this is shell injection; otherwise it "
             "still controls which binary runs.",
             "Pass a fixed program with an argument slice and never invoke a shell.",
             ["cmd"], obj_hint="exec")

    # SQL
    for m in ("Query", "QueryRow", "Exec", "QueryContext", "QueryRowContext",
              "ExecContext", "Prepare", "Raw"):
        sink(f"go-sqli-{m.lower()}", m, f"SQL injection via {m}()", "high",
             "CWE-89", A03, "sql-injection",
             "Untrusted data is concatenated into a SQL statement rather than "
             "passed as a bound parameter.",
             "Use placeholders ($1 / ?) and pass values as arguments.",
             ["sql"], arg_index=0)

    # Path traversal
    # The same file operations live in both `os` and the older `io/ioutil`,
    # and obj_hint takes one substring, so each package needs its own rule —
    # hinting only on `os` meant `ioutil.WriteFile(userPath, ...)` was missed.
    for pkg in ("os", "ioutil"):
        for m in ("Open", "OpenFile", "ReadFile", "WriteFile", "Create",
                  "Remove", "RemoveAll", "Rename", "Mkdir", "MkdirAll",
                  "ReadDir", "TempFile"):
            # The os rules keep their original ids; renaming them would
            # invalidate anyone's existing suppressions.
            rid = (f"go-path-{m.lower()}" if pkg == "os"
                   else f"go-path-{pkg}-{m.lower()}")
            sink(rid, m,
                 f"Path traversal via {pkg}.{m}()", "high",
                 "CWE-22", A01, "path-traversal",
                 "An attacker-controlled path allows access outside the "
                 "intended directory.",
                 "Clean the path and verify it stays within an allow-listed "
                 "root.",
                 ["path", "lfi"], arg_index=0, obj_hint=pkg)
    for m in ("ServeFile", "Dir"):
        sink(f"go-path-{m.lower()}", m, f"Path traversal via http.{m}()", "high",
             "CWE-22", A01, "path-traversal",
             "The file served is chosen by attacker-controlled input.",
             "Map the input through a fixed allow-list, or use http.FileServer "
             "with a confined root.",
             ["path", "lfi"], confidence="medium")

    # SSRF
    for m in ("Get", "Post", "Head", "PostForm", "NewRequest", "Do"):
        sink(f"go-ssrf-{m.lower()}", m,
             f"Server-side request forgery via http.{m}()", "high", "CWE-918",
             A10, "ssrf",
             "The request target is attacker-controlled, so the server can be "
             "made to reach internal hosts or cloud metadata.",
             "Validate the URL against an allow-list and block internal ranges.",
             ["ssrf"], obj_hint="http", confidence="medium")

    # XSS / template injection
    for m in ("Write", "WriteString", "Fprintf", "Fprint", "Fprintln"):
        sink(f"go-xss-{m.lower()}", m,
             f"Reflected XSS via {m}() to the response", "medium", "CWE-79",
             A03, "xss",
             "Untrusted data is written straight to the HTTP response without "
             "contextual escaping.",
             "Render through html/template, which escapes by context.",
             ["xss"], obj_hint="w", confidence="medium")
    # The fmt family takes the writer as its first argument rather than as a
    # receiver, so a rule hinted on `w` never matched `fmt.Fprintf(w, ...)`.
    for m in ("Fprintf", "Fprint", "Fprintln"):
        sink(f"go-xss-fmt-{m.lower()}", m,
             f"Reflected XSS via fmt.{m}() to the response", "medium",
             "CWE-79", A03, "xss",
             "Untrusted data is formatted into the HTTP response without "
             "contextual escaping.",
             "Render through html/template, which escapes by context.",
             ["xss"], obj_hint="fmt", confidence="medium")
    # http.Header.Set/Add take a header value that is never escaped. A CR or
    # LF in it splits the response, and a tainted Location is an open redirect.
    for m in ("Set", "Add"):
        sink(f"go-header-{m.lower()}", m,
             f"HTTP response header injection via Header.{m}()", "high",
             "CWE-113", A03, "header-injection",
             "An attacker-controlled header value can carry CR/LF and inject "
             "further headers or a response body; a Location built this way "
             "is also an open redirect.",
             "Strip CR and LF from the value, and allow-list redirect targets.",
             ["header", "redirect", "xss"], arg_index=1, obj_hint="header",
             confidence="medium")
    sink("go-ssti-parse", "Parse", "Server-side template injection", "high",
         "CWE-1336", A03, "ssti",
         "A template parsed from attacker-controlled input can execute "
         "arbitrary template actions.",
         "Parse fixed templates and pass data as arguments.",
         ["ssti"], arg_index=0, confidence="medium")

    # Redirect
    sink("go-redirect", "Redirect", "Open redirect", "medium", "CWE-601", A01,
         "open-redirect",
         "The redirect target comes from attacker-controlled input.",
         "Redirect only to validated relative paths.",
         ["redirect"])
    return k


def _sanitizers() -> list[SanitizerRule]:
    s: list[SanitizerRule] = []
    for m in ("EscapeString", "HTMLEscapeString", "HTMLEscape", "JSEscapeString"):
        s.append(SanitizerRule(kind="call", match=m, neutralize=["xss"]))
    s.append(SanitizerRule(kind="call", match="QueryEscape", neutralize=["redirect"]))
    s.append(SanitizerRule(kind="call", match="PathEscape", neutralize=["redirect"]))
    for m in ("Atoi", "ParseInt", "ParseFloat", "ParseBool"):
        s.append(SanitizerRule(
            kind="call", match=m,
            neutralize=["sql", "cmd", "xss", "ssrf", "lfi", "path", "code"]))
    s.append(SanitizerRule(kind="call", match="Base", neutralize=["path", "lfi"]))
    s.append(SanitizerRule(
        kind="call", match="Clean", neutralize=["path"], weak=True,
        note="filepath.Clean() collapses '..' but does not confine a path to a "
             "root; join it to the root and verify the prefix"))
    return s


def _patterns() -> list[PatternRule]:
    p: list[PatternRule] = []

    def pat(rid, match, title, desc, fix, severity="medium", cwe="", owasp=A05,
            category="security-misconfiguration", node_type="*",
            confidence="high", ignore_case=False):
        p.append(PatternRule(
            rule_id=rid, node_type=node_type, match=match, match_field="text",
            title=title, severity=severity, cwe=cwe, owasp=owasp,
            category=category, description=desc, remediation=fix, regex=True,
            confidence=confidence, ignore_case=ignore_case))

    pat("go-tls-skip-verify", r"InsecureSkipVerify\s*:\s*true",
        "TLS certificate verification disabled",
        "InsecureSkipVerify accepts any certificate, making the connection "
        "trivially machine-in-the-middle-able.",
        "Leave verification on and configure the correct root CAs.",
        severity="high", cwe="CWE-295", owasp=A02, category="insecure-transport")
    pat("go-weak-random", r"\bmath/rand\b|\brand\.(?:Intn|Int|Float64|Perm)\s*\(",
        "Predictable random number generator",
        "math/rand is not cryptographically secure; tokens derived from it are "
        "guessable.",
        "Use crypto/rand.",
        cwe="CWE-338", owasp=A02, category="weak-random")
    pat("go-weak-hash", r"\b(?:md5|sha1)\.(?:New|Sum)\s*\(",
        "Weak cryptographic hash (MD5/SHA-1)",
        "MD5 and SHA-1 are broken for signatures and integrity.",
        "Use SHA-256 or better, and bcrypt/argon2 for passwords.",
        severity="low", cwe="CWE-328", owasp=A02, category="weak-crypto")
    pat("go-text-template-html", r"text/template",
        "text/template used to render HTML",
        "text/template performs no contextual escaping; rendering untrusted "
        "data through it into HTML is XSS.",
        "Use html/template for anything rendered into a page.",
        cwe="CWE-79", owasp=A03, category="xss", confidence="medium")
    pat("go-unhandled-error", r"_\s*,\s*_\s*(?::=|=)\s*",
        "Multiple return values discarded",
        "Discarding an error return hides failures, including failed "
        "authorisation and validation checks.",
        "Handle the error, or state explicitly why it is safe to ignore.",
        severity="info", cwe="CWE-391", owasp=A05, category="error-handling",
        confidence="low")
    return p


def build_go_rules() -> RuleSet:
    return RuleSet(sources=_sources(), sinks=_sinks(),
                   sanitizers=_sanitizers(), patterns=_patterns())
