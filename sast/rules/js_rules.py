"""JavaScript/TypeScript rule set: raw JS, Node, Express, React and Angular.

Rule `kind` values used by the JS engine:
  source  'member' (property read)  | 'call'
  sink    'call' | 'property_assign' | 'jsx_attribute'
  sanitizer 'call'
"""
from __future__ import annotations

from .base import RuleSet, TaintSource, SinkRule, SanitizerRule, PatternRule

A01 = "A01:2021 — Broken Access Control"
A02 = "A02:2021 — Cryptographic Failures"
A03 = "A03:2021 — Injection"
A05 = "A05:2021 — Security Misconfiguration"
A07 = "A07:2021 — Identification and Authentication Failures"
A08 = "A08:2021 — Software and Data Integrity Failures"
A10 = "A10:2021 — Server-Side Request Forgery (SSRF)"

_ALL = ["sql", "xss", "cmd", "ssrf", "lfi", "path", "deser", "redirect",
        "code", "log", "ssti", "nosql", "proto", "redos", "xxe", "open"]

_XSS = ["xss"]
_CMD = ["cmd"]
_SQL = ["sql"]
_NOSQL = ["nosql", "sql"]
_SSRF = ["ssrf"]
_PATH = ["path", "lfi"]
_CODE = ["code"]
_REDIR = ["redirect"]
_PROTO = ["proto"]

NODE = ("Node.js", "Express", "NestJS")
EXPRESS = ("Express", "NestJS")
REACT = ("React", "Next.js")
ANGULAR = ("Angular",)


# ---------------------------------------------------------------------------
def _sources() -> list[TaintSource]:
    s: list[TaintSource] = []

    # --- Server-side request data (Express / Node / NestJS) ---
    for prop in ("query", "body", "params", "headers", "cookies", "rawHeaders",
                 "originalUrl", "url", "path", "hostname", "signedCookies"):
        s.append(TaintSource(
            kind="member", match=prop, tags=_ALL, obj_hint="req",
            description=f"Untrusted data from the HTTP request (req.{prop})",
        ))
    for prop in ("query", "body", "params", "headers", "cookies"):
        s.append(TaintSource(
            kind="member", match=prop, tags=_ALL, obj_hint="request",
            description=f"Untrusted data from the HTTP request (request.{prop})",
        ))
    for m in ("param", "get", "header"):
        s.append(TaintSource(
            kind="call", match=m, tags=_ALL, obj_hint="req",
            description=f"Untrusted data from the HTTP request (req.{m}())",
        ))

    # --- Browser / DOM sources (raw JS, React, Angular) ---
    for prop in ("href", "search", "hash", "pathname", "host", "hostname"):
        s.append(TaintSource(
            kind="member", match=prop, tags=_ALL, obj_hint="location",
            description=f"Attacker-controllable URL data (location.{prop})",
        ))
    for prop in ("URL", "documentURI", "referrer", "baseURI", "cookie"):
        s.append(TaintSource(
            kind="member", match=prop, tags=_ALL, obj_hint="document",
            description=f"Attacker-controllable browser data (document.{prop})",
        ))
    s.append(TaintSource(
        kind="member", match="name", tags=_ALL, obj_hint="window",
        description="Attacker-controllable window.name",
    ))
    s.append(TaintSource(
        kind="member", match="data", tags=_ALL, obj_hint="event",
        description="Untrusted data from a postMessage event (event.data)",
    ))
    s.append(TaintSource(
        kind="member", match="value", tags=_ALL, obj_hint="target",
        description="User-entered value from a DOM element (target.value)",
    ))
    for m in ("getItem",):
        s.append(TaintSource(
            kind="call", match=m, tags=_ALL, obj_hint="storage", confidence="low",
            description="Data read back from web storage (second-order: tainted "
                        "if attacker-controlled input was stored)",
        ))

    # --- Angular ---
    for m in ("snapshot", "queryParams", "params", "fragment"):
        s.append(TaintSource(
            kind="member", match=m, tags=_ALL, obj_hint="route", frameworks=ANGULAR,
            description=f"Untrusted data from the Angular route ({m})",
        ))

    # --- React ---
    for m in ("search", "state"):
        s.append(TaintSource(
            kind="member", match=m, tags=_ALL, obj_hint="location", frameworks=REACT,
            description=f"Untrusted data from the React router location.{m}",
        ))
    s.append(TaintSource(
        kind="member", match="params", tags=_ALL, obj_hint="match", frameworks=REACT,
        description="Untrusted data from React router match.params",
    ))

    # --- Node process / environment, second order ---
    s.append(TaintSource(
        kind="member", match="argv", tags=_ALL, obj_hint="process",
        description="Untrusted data from process arguments (process.argv)",
    ))
    s.append(TaintSource(
        kind="member", match="env", tags=_ALL, obj_hint="process", confidence="low",
        description="Environment data (process.env) — attacker-controlled only "
                    "if the environment is",
    ))
    for m in ("readFile", "readFileSync", "read", "createReadStream"):
        s.append(TaintSource(
            kind="call", match=m, tags=_ALL, obj_hint="fs", confidence="low",
            description=f"Data read from an external file via fs.{m}() "
                        "(trusted only if the file is)",
        ))
    return s


# ---------------------------------------------------------------------------
def _sinks() -> list[SinkRule]:
    k: list[SinkRule] = []

    def sink(rule_id, kind, match, title, severity, cwe, owasp, category,
             description, remediation, tags, arg_index=-1, obj_hint=None,
             frameworks=("*",), confidence="high"):
        k.append(SinkRule(
            rule_id=rule_id, kind=kind, match=match, title=title,
            severity=severity, cwe=cwe, owasp=owasp, category=category,
            description=description, remediation=remediation, tags=tags,
            arg_index=arg_index, obj_hint=obj_hint, frameworks=frameworks,
            confidence=confidence,
        ))

    # --- Code injection ---
    for fn in ("eval", "Function", "execScript"):
        sink(f"js-code-{fn.lower()}", "call", fn,
             f"Code injection via {fn}()", "critical", "CWE-95", A03,
             "code-injection",
             f"{fn}() executes its argument as JavaScript. With attacker-controlled "
             "input this is arbitrary code execution.",
             "Remove the dynamic evaluation and use explicit, whitelisted logic.",
             _CODE + _ALL[:0] + ["code", "xss"])
    for m in ("runInThisContext", "runInNewContext", "runInContext", "compileFunction"):
        sink(f"js-code-vm-{m.lower()}", "call", m,
             f"Code injection via vm.{m}()", "critical", "CWE-95", A03,
             "code-injection",
             "The Node vm module compiles and runs its argument as code. The vm "
             "module is not a security boundary.",
             "Do not evaluate untrusted input; redesign to avoid dynamic code.",
             ["code"], obj_hint="vm")
    for fn in ("setTimeout", "setInterval"):
        sink(f"js-code-{fn.lower()}", "call", fn,
             f"Code injection via {fn}() with a string argument",
             "high", "CWE-95", A03, "code-injection",
             f"{fn}() evaluates a string argument as code.",
             "Pass a function reference instead of a string.",
             ["code"], arg_index=0, confidence="medium")

    # --- Command injection (Node) ---
    for m in ("exec", "execSync"):
        sink(f"js-cmdi-{m.lower()}", "call", m,
             f"Command injection via child_process.{m}()",
             "critical", "CWE-78", A03, "command-injection",
             f"child_process.{m}() runs its argument through a shell, so "
             "attacker-controlled input becomes shell syntax.",
             "Use execFile/spawn with an argument array and no shell.",
             _CMD, arg_index=0)
    for m in ("spawn", "spawnSync", "execFile", "execFileSync", "fork"):
        sink(f"js-cmdi-{m.lower()}", "call", m,
             f"Command injection via child_process.{m}()",
             "high", "CWE-78", A03, "command-injection",
             f"The executable name passed to {m}() is attacker-controlled.",
             "Validate the command against an allow-list; never let input choose "
             "the binary, and keep shell:false.",
             _CMD, arg_index=0, confidence="medium")

    # --- SQL / NoSQL injection ---
    for m in ("query", "execute", "raw", "unsafe"):
        sink(f"js-sqli-{m}", "call", m,
             f"SQL injection via {m}()", "high", "CWE-89", A03, "sql-injection",
             "Untrusted data is concatenated into a SQL statement instead of being "
             "passed as a bound parameter.",
             "Use parameterised queries ($1 / ? placeholders) or the query builder.",
             _SQL, arg_index=0)
    for m in ("$where", "where", "find", "findOne", "updateOne", "deleteOne"):
        sink(f"js-nosqli-{m.replace('$','')}", "call", m,
             f"NoSQL injection via {m}()", "high", "CWE-943", A03, "nosql-injection",
             "A query object built from request data lets an attacker inject "
             "operators such as $ne, $gt or $where.",
             "Cast values to the expected primitive type and reject keys starting "
             "with '$'.",
             ["nosql"], arg_index=0, confidence="medium")

    # --- XSS: DOM sinks ---
    for prop in ("innerHTML", "outerHTML"):
        sink(f"js-xss-{prop.lower()}", "property_assign", prop,
             f"DOM XSS via .{prop}", "high", "CWE-79", A03, "xss",
             f"Assigning attacker-controlled data to .{prop} parses it as HTML and "
             "executes any script it contains.",
             "Use .textContent, or sanitize with DOMPurify before assigning.",
             _XSS)
    sink("js-xss-document-write", "call", "write",
         "DOM XSS via document.write()", "high", "CWE-79", A03, "xss",
         "document.write() parses its argument as HTML.",
         "Build nodes with createElement/textContent instead.",
         _XSS, obj_hint="document")
    sink("js-xss-insert-adjacent", "call", "insertAdjacentHTML",
         "DOM XSS via insertAdjacentHTML()", "high", "CWE-79", A03, "xss",
         "insertAdjacentHTML() parses its argument as HTML.",
         "Use insertAdjacentText, or sanitize first.",
         _XSS, arg_index=1)
    sink("js-xss-jquery-html", "call", "html",
         "DOM XSS via jQuery .html()", "high", "CWE-79", A03, "xss",
         "jQuery .html() parses its argument as HTML and runs embedded scripts.",
         "Use .text(), or sanitize with DOMPurify.",
         _XSS, confidence="medium")
    sink("js-xss-location-assign", "property_assign", "href",
         "Open redirect / javascript: URL via location.href",
         "medium", "CWE-601", A01, "open-redirect",
         "Assigning attacker-controlled data to location.href allows redirection "
         "to an arbitrary origin, or a javascript: URL.",
         "Validate the target against an allow-list of paths or origins.",
         _REDIR + _XSS, obj_hint="location")

    # --- XSS: framework sinks ---
    sink("react-xss-dangerously-set-inner-html", "jsx_attribute",
         "dangerouslySetInnerHTML",
         "React XSS via dangerouslySetInnerHTML", "high", "CWE-79", A03, "xss",
         "dangerouslySetInnerHTML bypasses React's escaping and injects raw HTML.",
         "Render the value as a child so React escapes it, or sanitize with "
         "DOMPurify first.",
         _XSS, frameworks=REACT)
    sink("react-xss-href-injection", "jsx_attribute", "href",
         "React URL injection via href", "medium", "CWE-601", A01, "open-redirect",
         "An attacker-controlled href can be a javascript: URL (script execution) "
         "or an arbitrary external origin.",
         "Validate the scheme against http/https and the origin against an allow-list.",
         _REDIR, frameworks=REACT, confidence="medium")
    for m in ("bypassSecurityTrustHtml", "bypassSecurityTrustScript",
              "bypassSecurityTrustStyle", "bypassSecurityTrustUrl",
              "bypassSecurityTrustResourceUrl"):
        sink(f"angular-xss-{m.lower()}", "call", m,
             f"Angular sanitizer bypassed via {m}()", "high", "CWE-79", A03, "xss",
             f"{m}() tells Angular to trust the value verbatim, disabling the "
             "built-in sanitizer for it.",
             "Let Angular sanitize the value; only bypass for constants you control.",
             _XSS, arg_index=0, frameworks=ANGULAR)
    sink("angular-xss-inner-html", "property_assign", "innerHTML",
         "Angular XSS via innerHTML binding", "high", "CWE-79", A03, "xss",
         "Binding attacker data to innerHTML renders it as markup.",
         "Use interpolation, which Angular escapes.",
         _XSS, frameworks=ANGULAR)

    # --- SSRF ---
    for fn in ("fetch", "request", "get", "post", "put", "patch", "head"):
        sink(f"js-ssrf-{fn}", "call", fn,
             f"Server-side request forgery via {fn}()", "high", "CWE-918", A10,
             "ssrf",
             "The request target is attacker-controlled, so the server can be made "
             "to reach internal hosts or cloud metadata endpoints.",
             "Validate the URL against an allow-list of hosts and block internal ranges.",
             _SSRF, arg_index=0, confidence="medium")

    # --- Path traversal / file access ---
    for m in ("readFile", "readFileSync", "writeFile", "writeFileSync",
              "appendFile", "appendFileSync", "unlink", "unlinkSync",
              "createReadStream", "createWriteStream", "open", "openSync",
              "rename", "renameSync", "rmdir", "readdir", "readdirSync"):
        sink(f"js-path-{m.lower()}", "call", m,
             f"Path traversal via fs.{m}()", "high", "CWE-22", A01, "path-traversal",
             "An attacker-controlled path lets files outside the intended directory "
             "be read or written.",
             "Resolve the path and verify it stays within an allow-listed root.",
             _PATH, arg_index=0, obj_hint="fs")
    for m in ("sendFile", "download"):
        sink(f"js-path-{m.lower()}", "call", m,
             f"Path traversal via res.{m}()", "high", "CWE-22", A01, "path-traversal",
             "The file served is chosen by attacker-controlled input.",
             "Map the input through a fixed allow-list of filenames.",
             _PATH, arg_index=0, obj_hint="res")

    # --- Open redirect ---
    sink("js-redirect-res", "call", "redirect",
         "Open redirect via res.redirect()", "medium", "CWE-601", A01,
         "open-redirect",
         "The redirect target comes from attacker-controlled input, enabling "
         "phishing against your origin.",
         "Redirect only to validated relative paths or an allow-listed origin.",
         _REDIR, arg_index=-1, frameworks=EXPRESS)

    # --- Deserialization / prototype pollution ---
    sink("js-deser-unserialize", "call", "unserialize",
         "Insecure deserialization", "critical", "CWE-502", A08,
         "insecure-deserialization",
         "node-serialize style unserialize() evaluates embedded functions, giving "
         "remote code execution.",
         "Use JSON.parse for data interchange.",
         ["deser", "code"], arg_index=0)
    for m in ("merge", "mergeWith", "defaultsDeep", "set", "setWith"):
        sink(f"js-proto-{m.lower()}", "call", m,
             f"Prototype pollution via {m}()", "high", "CWE-1321", A08,
             "prototype-pollution",
             "Deep-merging attacker-controlled data can set __proto__ or "
             "constructor.prototype, changing behaviour application-wide.",
             "Use a merge that rejects __proto__/constructor keys, or validate the "
             "object's shape first.",
             _PROTO + ["nosql"], confidence="medium")

    # --- Template injection / dynamic require ---
    sink("js-ssti-template", "call", "compile",
         "Server-side template injection", "high", "CWE-1336", A03, "ssti",
         "A template is compiled from attacker-controlled input, which generally "
         "yields code execution.",
         "Compile fixed templates and pass data as variables.",
         ["ssti", "code"], arg_index=0, confidence="medium")
    sink("js-code-dynamic-require", "call", "require",
         "Dynamic require() of an attacker-controlled path",
         "high", "CWE-98", A03, "file-inclusion",
         "require() with attacker-controlled input can load arbitrary files from "
         "disk and execute them.",
         "Require a fixed set of modules chosen by an allow-list.",
         ["lfi", "code", "path"], arg_index=0)
    return k


# ---------------------------------------------------------------------------
def _sanitizers() -> list[SanitizerRule]:
    s: list[SanitizerRule] = []
    # DOMPurify and friends genuinely neutralise XSS.
    for m in ("sanitize", "purify"):
        s.append(SanitizerRule(kind="call", match=m, neutralize=["xss"]))
    s.append(SanitizerRule(kind="call", match="escape", neutralize=["xss"],
                           cls="validator"))
    s.append(SanitizerRule(kind="call", match="escapeHtml", neutralize=["xss"]))
    # Numeric coercion removes string-injection payloads.
    for m in ("parseInt", "parseFloat", "Number"):
        s.append(SanitizerRule(
            kind="call", match=m,
            neutralize=["sql", "cmd", "xss", "ssrf", "lfi", "path", "code",
                        "nosql", "redirect"],
        ))
    # path.basename() strips directory traversal but nothing else.
    s.append(SanitizerRule(kind="call", match="basename", neutralize=["path", "lfi"]))
    s.append(SanitizerRule(kind="call", match="encodeURIComponent",
                           neutralize=["redirect"]))
    # Escaping that is commonly assumed to be enough but is not.
    s.append(SanitizerRule(
        kind="call", match="escape", neutralize=["xss"], weak=True,
        note="escape() is a URL encoder, not an HTML escaper; it does not prevent XSS",
    ))
    s.append(SanitizerRule(
        kind="call", match="stripTags", neutralize=["xss"], weak=True,
        note="stripping tags does not escape quotes; unsafe in an attribute context",
    ))
    s.append(SanitizerRule(
        kind="call", match="normalize", neutralize=["path"], weak=True,
        note="path.normalize() does not confine a path to a root directory; "
             "resolve it and check the prefix",
    ))
    return s


# ---------------------------------------------------------------------------
def _patterns() -> list[PatternRule]:
    p: list[PatternRule] = []

    def pat(rule_id, match, title, description, remediation, severity="medium",
            cwe="", owasp=A05, category="security-misconfiguration",
            node_type="*", match_field="text", regex=True, frameworks=("*",),
            confidence="high", ignore_case=False):
        p.append(PatternRule(
            rule_id=rule_id, node_type=node_type, match=match,
            match_field=match_field, title=title, severity=severity, cwe=cwe,
            owasp=owasp, category=category, description=description,
            remediation=remediation, frameworks=frameworks, regex=regex,
            confidence=confidence, ignore_case=ignore_case,
        ))

    pat("js-weak-random", r"\bMath\.random\s*\(", "Predictable random number generator",
        "Math.random() is not cryptographically secure; tokens, session IDs and "
        "password-reset values derived from it are guessable.",
        "Use crypto.randomUUID() or crypto.getRandomValues()/randomBytes().",
        cwe="CWE-338", owasp=A02, category="weak-random",
        node_type="call_expression")
    pat("js-crypto-weak-hash", r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]",
        "Weak cryptographic hash (MD5/SHA-1)",
        "MD5 and SHA-1 are broken for signatures, integrity and password storage.",
        "Use SHA-256+ for integrity and bcrypt/scrypt/argon2 for passwords.",
        severity="low", cwe="CWE-328", owasp=A02, category="weak-crypto",
        node_type="call_expression")
    pat("js-crypto-ecb", r"createCipheriv?\s*\(\s*['\"][a-z0-9-]*ecb",
        "Insecure cipher mode (ECB)",
        "ECB maps identical plaintext blocks to identical ciphertext blocks, "
        "leaking plaintext structure.",
        "Use an authenticated mode such as AES-GCM.",
        cwe="CWE-327", owasp=A02, category="weak-crypto",
        node_type="call_expression")
    pat("js-tls-verify-disabled",
        r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*\]?\s*=\s*['\"]?0",
        "TLS certificate verification disabled",
        "Disabling certificate verification accepts any certificate, making the "
        "connection trivially interceptable.",
        "Leave verification enabled and fix the trust store instead.",
        severity="high", cwe="CWE-295", owasp=A02, category="insecure-transport")
    pat("js-cors-wildcard",
        r"origin\s*:\s*(?:['\"]\*['\"]|true)|Access-Control-Allow-Origin['\"]\s*,\s*['\"]\*",
        "Permissive CORS policy",
        "Allowing any origin lets third-party sites read authenticated responses; "
        "with credentials enabled this is a cross-origin data leak.",
        "Reflect only an allow-list of trusted origins.",
        severity="medium", cwe="CWE-942", owasp=A05, category="cors-misconfiguration",
        confidence="medium")
    pat("js-cookie-insecure",
        r"(?:secure\s*:\s*false|httpOnly\s*:\s*false)",
        "Cookie without Secure/HttpOnly",
        "The cookie is sent over plaintext HTTP or is readable from JavaScript, "
        "making session theft easier.",
        "Set secure:true, httpOnly:true and sameSite.",
        cwe="CWE-1004", category="security-misconfiguration", ignore_case=True)
    pat("js-jwt-none-algorithm",
        r"algorithms?\s*:\s*\[?\s*['\"]none['\"]",
        "JWT 'none' algorithm accepted",
        "Accepting alg:none means an attacker can forge any token by stripping "
        "the signature.",
        "Pin the expected algorithm (e.g. RS256) when verifying.",
        severity="critical", cwe="CWE-347", owasp=A07, category="broken-authentication")
    pat("js-jwt-verify-disabled",
        r"ignoreExpiration\s*:\s*true|verify\s*:\s*false",
        "JWT validation weakened",
        "Expiry or signature validation is disabled, so expired or forged tokens "
        "are accepted.",
        "Validate signature and expiry on every request.",
        severity="high", cwe="CWE-347", owasp=A07, category="broken-authentication")
    pat("js-express-no-helmet", r"\bexpress\s*\(\s*\)",
        "Express app without security headers",
        "No helmet() middleware was detected on this app, so responses ship "
        "without HSTS, X-Content-Type-Options, frame protections or a CSP.",
        "Add app.use(helmet()) early in the middleware chain.",
        severity="info", cwe="CWE-693", owasp=A05,
        category="security-misconfiguration", frameworks=EXPRESS,
        confidence="low", node_type="call_expression")
    pat("angular-xss-bypass-import", r"DomSanitizer",
        "Angular DomSanitizer in use",
        "DomSanitizer exists to bypass Angular's escaping. Every bypassSecurityTrust* "
        "call it enables needs review.",
        "Prefer letting Angular sanitize; review each bypass for attacker-controlled input.",
        severity="info", cwe="CWE-79", owasp=A03, category="xss",
        frameworks=ANGULAR, confidence="low", node_type="import_statement")
    return p


def build_js_rules() -> RuleSet:
    return RuleSet(
        sources=_sources(),
        sinks=_sinks(),
        sanitizers=_sanitizers(),
        patterns=_patterns(),
    )
