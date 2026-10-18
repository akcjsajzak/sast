"""C# rule set: ASP.NET Core/MVC, ADO.NET, Entity Framework."""
from __future__ import annotations

from .base import RuleSet, TaintSource, SinkRule, SanitizerRule, PatternRule

A01 = "A01:2021 — Broken Access Control"
A02 = "A02:2021 — Cryptographic Failures"
A03 = "A03:2021 — Injection"
A05 = "A05:2021 — Security Misconfiguration"
A07 = "A07:2021 — Identification and Authentication Failures"
A08 = "A08:2021 — Software and Data Integrity Failures"
A10 = "A10:2021 — Server-Side Request Forgery (SSRF)"

_ALL = ["sql", "cmd", "xss", "ssrf", "lfi", "path", "deser", "code", "ldap",
        "redirect", "log", "xxe", "xpath", "ssti"]

ASPNET = ("ASP.NET", "ASP.NET Core")


def _sources() -> list[TaintSource]:
    s: list[TaintSource] = []
    for prop in ("Query", "Form", "QueryString", "Headers", "Cookies", "Body",
                 "Params", "RouteValues", "InputStream", "Url", "UserAgent",
                 "UrlReferrer", "RawUrl", "Path", "ContentType"):
        s.append(TaintSource(
            kind="member", match=prop, tags=_ALL, obj_hint="request",
            description=f"Untrusted data from the HTTP request (Request.{prop})",
        ))
    for m in ("ReadAsStringAsync", "ReadFromJsonAsync", "ReadAsync"):
        s.append(TaintSource(
            kind="call", match=m, tags=_ALL, obj_hint="request",
            description=f"Untrusted data from the HTTP request body ({m}())",
        ))
    # Classic ASP.NET reads a parameter straight off the request object:
    # `Request["city"]`, which has no member name at all — it is an indexer.
    # Without the request itself as a source, that whole form was invisible,
    # and it is the shape most WebForms code uses.
    for kind in ("identifier", "member"):
        s.append(TaintSource(
            kind=kind, match="Request", tags=_ALL,
            description="Untrusted data from the HTTP request object",
        ))
    s.append(TaintSource(
        kind="member", match="Value", tags=_ALL, obj_hint="routedata",
        description="Untrusted data from a route value",
    ))
    # CLI / environment / second-order.
    s.append(TaintSource(
        kind="call", match="GetEnvironmentVariable", tags=_ALL,
        obj_hint="environment", confidence="low",
        description="Environment data — attacker-controlled only if the "
                    "environment is",
    ))
    for m in ("ReadAllText", "ReadLine", "ReadToEnd", "ReadAllLines"):
        s.append(TaintSource(
            kind="call", match=m, tags=_ALL, confidence="low",
            description=f"Data read from an external file or stream via {m}()",
        ))
    for m in ("GetString", "GetValue"):
        s.append(TaintSource(
            kind="call", match=m, tags=_ALL, obj_hint="reader", confidence="low",
            description=f"Column read back from the database via {m}() "
                        "(second-order: tainted if attacker data was stored)",
        ))
    return s


def _sinks() -> list[SinkRule]:
    k: list[SinkRule] = []

    def sink(rid, match, title, severity, cwe, owasp, category, desc, fix, tags,
             arg_index=-1, obj_hint=None, confidence="high", kind="call",
             receiver_tainted=False, safe_args=None):
        k.append(SinkRule(rule_id=rid, kind=kind, match=match, title=title,
                          severity=severity, cwe=cwe, owasp=owasp,
                          category=category, description=desc, remediation=fix,
                          tags=tags, arg_index=arg_index, obj_hint=obj_hint,
                          confidence=confidence,
                          receiver_tainted=receiver_tainted,
                          safe_args=safe_args))

    # SQL
    # FromSql/ExecuteSqlCommand are EF Core 2's names. Given a string they
    # run it raw; given an interpolated string literal written in the call
    # they bind the holes as parameters, so the literal form is excluded
    # by argument shape.
    for m in ("ExecuteReader", "ExecuteNonQuery", "ExecuteScalar",
              "ExecuteSqlRaw", "ExecuteSqlRawAsync", "FromSqlRaw", "SqlQuery",
              "ExecuteSqlCommand", "FromSql", "ExecuteSqlCommandAsync"):
        sink(f"cs-sqli-{m.lower()}", m, f"SQL injection via {m}()", "high",
             "CWE-89", A03, "sql-injection",
             "Untrusted data is concatenated into a SQL statement rather than "
             "passed as a parameter.",
             "Use SqlParameter / FromSqlInterpolated with bound values.",
             ["sql"], arg_index=0,
             safe_args=r'^(?:\$@?|@\$)"' if m in ("FromSql", "ExecuteSqlCommand",
                                                 "ExecuteSqlCommandAsync") else None)
    # Every ADO.NET provider ships its own command and adapter class, and the
    # name is the only thing that differs. Matching `SqlCommand` alone meant a
    # MySQL or Postgres application — WebGoat.NET included — had none of its
    # SQL sinks recognised.
    # Both SQLite spellings are real: System.Data.SQLite has SQLiteCommand
    # and Microsoft.Data.Sqlite has SqliteCommand. Each needs matching, but
    # they lowercase to one id, so the id is disambiguated rather than one of
    # the classes being dropped.
    seen_ids: set = set()
    for prefix in ("Sql", "MySql", "Npgsql", "SQLite", "Sqlite", "Oracle",
                   "OleDb", "Odbc", "Db", "Firebird", "Fb"):
        for suffix in ("Command", "DataAdapter"):
            cls = prefix + suffix
            rule_id = f"cs-sqli-{cls.lower()}"
            if rule_id in seen_ids:
                rule_id = f"cs-sqli-{prefix}{suffix}".lower() + "-alt"
            seen_ids.add(rule_id)
            sink(rule_id, cls,
                 f"SQL injection via {cls}", "high", "CWE-89", A03,
                 "sql-injection",
                 "The command text is built from untrusted data.",
                 "Use parameterised commands with a provider parameter type.",
                 ["sql"], arg_index=0)
    for helper in ("ExecuteDataset", "ExecuteDataRow", "ExecuteReader",
                   "ExecuteNonQuery", "ExecuteScalar"):
        sink(f"cs-sqli-helper-{helper.lower()}", helper,
             f"SQL injection via a SQL helper ({helper}())", "high", "CWE-89",
             A03, "sql-injection",
             "The statement passed to the helper is built from untrusted data.",
             "Use parameterised commands with bound values.",
             ["sql"], obj_hint="helper")

    # Command injection
    for m in ("Start",):
        sink("cs-cmdi-process-start", m, "Command injection via Process.Start()",
             "critical", "CWE-78", A03, "command-injection",
             "Attacker-controlled data reaches a process invocation; with "
             "UseShellExecute or cmd /c this is shell injection.",
             "Pass a fixed FileName with an argument list, and keep "
             "UseShellExecute false.",
             ["cmd"], obj_hint="process")
    # `p.StartInfo.FileName = input; p.Start()`: the command is set as a
    # property, so the Start() call itself carries no tainted argument.
    for prop in ("FileName", "Arguments"):
        sink(f"cs-cmdi-startinfo-{prop.lower()}", prop,
             f"Command injection via ProcessStartInfo.{prop}",
             "critical", "CWE-78", A03, "command-injection",
             f"The process {prop.lower()} is set from attacker-controlled data, "
             "so the attacker chooses what runs or the arguments it gets.",
             "Run a fixed executable and validate each argument against an "
             "allow-list; keep UseShellExecute false.",
             ["cmd"], kind="property_assign", obj_hint="startinfo")

    # Deserialization
    for m in ("Deserialize", "BinaryFormatter", "ReadObject", "FromJson"):
        sink(f"cs-deser-{m.lower()}", m, f"Insecure deserialization via {m}()",
             "critical", "CWE-502", A08, "insecure-deserialization",
             "Deserializing untrusted data with a type-permissive formatter "
             "(BinaryFormatter, TypeNameHandling.All) allows gadget chains to "
             "execute code.",
             "Use System.Text.Json with a fixed type and no polymorphic "
             "type handling.",
             ["deser", "code"], arg_index=0, confidence="medium")

    # Path traversal
    for m in ("ReadAllText", "ReadAllBytes", "WriteAllText", "WriteAllBytes",
              "Open", "OpenRead", "OpenWrite", "Delete", "Copy", "Move",
              "AppendAllText"):
        sink(f"cs-path-{m.lower()}", m, f"Path traversal via File.{m}()", "high",
             "CWE-22", A01, "path-traversal",
             "An attacker-controlled path allows access outside the intended "
             "directory.",
             "Resolve the path and verify it stays within an allow-listed root.",
             ["path", "lfi"], arg_index=0, obj_hint="file")
    sink("cs-path-physicalfile", "PhysicalFile",
         "Path traversal via PhysicalFile()", "high", "CWE-22", A01,
         "path-traversal",
         "The file served is chosen by attacker-controlled input.",
         "Map the input through a fixed allow-list of filenames.",
         ["path", "lfi"], arg_index=0)

    # SSRF
    for m in ("GetAsync", "PostAsync", "PutAsync", "DeleteAsync", "SendAsync",
              "GetStringAsync", "DownloadString", "OpenRead"):
        sink(f"cs-ssrf-{m.lower()}", m,
             f"Server-side request forgery via {m}()", "high", "CWE-918", A10,
             "ssrf",
             "The request target is attacker-controlled, so the server can be "
             "made to reach internal hosts or cloud metadata.",
             "Validate the URL against an allow-list and block internal ranges.",
             ["ssrf"], arg_index=0, confidence="medium")

    # XSS / redirect / code
    sink("cs-xss-writeliteral", "Write", "Reflected XSS via Response.Write()",
         "high", "CWE-79", A03, "xss",
         "Untrusted data is written to the response without HTML encoding.",
         "Render through Razor, which encodes by default, or call HtmlEncode.",
         ["xss"], obj_hint="response")
    sink("cs-xss-raw", "Raw", "XSS via Html.Raw()", "high", "CWE-79", A03, "xss",
         "Html.Raw() emits its argument unencoded, bypassing Razor's escaping.",
         "Render the value normally so Razor encodes it.",
         ["xss"], arg_index=0)
    sink("cs-redirect", "Redirect", "Open redirect", "medium", "CWE-601", A01,
         "open-redirect",
         "The redirect target comes from attacker-controlled input.",
         "Use LocalRedirect, or validate against an allow-list.",
         ["redirect"], arg_index=0)
    for m in ("Load", "LoadXml", "XmlReader"):
        sink(f"cs-xxe-{m.lower()}", m, "XML external entity processing", "high",
             "CWE-611", A05, "xxe",
             "Loading untrusted XML with a resolver that honours external "
             "entities exposes local files and internal services.",
             "Set XmlResolver = null and DtdProcessing = Prohibit.",
             ["xxe"], arg_index=0, confidence="medium")

    # An ADO.NET command carries its statement from the constructor or the
    # CommandText property, and the execute call then takes no arguments at
    # all — so the taint is in the receiver, not in an argument, and an
    # argument-indexed rule could never match `cmd.ExecuteReader()`.
    for m in ("ExecuteReader", "ExecuteNonQuery", "ExecuteScalar",
              "ExecuteReaderAsync", "ExecuteNonQueryAsync",
              "ExecuteScalarAsync"):
        sink(f"cs-sqli-cmd-{m.lower()}", m,
             f"SQL injection via a command built from untrusted data ({m}())",
             "high", "CWE-89", A03, "sql-injection",
             "The command this executes was built by concatenating untrusted "
             "data into its statement text.",
             "Use parameterised commands with SqlParameter.",
             ["sql"], receiver_tainted=True)
    sink("cs-sqli-commandtext", "CommandText",
         "SQL injection via CommandText", "high", "CWE-89", A03,
         "sql-injection",
         "The statement assigned to CommandText is built from untrusted data.",
         "Use parameterised commands with SqlParameter.",
         ["sql"], kind="property_assign")

    # XPath injection
    for m in ("SelectSingleNode", "SelectNodes", "XPathSelectElement",
              "XPathSelectElements", "Compile", "Evaluate"):
        sink(f"cs-xpathi-{m.lower()}", m, "XPath injection", "high",
             "CWE-643", A03, "xpath-injection",
             "The XPath expression is built from untrusted data, so the query "
             "can be rewritten to select data it should not reach.",
             "Pass the value as an XPath variable rather than concatenating it.",
             ["xpath", "sql"], arg_index=0)

    # Path traversal through the stream constructors and the WebForms helper
    # that maps a request-supplied path onto the filesystem.
    for m in ("StreamReader", "StreamWriter", "FileStream", "FileInfo",
              "MapPath", "OpenText", "CreateText", "AppendText"):
        sink(f"cs-path-{m.lower()}", m, f"Path traversal via {m}()", "high",
             "CWE-22", A01, "path-traversal",
             "An attacker-controlled path allows access outside the intended "
             "directory.",
             "Resolve the path and verify it stays within an allow-listed root.",
             ["path", "lfi"], arg_index=0)

    # Response header injection / open redirect
    for m in ("AppendHeader", "AddHeader"):
        sink(f"cs-header-{m.lower()}", m,
             "HTTP response header injection", "high", "CWE-113", A03,
             "header-injection",
             "An attacker-controlled header value can carry CR/LF and inject "
             "further headers or a response body; a Location built this way "
             "is also an open redirect.",
             "Strip CR and LF from the value, and allow-list redirect targets.",
             ["redirect", "xss"], arg_index=1, confidence="medium")

    # Loading code chosen by untrusted input
    for m in ("LoadFrom", "LoadFile", "UnsafeLoadFrom", "CreateInstance",
              "GetType"):
        sink(f"cs-code-{m.lower()}", m,
             f"Code loaded from untrusted input via {m}()", "high", "CWE-470",
             A08, "unsafe-reflection",
             "The assembly or type to load is chosen by attacker-controlled "
             "data, which decides what code runs.",
             "Map the input through a fixed allow-list of types.",
             ["code"], arg_index=0, confidence="medium")
    sink("cs-code-assembly-load", "Load",
         "Assembly loaded from untrusted input", "high", "CWE-470", A08,
         "unsafe-reflection",
         "The assembly to load is chosen by attacker-controlled data.",
         "Map the input through a fixed allow-list.",
         ["code"], arg_index=0, obj_hint="assembly", confidence="medium")
    return k


def _sanitizers() -> list[SanitizerRule]:
    s: list[SanitizerRule] = []
    for m in ("HtmlEncode", "HtmlAttributeEncode", "JavaScriptStringEncode",
              "Encode"):
        s.append(SanitizerRule(kind="call", match=m, neutralize=["xss"]))
    s.append(SanitizerRule(kind="call", match="UrlEncode", neutralize=["redirect"]))
    for m in ("Parse", "TryParse", "ToInt32", "ToInt64", "ToDouble"):
        s.append(SanitizerRule(
            kind="call", match=m,
            neutralize=["sql", "cmd", "xss", "ssrf", "lfi", "path", "code"]))
    s.append(SanitizerRule(kind="call", match="GetFileName",
                           neutralize=["path", "lfi"]))
    s.append(SanitizerRule(
        kind="call", match="GetFullPath", neutralize=["path"], weak=True,
        note="Path.GetFullPath() resolves a path but does not confine it to a "
             "root; compare the result against the allowed prefix"))
    return s


def _patterns() -> list[PatternRule]:
    p: list[PatternRule] = []

    def pat(rid, match, title, desc, fix, severity="medium", cwe="", owasp=A05,
            category="security-misconfiguration", confidence="high",
            ignore_case=False):
        p.append(PatternRule(
            rule_id=rid, node_type="*", match=match, match_field="text",
            title=title, severity=severity, cwe=cwe, owasp=owasp,
            category=category, description=desc, remediation=fix, regex=True,
            confidence=confidence, ignore_case=ignore_case))

    pat("cs-binaryformatter", r"\bnew\s+BinaryFormatter\s*\(",
        "BinaryFormatter in use",
        "BinaryFormatter is unsafe by design and deprecated: deserializing any "
        "untrusted payload with it yields code execution.",
        "Migrate to System.Text.Json or a contract-based serializer.",
        severity="high", cwe="CWE-502", owasp=A08,
        category="insecure-deserialization")
    pat("cs-typenamehandling", r"TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects)",
        "Json.NET polymorphic type handling enabled",
        "TypeNameHandling lets the payload choose which types to construct, "
        "which is a known remote-code-execution vector.",
        "Use TypeNameHandling.None, or a restrictive SerializationBinder.",
        severity="high", cwe="CWE-502", owasp=A08,
        category="insecure-deserialization")
    pat("cs-tls-accept-all",
        r"ServerCertificateValidationCallback\s*(?:\+)?=|"
        r"RemoteCertificateValidationCallback\s*(?:\+)?=.*true",
        "TLS certificate validation overridden",
        "A validation callback that always returns true accepts any "
        "certificate, making the connection interceptable.",
        "Remove the override and fix the trust store.",
        severity="high", cwe="CWE-295", owasp=A02, category="insecure-transport",
        confidence="medium")
    pat("cs-weak-hash", r"\b(?:MD5|SHA1)\.Create\s*\(",
        "Weak cryptographic hash (MD5/SHA-1)",
        "MD5 and SHA-1 are broken for signatures and integrity.",
        "Use SHA-256 or better; use PBKDF2/bcrypt/argon2 for passwords.",
        severity="low", cwe="CWE-328", owasp=A02, category="weak-crypto")
    pat("cs-weak-random", r"\bnew\s+Random\s*\(",
        "Predictable random number generator",
        "System.Random is not cryptographically secure; tokens derived from it "
        "are guessable.",
        "Use RandomNumberGenerator for security-relevant values.",
        cwe="CWE-338", owasp=A02, category="weak-random")
    pat("cs-ecb-mode", r"CipherMode\.ECB",
        "Insecure cipher mode (ECB)",
        "ECB maps identical plaintext blocks to identical ciphertext blocks, "
        "leaking plaintext structure.",
        "Use an authenticated mode such as AES-GCM.",
        cwe="CWE-327", owasp=A02, category="weak-crypto")
    pat("cs-validate-request-disabled",
        r"ValidateInput\s*\(\s*false\s*\)|validateRequest\s*=\s*[\"']false[\"']",
        "ASP.NET request validation disabled",
        "Request validation is a defence-in-depth filter against markup in "
        "input; disabling it removes that layer.",
        "Leave validation enabled and encode output contextually.",
        cwe="CWE-79", owasp=A03, category="xss")
    pat("cs-allow-anonymous", r"\[AllowAnonymous\]",
        "Endpoint explicitly allows anonymous access",
        "AllowAnonymous removes authentication for this endpoint. Each use "
        "needs to be deliberate.",
        "Confirm the endpoint is meant to be public.",
        severity="info", cwe="CWE-306", owasp=A01,
        category="broken-access-control", confidence="low")
    return p


def build_csharp_rules() -> RuleSet:
    return RuleSet(sources=_sources(), sinks=_sinks(),
                   sanitizers=_sanitizers(), patterns=_patterns())
