"""Java rule set: raw Java (Servlet), Spring and Spring Boot aware."""
from __future__ import annotations

from .base import RuleSet, TaintSource, SinkRule, SanitizerRule, PatternRule

_ALL = ["sql", "xss", "cmd", "ssrf", "lfi", "path", "deser", "xxe", "ldap",
        "trustbound",
        "redirect", "code", "log", "ssti", "jndi", "el", "xpath", "redos"]
A03 = "A03:2021 — Injection"
A10 = "A10:2021 — Server-Side Request Forgery (SSRF)"
A08 = "A08:2021 — Software and Data Integrity Failures"


def _sources() -> list[TaintSource]:
    s = []
    # Servlet / raw Java request accessors.
    for m in ("getParameter", "getParameterValues", "getHeader", "getHeaders",
              "getQueryString", "getInputStream", "getReader", "getCookies",
              "getAttribute", "getParameterMap",
              # The *names* are attacker-controlled too: a request decides
              # which parameters and headers it sends, and code that echoes a
              # name or stores it under that key is reflecting request data.
              "getParameterNames", "getHeaderNames", "getAttributeNames",
              "getPart", "getParts"):
        s.append(TaintSource(
            kind="method", match=m, tags=_ALL,
            description=f"Untrusted data from Servlet request ->{m}()",
        ))
    # The request's own address, and the client metadata around it. These are
    # attacker-influenced — the path and the Host header are whatever was
    # sent — but they describe *this* server, so they cannot stand in for a
    # URL an attacker chose: `new URL(request.getRequestURL())` points back
    # here, and tagging it `ssrf` reported an SSRF on every servlet that
    # rebuilt its own host. Injection into a query, a command or a
    # deserializer is still possible, so those tags stay.
    _SELF_REFERENTIAL = [t for t in _ALL if t not in ("ssrf",)]
    for m in ("getPathInfo", "getRequestURI", "getRequestURL", "getServletPath",
              "getPathTranslated", "getRemoteUser", "getRemoteHost",
              "getRemoteAddr", "getAuthType", "getContentType",
              "getCharacterEncoding"):
        s.append(TaintSource(
            kind="method", match=m, tags=_SELF_REFERENTIAL, confidence="medium",
            description=f"Attacker-influenced request metadata ->{m}()",
        ))
    # Spring WebUtils / RequestContextHolder / @RequestParam handled at method entry.
    s.append(TaintSource(
        kind="method", match="getenv", tags=_ALL, obj_hint="system",
        description="Untrusted data from System.getenv()",
    ))
    # A system property can carry attacker data when the deployment lets it,
    # but the JVM's own properties describe the platform and are not request
    # input. Excluding them keeps the source without reporting on every
    # servlet that looks up its working directory or OS name.
    s.append(TaintSource(
        kind="method", match="getProperty", tags=_ALL, obj_hint="system",
        confidence="low",
        arg_not_literal=(0, (
            "os.name", "os.arch", "os.version", "user.dir", "user.home",
            "user.name", "java.home", "java.version", "java.vendor",
            "java.io.tmpdir", "java.class.path", "java.library.path",
            "file.separator", "path.separator", "line.separator",
            "file.encoding", "sun.jnu.encoding",
        )),
        description="Data from a JVM system property (attacker-controlled only "
                    "if the deployment lets the attacker set properties)",
    ))
    s.append(TaintSource(
        kind="method", match="getOriginalFilename", tags=_ALL, obj_hint="multipartfile",
        description="Untrusted data from uploaded file getOriginalFilename()",
    ))
    # Zip Slip: archive entry names are attacker-controlled paths.
    s.append(TaintSource(
        kind="method", match="getName", tags=["path", "lfi"], obj_hint="zipentry",
        description="Untrusted path from archive entry ZipEntry.getName()",
    ))

    # --- Second-order sources -------------------------------------------
    # Values read back out of storage carry whatever was written there. This
    # is the stored-XSS / second-order-SQLi shape; low confidence because the
    # originating write may be outside the scanned code.
    for m in ("getString", "getObject", "getNString", "getCharacterStream",
              "getClob", "getBytes"):
        s.append(TaintSource(
            kind="method", match=m, tags=_ALL, obj_hint="resultset", confidence="low",
            description=f"Column read back from the database via ResultSet.{m}() "
                        "(second-order: tainted if attacker data was stored)",
        ))
    for m, hint in (("readLine", "reader"), ("readAllLines", "files"),
                    ("readString", "files"), ("readAllBytes", "files"),
                    ("nextLine", "scanner"), ("next", "scanner")):
        s.append(TaintSource(
            kind="method", match=m, tags=_ALL, obj_hint=hint, confidence="low",
            description=f"Data read from an external file or stream via {m}() "
                        "(trusted only if the source is)",
        ))
    return s


def _sinks() -> list[SinkRule]:
    k = []

    # --- SQL injection ---
    for m in ("executeQuery", "execute", "executeUpdate", "executeLargeUpdate",
              "prepareStatement", "prepareCall", "createQuery", "createNativeQuery",
              "queryForObject", "queryForList", "query", "update",
              # The rest of Spring's JdbcTemplate surface, plus JDBC batching.
              # Each takes the statement as a string exactly as the methods
              # above do, so leaving them out made a flow invisible purely
              # because of which overload the caller happened to pick.
              "queryForRowSet", "queryForMap", "queryForLong", "queryForInt",
              "queryForStream", "batchUpdate", "addBatch", "executeBatch",
              "executeLargeBatch", "nativeQuery", "createSQLQuery"):
        k.append(SinkRule(
            rule_id=f"java-sqli-{m}", kind="method", match=m,
            title=f"SQL injection via {m}()",
            severity="high", cwe="CWE-89", owasp=A03, category="sql-injection",
            description=f"Untrusted data flows into the SQL/query passed to {m}().",
            remediation="Use PreparedStatement with bound parameters or named parameters.",
            tags=["sql"],
        ))

    # --- Command injection ---
    k.append(SinkRule(
        rule_id="java-cmdi-exec", kind="method", match="exec",
        title="Command injection via Runtime.exec()",
        severity="critical", cwe="CWE-78", owasp=A03, category="command-injection",
        description="Untrusted data flows into a shell command passed to Runtime.exec().",
        remediation="Avoid shell execution with untrusted input; use ProcessBuilder with an argument array and no shell.",
        # Any argument counts, not just the command. The overloads also take
        # an environment array and a working directory, and an attacker who
        # controls the environment controls execution anyway — LD_PRELOAD,
        # IFS, PATH and BASH_ENV all turn a tainted envp into code execution.
        tags=["cmd"], obj_hint="Runtime",
    ))
    # A ProcessBuilder is often built empty and filled later, so the command
    # never passes through the constructor the object_create rule below sees.
    for m in ("command", "directory"):
        k.append(SinkRule(
            rule_id=f"java-cmdi-pb-{m}", kind="method", match=m,
            title=f"Command injection via ProcessBuilder.{m}()",
            severity="critical", cwe="CWE-78", owasp=A03,
            category="command-injection",
            description=f"Untrusted data sets the command ProcessBuilder will run "
                        f"via {m}().",
            remediation="Choose the program from a fixed allow-list and pass "
                        "arguments separately, never through a shell.",
            tags=["cmd"], obj_hint="processbuilder",
        ))
    k.append(SinkRule(
        rule_id="java-cmdi-processbuilder", kind="object_create", match="ProcessBuilder",
        title="Command injection via ProcessBuilder",
        severity="high", cwe="CWE-78", owasp=A03, category="command-injection",
        description="Untrusted data flows into a command executed by ProcessBuilder.",
        remediation="Whitelist commands and pass arguments separately, never via a shell string.",
        tags=["cmd"],
    ))

    # --- SSRF ---
    for m in ("getForObject", "getForEntity", "postForObject", "postForEntity",
              "exchange", "openConnection", "openStream"):
        k.append(SinkRule(
            rule_id=f"java-ssrf-{m}", kind="method", match=m,
            title=f"Server-side request forgery via {m}()",
            severity="high", cwe="CWE-918", owasp=A10, category="ssrf",
            description=f"Untrusted data controls the URL passed to {m}().",
            remediation="Validate and whitelist destination URLs; block loopback and private ranges.",
            tags=["ssrf"],
        ))
    k.append(SinkRule(
        rule_id="java-ssrf-url", kind="object_create", match="URL",
        title="Server-side request forgery via new URL()",
        severity="high", cwe="CWE-918", owasp=A10, category="ssrf",
        description="Untrusted data controls a URL object.",
        remediation="Validate and whitelist destination URLs.",
        tags=["ssrf"],
    ))
    k.append(SinkRule(
        rule_id="java-ssrf-uri", kind="method", match="create",
        title="Server-side request forgery via URI.create()",
        severity="medium", cwe="CWE-918", owasp=A10, category="ssrf",
        description="Untrusted data controls a URI used for network access.",
        remediation="Validate and whitelist URIs.",
        tags=["ssrf"], obj_hint="URI",
    ))

    # --- XSS (response writer) ---
    # printf/format take the format string first, and the Locale overload
    # pushes it to the second position, so neither can be pinned to a fixed
    # argument index: any tainted argument is reflected into the response.
    for m in ("printf", "format"):
        k.append(SinkRule(
            rule_id=f"java-xss-{m}", kind="method", match=m,
            title=f"Cross-site scripting via response writer ->{m}()",
            severity="medium", cwe="CWE-79", owasp=A03, category="xss",
            description=f"Untrusted data is formatted into the HTTP response via "
                        f"{m}() without encoding. A tainted format string is "
                        "worse still, since the conversions themselves become "
                        "attacker-controlled.",
            remediation="HTML-encode the values and keep the format string a literal.",
            tags=["xss"], obj_hint="response",
        ))
    for m in ("write", "print", "println", "append"):
        k.append(SinkRule(
            rule_id=f"java-xss-{m}", kind="method", match=m,
            title=f"Cross-site scripting via response writer ->{m}()",
            severity="medium", cwe="CWE-79", owasp=A03, category="xss",
            description=f"Untrusted data is written to the HTTP response via {m}() without encoding.",
            remediation="HTML-encode output (e.g. OWASP Java Encoder or HtmlUtils.htmlEscape).",
            tags=["xss"], obj_hint="response",
        ))

    # --- Spring: a String body returned as the response ---
    # Spring writes a ResponseEntity<String> body out as text, and with a
    # browser's Accept header that is text/html, so request data in it is
    # reflected XSS. A bean body is JSON and is left alone (type_arg).
    k.append(SinkRule(
        rule_id="java-xss-responseentity", kind="object_create",
        match="ResponseEntity",
        title="XSS via a ResponseEntity<String> body",
        severity="medium", cwe="CWE-79", owasp=A03, category="xss",
        description="Untrusted data is returned as the body of a "
                    "ResponseEntity<String>, which browsers render as HTML.",
        remediation="Encode for HTML (e.g. HtmlUtils.htmlEscape), or return "
                    "JSON with an explicit application/json content type.",
        tags=["xss"], arg_index=0, type_arg="String", confidence="medium",
    ))
    for m in ("ok", "body"):
        k.append(SinkRule(
            rule_id=f"java-xss-responseentity-{m}", kind="method", match=m,
            obj_hint="ResponseEntity",
            title=f"XSS via ResponseEntity.{m}() with a String body",
            severity="medium", cwe="CWE-79", owasp=A03, category="xss",
            description="Untrusted data is returned as the body of a "
                        "ResponseEntity<String>, which browsers render as HTML.",
            remediation="Encode for HTML (e.g. HtmlUtils.htmlEscape), or return "
                        "JSON with an explicit application/json content type.",
            tags=["xss"], arg_index=0, type_arg="String", confidence="medium",
        ))

    # --- Path traversal / arbitrary file access ---
    # Classpath resources: a `../` in the name walks out of the intended
    # resource folder (VulnerableApp's path traversal levels read this way).
    for m in ("getResourceAsStream", "getResource"):
        k.append(SinkRule(
            rule_id=f"java-path-{m.lower()}", kind="method", match=m,
            title=f"Path traversal via {m}()",
            severity="high", cwe="CWE-22", owasp="A01:2021 — Broken Access Control",
            category="path-traversal",
            description="Untrusted data chooses which classpath resource is read.",
            remediation="Map the input to a fixed allow-list of resource names.",
            tags=["path", "lfi"], arg_index=0,
        ))
    k.append(SinkRule(
        rule_id="java-path-file", kind="object_create", match="File",
        title="Path traversal via new File()",
        severity="high", cwe="CWE-22", owasp="A01:2021 — Broken Access Control",
        category="path-traversal",
        description="Untrusted data controls a File path.",
        remediation="Canonicalize and validate paths against an allow-list directory.",
        tags=["path", "lfi"],
    ))
    for m in ("readAllBytes", "readString", "readAllLines", "write", "writeString",
              "read", "newInputStream", "newOutputStream"):
        k.append(SinkRule(
            rule_id=f"java-path-{m}", kind="method", match=m,
            title=f"Path traversal via Files.{m}()",
            severity="high", cwe="CWE-22", owasp="A01:2021 — Broken Access Control",
            category="path-traversal",
            description=f"Untrusted data controls a filesystem path passed to Files.{m}().",
            remediation="Canonicalize and validate paths against an allow-list directory.",
            tags=["path", "lfi"], obj_hint="Files",
        ))

    # --- Insecure deserialization ---
    for m in ("readObject", "readUnshared"):
        k.append(SinkRule(
            rule_id=f"java-deser-{m}", kind="method", match=m,
            title=f"Insecure deserialization via ObjectInputStream.{m}()",
            severity="high", cwe="CWE-502", owasp=A08, category="insecure-deserialization",
            description=f"Untrusted data is deserialized via {m}().",
            remediation="Use an allow-list ObjectInputFilter; avoid deserializing untrusted data.",
            tags=["deser"], obj_hint="ObjectInputStream",
        ))
    k.append(SinkRule(
        rule_id="java-deser-readValue", kind="method", match="readValue",
        title="Insecure deserialization via ObjectMapper.readValue()",
        severity="high", cwe="CWE-502", owasp=A08, category="insecure-deserialization",
        description="Untrusted data is deserialized by Jackson's readValue().",
        remediation="Enable polymorphic type restrictions and validate input.",
        tags=["deser"], obj_hint="ObjectMapper",
    ))
    k.append(SinkRule(
        rule_id="java-deser-unmarshal", kind="method", match="unmarshal",
        title="Insecure deserialization via JAXB unmarshal()",
        severity="high", cwe="CWE-502", owasp=A08, category="insecure-deserialization",
        description="Untrusted XML/input is deserialized via unmarshal().",
        remediation="Validate against an XML schema and disable external entities.",
        tags=["deser"],
    ))

    # --- SpEL injection ---
    k.append(SinkRule(
        rule_id="java-spel-parseExpression", kind="method", match="parseExpression",
        title="Spring SpEL injection via SpelExpressionParser.parseExpression()",
        severity="high", cwe="CWE-917", owasp=A03, category="spel-injection",
        description="Untrusted data is evaluated as a Spring Expression Language expression, enabling code execution.",
        remediation="Never evaluate untrusted SpEL; use SimpleEvaluationContext with allow-listed access.",
        tags=["code"],
    ))

    # --- Open redirect / header injection ---
    k.append(SinkRule(
        rule_id="java-redirect-sendRedirect", kind="method", match="sendRedirect",
        title="Open redirect via sendRedirect()",
        severity="medium", cwe="CWE-601", owasp="A01:2021 — Broken Access Control",
        category="open-redirect",
        description="Untrusted data controls a redirect target.",
        remediation="Whitelist redirect targets.",
        tags=["redirect"],
    ))
    for m in ("setHeader", "addHeader"):
        k.append(SinkRule(
            rule_id=f"java-header-{m}", kind="method", match=m,
            title=f"Header injection via {m}()",
            severity="medium", cwe="CWE-113", owasp=A03, category="header-injection",
            description=f"Untrusted data flows into an HTTP header via {m}().",
            remediation="Strip CR/LF and validate header values.",
            tags=["redirect"],
        ))

    # --- LDAP injection (search only: `lookup` is JNDI, handled separately) ---
    # UnboundID's LDAPConnection and Spring's LdapTemplate take the filter
    # as a later argument; matched on the receiver's declared type.
    for hint, methods in (("ldapconnection", ("search", "searchForEntry")),
                          ("ldaptemplate", ("search", "searchForObject",
                                            "authenticate"))):
        for m in methods:
            k.append(SinkRule(
                rule_id=f"java-ldap-{hint}-{m.lower()}", kind="method", match=m,
                title=f"LDAP injection via {m}()",
                severity="high", cwe="CWE-90", owasp=A03,
                category="ldap-injection",
                description="Untrusted data is concatenated into an LDAP filter.",
                remediation="Build filters with Filter.createEqualityFilter() / "
                            "LdapQueryBuilder, or escape with Filter.encodeValue().",
                tags=["ldap"], obj_hint=hint))
    # A redirect target set through Spring's typed APIs.
    for m, hint in (("setLocation", "headers"), ("location", "responseentity")):
        k.append(SinkRule(
            rule_id=f"java-redirect-{m.lower()}", kind="method", match=m,
            title=f"Open redirect via {m}()",
            severity="medium", cwe="CWE-601", owasp="A01:2021 — Broken Access Control",
            category="open-redirect",
            description="The redirect target comes from user input, so the "
                        "response can send the browser to any site.",
            remediation="Redirect only to relative paths or an allow-listed host.",
            tags=["redirect"], arg_index=0, obj_hint=hint))
    k.append(SinkRule(
        rule_id="java-ldap-search", kind="method", match="search",
        title="LDAP injection via DirContext.search()",
        severity="high", cwe="CWE-90", owasp=A03, category="ldap-injection",
        description="Untrusted data flows into an LDAP filter passed to search().",
        remediation="Escape LDAP filter values and use whitelisted attributes.",
        tags=["ldap"], obj_hint="dircontext",
    ))

    # --- SSRF (additional transports) ---
    k.append(SinkRule(
        rule_id="java-ssrf-httpclient-send", kind="method", match="send",
        title="Server-side request forgery via HttpClient.send()",
        severity="high", cwe="CWE-918", owasp=A10, category="ssrf",
        description="Untrusted data controls a request sent via HttpClient.",
        remediation="Validate and whitelist destination URLs.",
        tags=["ssrf"], obj_hint="httpclient",
    ))
    k.append(SinkRule(
        rule_id="java-ssrf-webclient", kind="method", match="create", obj_hint="webclient",
        title="Server-side request forgery via WebClient.create()",
        severity="high", cwe="CWE-918", owasp=A10, category="ssrf",
        description="Untrusted data controls the base URL of a WebClient.",
        remediation="Validate and whitelist destination URLs.",
        tags=["ssrf"],
    ))

    # --- Command / code injection via scripting engine ---
    k.append(SinkRule(
        rule_id="java-cmdi-scriptengine", kind="method", match="eval",
        title="Code injection via ScriptEngine.eval()",
        severity="critical", cwe="CWE-94", owasp=A03, category="code-injection",
        description="Untrusted data is evaluated as script code by ScriptEngine.eval().",
        remediation="Never evaluate untrusted script; use a sandboxed engine if required.",
        tags=["code"], obj_hint="scriptengine",
    ))

    # --- Insecure deserialization (additional) ---
    k.append(SinkRule(
        rule_id="java-deser-yaml", kind="method", match="load",
        title="Insecure deserialization via Yaml.load()",
        severity="high", cwe="CWE-502", owasp=A08, category="insecure-deserialization",
        description="Untrusted YAML is deserialized by SnakeYAML's load(), enabling object construction.",
        remediation="Use SafeConstructor / Yaml(Constructor) and validate input.",
        tags=["deser"], obj_hint="yaml",
    ))
    k.append(SinkRule(
        rule_id="java-deser-xstream", kind="method", match="fromXML",
        title="Insecure deserialization via XStream.fromXML()",
        severity="high", cwe="CWE-502", owasp=A08, category="insecure-deserialization",
        description="Untrusted XML is deserialized by XStream.fromXML().",
        remediation="Configure an XStream type allow-list before deserializing.",
        tags=["deser"], obj_hint="xstream",
    ))

    # --- Path traversal (additional) ---
    for cls in ("FileInputStream", "FileOutputStream", "FileReader", "FileWriter",
                "RandomAccessFile"):
        k.append(SinkRule(
            rule_id=f"java-path-{cls}", kind="object_create", match=cls,
            title=f"Path traversal via new {cls}()",
            severity="high", cwe="CWE-22", owasp="A01:2021 — Broken Access Control",
            category="path-traversal",
            description=f"Untrusted data controls a filesystem path passed to {cls}.",
            remediation="Canonicalize and validate paths against an allow-list directory.",
            tags=["path", "lfi"],
        ))

    # --- Open redirect (Spring RedirectView) ---
    k.append(SinkRule(
        rule_id="java-redirect-view", kind="object_create", match="RedirectView",
        title="Open redirect via RedirectView",
        severity="medium", cwe="CWE-601", owasp="A01:2021 — Broken Access Control",
        category="open-redirect",
        description="Untrusted data controls a RedirectView target.",
        remediation="Whitelist redirect targets.",
        tags=["redirect"],
    ))

    # --- SpEL evaluation ---
    k.append(SinkRule(
        rule_id="java-spel-getValue", kind="method", match="getValue",
        title="Spring SpEL injection via Expression.getValue()",
        severity="high", cwe="CWE-917", owasp=A03, category="spel-injection",
        description="A SpEL expression is evaluated; if built from untrusted input this enables code execution.",
        remediation="Use SimpleEvaluationContext with an allow-list and never evaluate untrusted expressions.",
        tags=["code"], obj_hint="expression",
    ))

    # --- Log injection ---
    for m in ("info", "warn", "error", "debug", "trace", "fatal", "log"):
        k.append(SinkRule(
            rule_id=f"java-log-{m}", kind="method", match=m,
            title=f"Log injection via logger.{m}()",
            severity="low", cwe="CWE-117", owasp="A09:2021 — Security Logging and Monitoring Failures",
            category="log-injection",
            description=f"Untrusted data is written to logs via logger.{m}().",
            remediation="Strip CR/LF and sanitize untrusted values before logging.",
            tags=["log"], obj_hint="logger",
        ))

    # --- Server-side template injection ---
    k.append(SinkRule(
        rule_id="java-ssti-process", kind="method", match="process",
        title="Server-side template injection via template engine process()",
        severity="high", cwe="CWE-1336", owasp=A03, category="ssti",
        description="Untrusted data is rendered as a template (FreeMarker/Velocity/Thymeleaf).",
        remediation="Never render untrusted strings as templates; use fixed template files.",
        tags=["ssti"], obj_hint="template",
    ))
    k.append(SinkRule(
        rule_id="java-ssti-velocity-evaluate", kind="method", match="evaluate",
        title="Server-side template injection via Velocity.evaluate()",
        severity="high", cwe="CWE-1336", owasp=A03, category="ssti",
        description="Untrusted data is evaluated as a Velocity template.",
        remediation="Never evaluate untrusted Velocity templates.",
        tags=["ssti"], obj_hint="velocity",
    ))
    k.append(SinkRule(
        rule_id="java-ssti-velocity-merge", kind="method", match="merge",
        title="Server-side template injection via Velocity Template.merge()",
        severity="high", cwe="CWE-1336", owasp=A03, category="ssti",
        description="Untrusted data is merged/rendered as a Velocity template.",
        remediation="Never merge untrusted Velocity templates.",
        tags=["ssti"], obj_hint="template",
    ))

    # --- JNDI injection ---
    k.append(SinkRule(
        rule_id="java-jndi-lookup", kind="method", match="lookup",
        title="JNDI injection via Context.lookup()",
        severity="critical", cwe="CWE-917", owasp=A03, category="jndi-injection",
        description="Untrusted data is used as a JNDI lookup name, enabling remote code loading (Log4Shell class).",
        remediation="Never pass untrusted input to JNDI lookups; disable remote codebases.",
        tags=["jndi"], obj_hint="context",
    ))

    # --- Expression Language / OGNL injection ---
    k.append(SinkRule(
        rule_id="java-el-eval", kind="method", match="eval",
        title="Expression language injection via ELProcessor.eval()",
        severity="high", cwe="CWE-917", owasp=A03, category="el-injection",
        description="Untrusted data is evaluated as an EL expression.",
        remediation="Never evaluate untrusted EL expressions.",
        tags=["el"], obj_hint="elprocessor",
    ))
    k.append(SinkRule(
        rule_id="java-el-createValueExpression", kind="method", match="createValueExpression",
        title="Expression language injection via ExpressionFactory",
        severity="high", cwe="CWE-917", owasp=A03, category="el-injection",
        description="Untrusted data is compiled as an EL expression.",
        remediation="Never build EL expressions from untrusted input.",
        tags=["el"], obj_hint="expressionfactory",
    ))
    k.append(SinkRule(
        rule_id="java-el-ognl-getValue", kind="method", match="getValue",
        title="OGNL expression injection via Ognl.getValue()",
        severity="high", cwe="CWE-917", owasp=A03, category="el-injection",
        description="Untrusted data is evaluated as an OGNL expression (Struts2 class).",
        remediation="Never evaluate untrusted OGNL expressions.",
        tags=["el"], obj_hint="ognl",
    ))

    # --- XPath injection ---
    k.append(SinkRule(
        rule_id="java-xpath-compile", kind="method", match="compile",
        title="XPath injection via XPath.compile()",
        severity="high", cwe="CWE-643", owasp=A03, category="xpath-injection",
        description="Untrusted data flows into an XPath expression.",
        remediation="Whitelist XPath expressions; use parameterized queries.",
        tags=["xpath"], obj_hint="xpath",
    ))
    k.append(SinkRule(
        rule_id="java-xpath-evaluate", kind="method", match="evaluate",
        title="XPath injection via XPathExpression.evaluate()",
        severity="high", cwe="CWE-643", owasp=A03, category="xpath-injection",
        description="Untrusted data flows into an XPath expression.",
        remediation="Whitelist XPath expressions.",
        tags=["xpath"], obj_hint="xpath",
    ))

    # --- ReDoS (tainted regex pattern) ---
    k.append(SinkRule(
        rule_id="java-redos-compile", kind="method", match="compile",
        title="ReDoS via Pattern.compile() with untrusted pattern",
        severity="low", cwe="CWE-1333", owasp="A04:2021 — Insecure Design",
        category="redos",
        description="An untrusted value is used as the regex pattern.",
        remediation="Never compile untrusted regex; use Pattern.quote() and bound backtracking.",
        tags=["redos"], obj_hint="pattern",
    ))
    k.append(SinkRule(
        rule_id="java-redos-matches", kind="method", match="matches",
        title="ReDoS via String.matches() with untrusted pattern",
        severity="low", cwe="CWE-1333", owasp="A04:2021 — Insecure Design",
        category="redos",
        description="An untrusted value is used as the regex pattern.",
        remediation="Never use untrusted regex patterns.",
        tags=["redos"],
    ))

    # --- Insecure deserialization (Kryo / fastjson) ---
    k.append(SinkRule(
        rule_id="java-deser-kryo", kind="method", match="readObject",
        title="Insecure deserialization via Kryo.readObject()",
        severity="high", cwe="CWE-502", owasp=A08, category="insecure-deserialization",
        description="Untrusted data is deserialized by Kryo.",
        remediation="Register an allow-list of classes with Kryo.",
        tags=["deser"], obj_hint="kryo",
    ))
    k.append(SinkRule(
        rule_id="java-deser-fastjson", kind="method", match="parseObject",
        title="Insecure deserialization via fastjson JSON.parseObject()",
        severity="high", cwe="CWE-502", owasp=A08, category="insecure-deserialization",
        description="Untrusted JSON is deserialized by fastjson, which historically allows gadget chains.",
        remediation="Upgrade fastjson and disable autoType; validate with a schema.",
        tags=["deser"], obj_hint="json",
    ))

    return k


def _trustbound_sinks() -> list[SinkRule]:
    """A tainted name crossing into session storage (CWE-501)."""
    A05 = "A05:2021 — Security Misconfiguration"
    out = []
    for m in ("setAttribute", "putValue"):
        out.append(SinkRule(
            rule_id=f"java-trustbound-{m}", kind="method", match=m,
            title=f"Trust boundary violation via {m}()",
            severity="medium", cwe="CWE-501", owasp=A05,
            category="trust-boundary",
            description="Attacker-controlled data is written into the session "
                        "under an attacker-controlled name, mixing untrusted "
                        "input with trusted server-side state.",
            remediation="Validate the key against an allow-list before storing, "
                        "and never let a request choose a session attribute name.",
            # Either position matters: an attacker-chosen name is the trust
            # boundary violation CWE-501 describes, and attacker-chosen content
            # under a trusted name is what later code then relies on. Pinning
            # this to argument 0 missed every `putValue("userid", param)`.
            tags=["trustbound", "log"], arg_index=-1, confidence="medium"))
    return out


def _sanitizers() -> list[SanitizerRule]:
    s = []
    # Spring's hex/decimal variants and the OWASP Java Encoder's
    # context-specific methods escape at least as much as htmlEscape.
    for m in ("htmlEscape", "escapeHtml", "escapeHtml4", "forHtml", "encodeForHTML",
              "escapeHtml3", "htmlEscapeHex", "htmlEscapeDecimal", "forHtmlContent",
              "forHtmlAttribute", "forHtmlUnquotedAttribute", "encodeForHTMLAttribute",
              "escapeXml", "escapeXml10", "escapeXml11", "forXml", "forXmlContent",
              "forXmlAttribute"):
        s.append(SanitizerRule(kind="method", match=m, neutralize=["xss"]))
    s.append(SanitizerRule(kind="method", match="encodeForURL", neutralize=["redirect"]))
    # LDAP filter escaping: UnboundID, Spring LDAP, OWASP ESAPI.
    for m in ("encodeValue", "filterEncode", "encodeForLDAP"):
        s.append(SanitizerRule(kind="method", match=m, neutralize=["ldap"]))
    return s


def _patterns() -> list[PatternRule]:
    A02 = "A02:2021 — Cryptographic Failures"
    p = []
    for factory in ("DocumentBuilderFactory", "SAXParserFactory", "XMLInputFactory",
                    "SAXReader", "SAXBuilder"):
        p.append(PatternRule(
            rule_id=f"java-xxe-{factory}", node_type="object_creation_expression",
            match=factory, match_field="text", regex=False,
            title=f"Potential XXE via {factory}",
            severity="medium", cwe="CWE-611", owasp="A05:2021 — Security Misconfiguration",
            category="xxe",
            description=f"{factory} is instantiated. Ensure external entity resolution and DTDs are explicitly disabled.",
            remediation="Disable DOCTYPE/external entities (e.g. setFeature on DocumentBuilderFactory).",
        ))
    p.append(PatternRule(
        rule_id="java-insecure-cookie",
        node_type="*",
        match=r"\.addCookie\s*\(",
        absent=r"setSecure\s*\(\s*true\s*\)",
        match_field="text", regex=True,
        title="Cookie sent without the Secure flag",
        severity="medium", cwe="CWE-614", owasp=A02,
        category="security-misconfiguration",
        description="A cookie is added to the response without setSecure(true) "
                    "anywhere in this file, so it is transmitted over plaintext "
                    "HTTP and can be captured in transit.",
        remediation="Call setSecure(true) and setHttpOnly(true) before adding "
                    "the cookie, and set SameSite.",
        confidence="medium",
    ))
    p.append(PatternRule(
        rule_id="java-crypto-weak-cipher",
        node_type="*",
        match=r"""(?:Cipher|SecretKeyFactory|KeyGenerator)\.getInstance\s*\(\s*"""
              r"""[^")]*"(?:DES|DESede|TripleDES|RC2|RC4|ARCFOUR|Blowfish|IDEA|"""
              r"""AES/ECB|DES/ECB|[A-Za-z0-9]+/ECB)""",
        match_field="text", regex=True, ignore_case=True,
        title="Weak or broken cipher algorithm",
        severity="medium", cwe="CWE-327", owasp=A02, category="weak-crypto",
        description="DES, 3DES, RC2, RC4, Blowfish and IDEA are broken or too "
                    "weak for current use, and ECB mode leaks plaintext "
                    "structure by mapping equal blocks to equal ciphertext.",
        remediation="Use AES-GCM (or AES-CBC with a random IV and a MAC) and a "
                    "256-bit key.",
    ))
    p.append(PatternRule(
        rule_id="java-crypto-weak-hash-algorithm",
        node_type="*",
        match=r"""MessageDigest\.getInstance\s*\(\s*[^")]*"(?:MD2|MD4|MD5|SHA-?1)"""
              r"""|["'](?:MD5|SHA1|SHA-1)["']\s*,\s*["'][A-Za-z]+["']\s*\)""",
        match_field="text", regex=True, ignore_case=True,
        title="Weak cryptographic hash (MD5/SHA-1)",
        severity="low", cwe="CWE-328", owasp=A02, category="weak-crypto",
        description="MD2, MD4, MD5 and SHA-1 are collision-prone and unfit for "
                    "signatures, integrity checks or password storage.",
        remediation="Use SHA-256 or better; use bcrypt/scrypt/argon2 for passwords.",
    ))
    p.append(PatternRule(
        rule_id="java-crypto-md5", node_type="string_literal", match="MD5",
        match_field="text", title="Weak cryptographic hash (MD5)",
        severity="low", cwe="CWE-328", owasp="A02:2021 — Cryptographic Failures",
        category="weak-crypto",
        description="MD5 is cryptographically broken.",
        remediation="Use SHA-256+ or a password hashing function.",
    ))
    p.append(PatternRule(
        rule_id="java-crypto-sha1", node_type="string_literal", match="SHA-1",
        match_field="text", title="Weak cryptographic hash (SHA-1)",
        severity="low", cwe="CWE-328", owasp="A02:2021 — Cryptographic Failures",
        category="weak-crypto",
        description="SHA-1 is deprecated for security use.",
        remediation="Use SHA-256+.",
    ))
    p.append(PatternRule(
        rule_id="java-csrf-disabled", node_type="*",
        match=r"csrf\s*\(\)\s*\.\s*disable", match_field="text", regex=True,
        title="CSRF protection disabled",
        severity="medium", cwe="CWE-352", owasp="A01:2021 — Broken Access Control",
        category="csrf",
        description="Spring Security CSRF protection is disabled via csrf().disable().",
        remediation="Keep CSRF protection enabled; exempt only specific safe endpoints.",
    ))
    p.append(PatternRule(
        rule_id="java-auth-permitAll", node_type="*", match="permitAll()",
        match_field="text", title="Endpoint permits all access (permitAll())",
        severity="medium", cwe="CWE-862", owasp="A01:2021 — Broken Access Control",
        category="broken-access-control",
        description="permitAll() grants unauthenticated access; verify this endpoint should be public.",
        remediation="Restrict access with authenticated()/hasRole() unless intentionally public.",
    ))
    p.append(PatternRule(
        rule_id="java-weak-tls", node_type="string_literal",
        match=r'"(TLSv1|SSLv3|SSL)"', match_field="text", regex=True,
        title="Weak TLS/SSL protocol in use",
        severity="medium", cwe="CWE-326", owasp="A02:2021 — Cryptographic Failures",
        category="weak-crypto",
        description="A deprecated TLS/SSL protocol (TLSv1, SSLv3, SSL) is referenced.",
        remediation="Use TLS 1.2 or higher.",
    ))
    p.append(PatternRule(
        rule_id="java-hardcoded-secret", node_type="variable_declarator",
        match=r"(password|passwd|pwd|pass|secret|api[_-]?key|token)\s*=\s*\"[^\"]{4,}\"",
        match_field="text", regex=True, ignore_case=True,
        title="Hardcoded credential",
        severity="low", cwe="CWE-798", owasp="A07:2021 — Identification and Authentication Failures",
        category="hardcoded-secret",
        description="A credential/secret literal is assigned inline in source.",
        remediation="Load secrets from environment variables or a secrets manager.",
    ))
    p.append(PatternRule(
        rule_id="java-weak-random", node_type="object_creation_expression",
        match=r"\bnew\s+(?:java\.util\.)?Random\s*\(", match_field="text", regex=True,
        title="Predictable random number generator",
        severity="low", cwe="CWE-330", owasp="A02:2021 — Cryptographic Failures",
        category="weak-random",
        description="java.util.Random is not cryptographically secure.",
        remediation="Use java.security.SecureRandom for security-sensitive values.",
    ))
    p.append(PatternRule(
        rule_id="java-weak-random-math", node_type="method_invocation",
        match=r"Math\.random\s*\(", match_field="text", regex=True,
        title="Predictable random number generator (Math.random)",
        severity="low", cwe="CWE-330", owasp="A02:2021 — Cryptographic Failures",
        category="weak-random",
        description="Math.random() is not cryptographically secure.",
        remediation="Use java.security.SecureRandom.",
    ))
    p.append(PatternRule(
        rule_id="java-trust-all-tls", node_type="*",
        match=r"TrustAllCerts|trustAllCerts|TrustAllX509TrustManager",
        match_field="text", regex=True,
        title="Insecure trust manager (accepts all certificates)",
        severity="medium", cwe="CWE-295", owasp="A02:2021 — Cryptographic Failures",
        category="weak-tls",
        description="A trust-all X509TrustManager accepts any certificate, defeating TLS authentication.",
        remediation="Use the platform trust store and validate hostnames.",
    ))
    return p


def build_java_rules() -> RuleSet:
    return RuleSet(
        sources=_sources(),
        sinks=_sinks() + _trustbound_sinks(),
        sanitizers=_sanitizers(),
        patterns=_patterns(),
    )
