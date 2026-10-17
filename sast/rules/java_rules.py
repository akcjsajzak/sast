"""Java rule set: raw Java (Servlet), Spring and Spring Boot aware."""
from __future__ import annotations

from .base import RuleSet, TaintSource, SinkRule, SanitizerRule, PatternRule

_ALL = ["sql", "xss", "cmd", "ssrf", "lfi", "path", "deser", "xxe", "ldap",
        "redirect", "code", "log", "ssti", "jndi", "el", "xpath", "redos"]
A03 = "A03:2021 — Injection"
A10 = "A10:2021 — Server-Side Request Forgery (SSRF)"
A08 = "A08:2021 — Software and Data Integrity Failures"


def _sources() -> list[TaintSource]:
    s = []
    # Servlet / raw Java request accessors.
    for m in ("getParameter", "getParameterValues", "getHeader", "getHeaders",
              "getQueryString", "getInputStream", "getReader", "getCookies",
              "getAttribute", "getParameterMap"):
        s.append(TaintSource(
            kind="method", match=m, tags=_ALL,
            description=f"Untrusted data from Servlet request ->{m}()",
        ))
    # Spring WebUtils / RequestContextHolder / @RequestParam handled at method entry.
    s.append(TaintSource(
        kind="method", match="getenv", tags=_ALL, obj_hint="system",
        description="Untrusted data from System.getenv()",
    ))
    s.append(TaintSource(
        kind="method", match="getProperty", tags=_ALL, obj_hint="system",
        description="Untrusted data from System.getProperty()",
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
              "queryForObject", "queryForList", "query", "update"):
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
        tags=["cmd"], obj_hint="Runtime",
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
    for m in ("write", "print", "println", "append"):
        k.append(SinkRule(
            rule_id=f"java-xss-{m}", kind="method", match=m,
            title=f"Cross-site scripting via response writer ->{m}()",
            severity="medium", cwe="CWE-79", owasp=A03, category="xss",
            description=f"Untrusted data is written to the HTTP response via {m}() without encoding.",
            remediation="HTML-encode output (e.g. OWASP Java Encoder or HtmlUtils.htmlEscape).",
            tags=["xss"], obj_hint="response",
        ))

    # --- Path traversal / arbitrary file access ---
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


def _sanitizers() -> list[SanitizerRule]:
    s = []
    for m in ("htmlEscape", "escapeHtml", "escapeHtml4", "forHtml", "encodeForHTML",
              "escapeHtml3"):
        s.append(SanitizerRule(kind="method", match=m, neutralize=["xss"]))
    s.append(SanitizerRule(kind="method", match="encodeForURL", neutralize=["redirect"]))
    return s


def _patterns() -> list[PatternRule]:
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
        sinks=_sinks(),
        sanitizers=_sanitizers(),
        patterns=_patterns(),
    )
