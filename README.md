# SAST — offline application security scanning

A fully offline, dependency-free-at-runtime security scanner covering **code,
dependencies, infrastructure, containers and secrets** in a single pass.

**Eight languages** with interprocedural source-to-sink taint analysis:

| Language | Frameworks |
|---|---|
| PHP | Laravel, Symfony, raw |
| Java | Spring, Spring Boot, Jakarta EE, raw |
| JavaScript / TypeScript | Node, Express, React, Angular, Next.js, NestJS, Vue |
| Python | Django, Flask, FastAPI, raw |
| Go | net/http, Gin, Echo, Fiber, Gorilla |
| C# | ASP.NET Core, ASP.NET, raw |
| C / C++ | memory safety, raw |

Plus four scanners that need no source language at all: **IaC**
(Terraform, Kubernetes, CloudFormation, Helm, docker-compose), **containers**
(Dockerfile + base-image CVEs), **secrets** (provider patterns + entropy), and
**dependencies** across Composer, Maven/Gradle, npm, PyPI, Go modules, NuGet
and Conan/vcpkg.

Every engine runs in the same pass, so a Java backend with a React frontend,
Terraform infrastructure and a Dockerfile is scanned end to end in one
command. Reports are HTML, JSON or **SARIF**.

Think of it as an offline, framework-aware Snyk / SonarQube.

## Features

- **Framework auto-detection** — `composer.json` → Laravel / Symfony;
  `pom.xml` / `build.gradle` + Spring annotations → Spring / Spring Boot;
  `package.json` → Express / NestJS / React / Next.js / Angular / Vue, with
  source markers as a fallback.
- **Source-to-sink taint analysis** — interprocedural, sanitizer-aware, with a
  full trace (source → intermediate hops → sink) and code citations.
- **OWASP Top 10 + framework/dependency-specific rules**:
  - SQL injection (raw `mysqli`/PDO, Laravel `DB::raw`/`whereRaw`, Doctrine DQL,
    JDBC/JPA/JdbcTemplate, `knex.raw`/`sequelize.query`) and NoSQL injection
  - XSS (echo/print, Blade `{!! !!}`, Servlet response writer, `innerHTML`,
    `document.write`, React `dangerouslySetInnerHTML`, Angular
    `bypassSecurityTrust*`)
  - Node/Express: command injection via `child_process`, path traversal via
    `fs`/`res.sendFile`, open redirect, SSRF, prototype pollution, dynamic
    `require()`, JWT `alg:none`, permissive CORS
  - Command injection, SSRF, path traversal/LFI, insecure deserialization,
    XXE, LDAP injection, open redirect, SpEL injection, mass assignment,
    CSRF/authorization misconfig, weak crypto.
- **Dependency reachability** — every dependency finding is classified as
  `called`, `imported` or `unused` based on whether first-party code reaches
  it, and ranked accordingly, so the list leads with what matters.
- **Dependency vulnerability scanning** — matches `composer.lock`,
  `pom.xml`/`build.gradle`, and `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`
  against a bundled offline advisory DB with semantic version ranges; import
  OSV, NVD (1.1 & 2.0), or a custom JSON feed. Reports state how old the
  bundled database is.
- **Confidence-aware taint sources** — `$_SERVER` is modelled key by key
  (`HTTP_*`, `REQUEST_URI`, … are tainted; `DOCUMENT_ROOT`, `REMOTE_ADDR` are
  not), and second-order sources such as `$_SESSION`, database reads and file
  reads report at lower confidence than direct request input.
- **Template and configuration scanning** — Twig, JSP, Thymeleaf, FreeMarker
  and Blade for unescaped output; `.env`, `application.properties`, `web.xml`
  and `php.ini` for misconfiguration and committed secrets.
- **Soundness-aware sanitizers** — bypassable escaping (`addslashes`,
  `escapeshellcmd`, `strip_tags`, `filter_var` without a filter) downgrades a
  finding's confidence instead of silently clearing it.
- **Reports** — self-contained HTML, JSON, and SARIF 2.1.0 (GitHub code
  scanning, VS Code, SonarQube compatible).

## Install

Requires Python 3.10+.

```bash
pip install -e .
```

This installs the `sast` command. No network access is needed at scan time.

## Build a single offline executable

`make` downloads the OSV vulnerability feeds (Packagist + Maven), embeds them
into the package, and produces a self-contained binary with PyInstaller:

```bash
make                 # download feeds + build (default)
make feeds           # only (re)download feeds -> sast/data/advisories/downloaded.json
make build           # only build dist/sast (Linux) / dist/sast.exe (Windows)
make test            # run the unit test suite
make smoke           # run the built binary against one fixture per engine
```

`make smoke` exists because the unit tests import the Python package and so
say nothing about whether the *executable* works — a grammar or data file
missing from the bundle would pass every test and still fail for users. CI
runs it on both platforms before uploading an artifact.

The resulting binary (`dist/sast` or `dist/sast.exe`) contains the tool and the
advisory database — no network access is required to run it. Re-run `make`
periodically to refresh the embedded vulnerability data.

## Usage

```bash
# Scan a project, write an HTML report
sast scan /path/to/project -o report.html

# JSON / SARIF output
sast scan /path/to/project --format json
sast scan /path/to/project --format sarif -o results.sarif

# Filter by minimum severity
sast scan /path/to/project --min-severity high

# Use extra advisory DBs (repeatable)
sast scan /path/to/project --advisory-db my-advisories.json --advisory-db more.json
```

## Web interface

`sast server` serves a browser interface that scans a local path, an uploaded
ZIP, or a git repository and shows the report on the same page.

```bash
sast server                      # http://127.0.0.1:8000
sast server --port 9000 --data-dir /var/lib/sast
```

Scan history is kept in SQLite under `~/.sast` and survives a restart; a scan
cut short by one is marked `interrupted` rather than left reading `running`
forever. Reports stay available as HTML and JSON.

It is built on `http.server` from the standard library — a framework would
have cost the tool its defining property of running offline with nothing
installed.

### Security of the interface

**There is no authentication**, so the bind address is the security boundary.
It listens on `127.0.0.1` by default; `--host 0.0.0.0` prints a warning and
shows a banner in the page, because anyone who can reach the port can then
scan any path on the machine and read the results. Two protections apply
regardless: the `Host` header is checked, so a page on another site cannot
drive the server through DNS rebinding, and state-changing requests must be
same-origin.

The three inputs are all attacker-shaped, and are treated that way:

| Input | Handling |
|---|---|
| **ZIP** | Entries with absolute paths, `..` traversal, symlinks or device files are refused; the resolved destination is re-checked against the extraction root; size and entry count are capped against zip bombs. |
| **Git** | `git clone` is reached through an argument list, never a shell. Schemes are allow-listed, which blocks `ext::` (arbitrary command execution) and `file://`; a URL starting with `-` is refused so it cannot be read as `--upload-pack=`; clones are shallow, time-limited and cannot prompt for credentials. |
| **Local path** | Resolved and reported, so what was scanned is never ambiguous. |

### Failing a build (CI gating)

By default `sast scan` always exits 0. Pass `--fail-on` to exit 1 when
anything at or above a severity is found — code findings and vulnerable
dependencies both count:

```bash
sast scan . --format sarif -o results.sarif --fail-on high
```

### Scan scope and limits

```bash
sast scan . --include-tests          # also scan test code (excluded by default)
sast scan . --max-file-size 5        # skip source files over 5 MB (default: 2)
sast scan . --max-files 1000         # cap files scanned per language
```

Test code is skipped by default — fixtures deliberately contain unsafe
patterns that are not attacker-reachable in production. Files left out are
reported in the summary and in every report format.

Scanning is single-threaded on purpose: tree-sitter's Python binding holds
the GIL for the duration of a parse, so a worker pool measurably *slows*
scans down rather than speeding them up.

### Polyglot and multi-module projects

Every language present is scanned, not just the most common one, and
frameworks are detected from module manifests anywhere in the tree — so a
monorepo whose root has no `composer.json` or `pom.xml` still resolves
Laravel, Symfony, Spring and Spring Boot per module:

```
  Languages:   php, java
    php      framework: Laravel
    java     framework: Spring Boot
```

### Vulnerability feed coverage

`make feeds` downloads OSV data for **every language ecosystem** the scanner
analyses — Packagist, Maven, npm, PyPI, Go and NuGet. A dependency parser
without a matching feed silently reports zero vulnerabilities, so these are
not optional.

The OS distribution feeds that back base-image scanning are opt-in, because
Ubuntu's export alone is ~740 MB:

```bash
make feeds FEEDS="Packagist Maven npm PyPI Go NuGet Alpine Debian"
```

**C and C++ have no OSV ecosystem** (ConanCenter returns 404). The Conan and
vcpkg manifests are parsed, but matching them needs an NVD feed imported
separately.

### Importing vulnerability feeds (offline)

```bash
# OSV / GHSA JSON feed
sast import-feed osv-feed.json -o advisories.json

# NVD CVE feed (1.1 or 2.0 format)
sast import-feed nvdcve.json --package-map cpe-map.json -o advisories.json
```

The `--package-map` is an optional JSON mapping `{"vendor:product": "composer/name"}`
used to translate NVD CPEs into ecosystem package names.

## How it works

1. **Detect** language and framework from manifests + source annotations.
2. **Parse** every source file with tree-sitter (PHP, Java, JavaScript,
   TypeScript and TSX grammars).
3. **Index** functions/classes/methods into namespace-aware symbol tables.
4. **Taint** — data from sources (superglobals, request accessors,
   `@RequestParam`/`@PathVariable`, …) propagates through assignments,
   concatenation, and calls (interprocedurally) until it reaches a sink
   (dangerous call). Sanitizers (`htmlspecialchars`, `is_numeric` guards,
   prepared statements, `HtmlUtils.htmlEscape`, …) neutralize taint.
5. **Match** installed dependencies against the advisory DB.
6. **Report** validated findings with the full trace.

## Project layout

```
sast/
  analysis/    taint engines (PHP, Java, JS hand-written; one generic
               engine driven by language profiles for the rest), plus the
               secrets, IaC and container scanners
  advisory/    offline DB, semver, composer/maven parsing, feed importers
  detection/   language + framework auto-detection
  parsing/     tree-sitter parsers for all eight languages
  reporting/   HTML, JSON, SARIF renderers
  rules/       declarative rule model + per-language rule sets
  data/        bundled advisory seed databases
  web/         optional browser interface (`sast server`)
  engine.py    orchestration
  cli.py       command-line interface
examples/      vulnerable fixtures (raw-php, laravel-app, symfony-app,
               spring-app, express-app, react-app, angular-app)
tests/         unittest suite
```

## Extending

Rules are declarative. Add a `SinkRule`, `TaintSource`, `SanitizerRule`, or
`PatternRule` to `sast/rules/php_rules.py`, `java_rules.py` or `js_rules.py`
and it is picked up automatically. Add advisory entries to
`sast/data/advisories/seed.json` (Packagist), `seed-java.json` (Maven
`groupId:artifactId`) or `seed-npm.json` (npm package name).

The JavaScript rules use these `kind` values: sources are `member` (a property
read such as `req.query`) or `call`; sinks are `call`, `property_assign`
(`el.innerHTML = …`) or `jsx_attribute` (`dangerouslySetInnerHTML`). An
`obj_hint` scopes a rule to a receiver (`fs`, `res`, `req`, `location`), which
is what keeps Node APIs matching regardless of which framework was detected.

## Tests

```bash
python -m unittest tests.test_sast -v
```

## Beyond application code

### Secrets
Scanned across every text file, not just source — a credential is as dangerous
in a README or a CI config. Two strategies: ~22 **provider patterns** (AWS,
GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic, npm, PyPI, SendGrid,
Twilio, Azure, private keys, JWTs, DB connection URIs) matched by their
issuer-defined shape, and **Shannon entropy** over credential-shaped
assignments for keys with no distinctive format. Placeholders (`changeme`,
`your-api-key`, `${VAR}`) and low-variety values are suppressed, and findings
in example/fixture paths are downgraded rather than dropped.

**Secret values are redacted everywhere** — they never reach a report in any
format.

### Infrastructure as code
Terraform/HCL, Kubernetes, CloudFormation, Helm values and docker-compose:
world-open security groups, public S3 buckets and ACLs, publicly accessible
databases, unencrypted storage, wildcard IAM actions and principals, IMDSv1,
privileged containers, host namespaces, root containers, mounted Docker
sockets, and disabled audit logging.

### Dependency reachability

A vulnerable package in a lockfile is not the same thing as a vulnerable
application. Most dependency alerts are for packages that are installed but
never used. Every dependency finding is classified by whether first-party code
actually reaches it, and the list is ranked by that — a *called* medium
outranks an *unimported* critical:

| State | Meaning |
|---|---|
| `called` | The package is imported **and** a symbol the advisory names is invoked |
| `imported` | The package is imported, so the vulnerable version is loaded |
| `unused` | No first-party import found — usually deprioritisable |

```bash
sast scan . --ignore-unreachable   # drop what nothing imports
sast scan . --no-reachability      # skip the analysis
```

Each verdict carries its evidence (`imported as 'lodash' and the advisory's
defaultsDeep() is called in first-party code`) so it can be checked rather
than taken on trust. Package names are mapped to import names per ecosystem —
`pyyaml` imports as `yaml`, `org.group:artifact` as `org.group.artifact`.

This is **import and call-site evidence, not an exploitability claim**: it
establishes what can be known without resolving the dependency's own source.
`unused` does not prove a package is unloadable — another dependency may pull
it in — and `called` does not prove the vulnerable path is taken.

### Containers
Dockerfile analysis (root user, unpinned base image, secrets baked into
layers, `curl | sh`, `ADD` from a URL, disabled package verification, exposed
SSH) plus **base-image CVE matching** — the `FROM` line is treated as a
dependency and matched against distro advisories. A CycloneDX or SPDX SBOM is
ingested when the build produced one; images are never pulled or unpacked,
since that would need a daemon and a network.

```bash
sast scan . --only iac --only secrets   # run selected scanners
sast scan . --no-containers             # or disable one
```

## Templates and configuration

Rendering and deployment posture do not live in `.php` or `.java` files, so
they are scanned separately:

- **Templates** — Twig (`|raw`, `autoescape false`, `template_from_string`),
  JSP (`<%= %>` of request data, `<c:out escapeXml="false">`, `${param.*}`),
  Thymeleaf (`th:utext`, preprocessing expressions), FreeMarker (`#noescape`,
  `?new()`), and Blade (`{!! !!}`).
- **Configuration** — `.env`, `application.properties/yml`, `web.xml`,
  `php.ini`: debug mode left on, Spring Actuator exposed, TLS disabled,
  insecure session cookies, `allow_url_include`, and committed secrets.
  Secret *values* are redacted in every report format.

Disable either with `ScanOptions(scan_templates=False, scan_configs=False)`.

## Limitations

What the engine does **not** find, and why:

- **Access control, authorization and business logic** (OWASP A01/A04) —
  `User::find($_GET['id'])` followed by printing the record is correct
  dataflow and a critical IDOR. Deciding who may read what is not expressible
  as source-to-sink, so these are out of scope by construction rather than
  by omission. The same applies to authentication design, race
  conditions/TOCTOU, and "insufficient logging".
- **Context-sensitive escaping** — `htmlspecialchars()` is treated as sound
  for XSS (since PHP 8.1 it escapes quotes by default), but it is *not* safe
  inside `<script>` or an unquoted attribute. Judging that needs template
  analysis the engine does not do. Escaping that is bypassable regardless of
  context (`addslashes`, `escapeshellcmd`, `strip_tags`, `filter_var` with no
  filter) is handled: the finding survives at reduced confidence instead of
  being silently cleared.
- **Maven transitive dependencies** — `pom.xml` declares only direct
  dependencies, and resolving the rest needs the Maven resolver and a
  network. Commit (or generate) a `gradle.lockfile` or `mvn dependency:tree`
  output as `dependency-tree.txt` and those are scanned too. `composer.lock`
  already lists the full tree, so PHP is unaffected.
- **Variable variables** (`$$name`) in PHP.
- **Container images are not unpacked** — only the Dockerfile and, where
  present, an SBOM are read. Scanning the contents of a built image needs a
  daemon and a network, which would break the offline guarantee.
- **C/C++ analysis is function-local for memory safety** — unsafe APIs and
  tainted-length copies are found, but there is no pointer or alias analysis,
  so heap-shape bugs (use-after-free, double-free) are out of reach.
- **IaC rules are textual**, not a full HCL/YAML evaluation: a value computed
  by a module or a variable indirection is not resolved.
- **Reachability does not analyse dependency source.** It reads first-party
  imports and call sites only, so a package reached solely through another
  dependency reads as `unused`, and a dynamic import (`importlib`,
  `require(variable)`) is not followed.
- **No OSV feed exists for C/C++.** The Conan/vcpkg parsers extract packages,
  but OSV publishes no ConanCenter ecosystem, so native-library CVEs need an
  NVD feed imported with `sast import-feed`.
- **JavaScript module resolution** — identifiers are indexed globally by name
  rather than per module, so two different helpers sharing a name are conflated
  and a renamed import (`import { x as y }`) is not followed.
- **Vue and Svelte** single-file components are not parsed; their `.js`/`.ts`
  is, but `.vue`/`.svelte` templates are not.
- Vendor/third-party code is modeled via rules rather than parsed; only
  first-party source is scanned.
- Scanning is single-threaded by design (see "Scan scope and limits").
