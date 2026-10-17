# sast — Static Analysis & Surface Testing

![CI](https://github.com/akcjsajzak/sast/actions/workflows/build.yml/badge.svg)

`sast` is a security scanner that works its way through a codebase and hands
back one report covering every part of it: application code, third-party
dependencies, infrastructure-as-code, Dockerfiles, templates and hard-coded
secrets. It runs entirely offline and ships as a single binary, so there is
nothing to install and nothing to phone home to.

The name is a backronym. "Static Analysis & Surface Testing": static analysis
of your code, plus every other surface an attacker can reach — the packages you
depend on, the cloud resources you define, the containers you ship and the
credentials you commit.

![sast HTML report](docs/report.png)

## What it does

- **Eight languages**, analysed framework-aware. PHP (Laravel, Symfony), Java
  (Spring, Spring Boot, Jakarta EE), JavaScript and TypeScript (Node, Express,
  React, Angular, Next.js, NestJS, Vue), Python (Django, Flask, FastAPI), Go
  (net/http, Gin, Echo, Fiber, Gorilla), C# (ASP.NET), and C/C++ for memory
  safety. The framework is detected from your manifests, so the rules match
  what you actually wrote.
- **Source-to-sink taint analysis.** Data is tracked from where it enters (a
  request parameter, a superglobal, an environment read) through assignments,
  concatenation and calls, until it reaches a sink like `eval`, `system`, a
  raw SQL query or `innerHTML`. Every finding carries the full path it took to
  get there.
- **Dependencies, ranked by whether you use them.** A vulnerable package in a
  lockfile is only interesting if your code reaches it. Findings are marked
  `called`, `imported` or `unused`, and the report puts the ones your code
  actually invokes first.
- **The other surfaces.** Secrets across every text file, Terraform and
  Kubernetes misconfigurations, Dockerfile problems and base-image CVEs, and
  template/config issues — all in the same pass as the code scan.
- **Confidence that means something.** `$_SERVER` is modelled key by key, and
  data read from a database, session or file reports at lower confidence than
  direct request input. A sanitizer with a known bypass downgrades a finding
  instead of pretending it fixed it.

## Quick start

Python 3.10+ to install, nothing at scan time.

```bash
pip install -e .
sast scan /path/to/project -o report.html
```

```bash
# JSON or SARIF (SARIF goes straight into GitHub code scanning)
sast scan /path/to/project --format json
sast scan /path/to/project --format sarif -o results.sarif

# Fail CI when anything at or above a severity is found
sast scan . --format sarif -o results.sarif --fail-on high
```

## Building a single binary

```bash
make                 # download feeds + build (default)
make feeds           # only refresh the OSV feeds
make build           # only build dist/sast (Linux) or dist/sast.exe (Windows)
make test            # run the unit test suite
make smoke           # run the built binary against one fixture per engine
```

The result contains the tool and the advisory database. `make smoke` matters
because the unit tests import the Python package, not the executable; a
missing grammar or data file would pass them and still break for users, so CI
runs the smoke test on both platforms before uploading an artifact. Re-run
`make` now and then to refresh the embedded vulnerability data.

## Language coverage

| Language | Frameworks |
|---|---|
| PHP | Laravel, Symfony, raw |
| Java | Spring, Spring Boot, Jakarta EE, raw |
| JavaScript / TypeScript | Node, Express, React, Angular, Next.js, NestJS, Vue |
| Python | Django, Flask, FastAPI, raw |
| Go | net/http, Gin, Echo, Fiber, Gorilla |
| C# | ASP.NET Core, ASP.NET, raw |
| C / C++ | memory safety, raw |

The four scanners that need no source language at all (IaC, containers,
secrets, dependencies) run regardless of what languages are present.

## What it finds

### Code

Interprocedural, sanitizer-aware, with a trace from source to sink for every
finding. The rule set covers the OWASP Top 10 plus the framework-specific
surfaces:

- SQL injection (raw `mysqli`/PDO, Laravel `DB::raw`/`whereRaw`, Doctrine DQL,
  JDBC/JPA/JdbcTemplate, `knex.raw`/`sequelize.query`), NoSQL injection, command
  injection, LDAP, SpEL and XPath.
- XSS through `echo`/`print`, Blade `{!! !!}`, servlet response writers,
  `innerHTML`, `document.write`, React `dangerouslySetInnerHTML`, Angular
  `bypassSecurityTrust*`, and the Node `res.*` sinks.
- SSRF, path traversal, open redirect, insecure deserialization, XXE, mass
  assignment, prototype pollution, JWT `alg:none`, permissive CORS and weak
  crypto.
- C/C++ memory safety: unsafe APIs (`gets`, `strcpy`, `sprintf`), tainted
  format strings and copy lengths, allocation-size bugs, and a dedicated
  use-after-free / double-free checker.

### Dependencies

`composer.lock`, `pom.xml`/`build.gradle`, and `package-lock.json`/`yarn.lock`/
`pnpm-lock.yaml` are matched against the bundled advisory database with
semantic version ranges. Each finding is classified by reachability:

| State | Meaning |
|---|---|
| `called` | the package is imported **and** a symbol the advisory names is invoked |
| `imported` | the package is imported, so the vulnerable version is loaded |
| `unused` | no first-party import found |

A called medium outranks an unimported critical. `--ignore-unreachable` drops
the unused ones entirely, and each verdict carries its evidence so you can
check it rather than trust it.

### Secrets

Searched across every text file, because a credential is as dangerous in a
README or CI config as in source. Two approaches: about 22 provider patterns
(AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic, npm, PyPI,
SendGrid, Twilio, Azure, private keys, JWTs, database URIs) matched by their
issuer-defined shape, plus Shannon entropy over credential-shaped assignments.
Placeholders and low-variety values are suppressed, and secret values are
redacted before they ever reach a report.

### Infrastructure as code

Terraform/HCL, Kubernetes, CloudFormation, Helm and docker-compose: world-open
security groups, public buckets, publicly accessible databases, unencrypted
storage, wildcard IAM actions and principals, IMDSv1, privileged containers,
host namespaces and mounted Docker sockets.

### Containers

Dockerfile analysis (root user, unpinned base image, secrets baked into
layers, `curl | sh`, `ADD` from a URL, disabled package verification) plus
base-image CVE matching: the `FROM` line is treated as a dependency and matched
against distro advisories. A CycloneDX or SPDX SBOM is read when present.

### Templates and configuration

Rendering and deployment posture live outside `.php` and `.java` files: Twig
(`|raw`), JSP (`<%= %>`, `<c:out escapeXml="false">`), Thymeleaf (`th:utext`),
FreeMarker (`#noescape`), Blade (`{!! !!}`), plus `.env`,
`application.properties`, `web.xml` and `php.ini` for debug flags, exposed
actuators, disabled TLS and committed secrets.

## Reports

HTML (a single self-contained file), JSON, and SARIF 2.1.0. SARIF drops
straight into GitHub code scanning and any other SARIF-aware tool.

## Web interface

`sast server` serves a browser UI that scans a local path, an uploaded ZIP, or
a git repository, and shows the report on the same page. History is kept in
SQLite under `~/.sast` and survives restarts.

```bash
sast server                      # http://127.0.0.1:8000
sast server --port 9000 --data-dir /var/lib/sast
```

![sast web interface](docs/web.png)

It is built on `http.server` from the standard library; adding a web framework
would have cost the tool its defining property of running offline with nothing
installed.

There is no authentication, so the bind address is the security boundary. It
listens on `127.0.0.1` by default, and `--host 0.0.0.0` prints a warning.
Regardless of bind address, the `Host` header is checked (DNS-rebinding
protection) and state-changing requests must be same-origin. The inputs are
attacker-shaped and treated that way: ZIP entries with traversal or symlinks
are refused, git clone runs through an argument list rather than a shell with
schemes allow-listed, and local paths are resolved and reported unambiguously.

## CI gating

`sast scan` exits 0 by default. `--fail-on` flips that:

```bash
sast scan . --format sarif -o results.sarif --fail-on high
```

Anything at or above the threshold — code findings and vulnerable dependencies
both — makes the command exit 1.

## Usage reference

```bash
# Minimum severity
sast scan /path/to/project --min-severity high

# Extra advisory databases (repeatable)
sast scan /path/to/project --advisory-db my-advisories.json --advisory-db more.json

# Scope and limits
sast scan . --include-tests          # scan test code too (excluded by default)
sast scan . --max-file-size 5        # skip source files over 5 MB (default: 2)
sast scan . --max-files 1000         # cap files scanned per language

# Dependency reachability
sast scan . --ignore-unreachable     # drop what nothing imports
sast scan . --no-reachability        # skip the analysis

# Run only certain scanners
sast scan . --only iac --only secrets
sast scan . --no-containers

# Import an OSV / NVD feed offline
sast import-feed osv-feed.json -o advisories.json
sast import-feed nvdcve.json --package-map cpe-map.json -o advisories.json

# Refresh the embedded vulnerability data
sast fetch-feeds --ecosystems Packagist Maven npm PyPI Go NuGet
```

Polyglot projects are handled in one pass: every language present is scanned,
and frameworks are detected from module manifests anywhere in the tree, so a
monorepo resolves Laravel and Spring Boot per module rather than reporting
everything as raw.

## How it works

1. Detect language and framework from manifests and source annotations.
2. Parse every source file with tree-sitter.
3. Index functions, classes and methods into namespace-aware symbol tables.
4. Track taint from sources through assignments, concatenation and calls
   (interprocedurally) to sinks. Sanitizers neutralize taint; bypassable ones
   downgrade confidence instead of hiding it.
5. Match dependencies against the advisory database and classify each by
   reachability.
6. Emit validated findings with the full trace.

## Project layout

```
sast/
  analysis/    taint engines (PHP, Java, JS hand-written; one generic engine
               driven by language profiles for the rest), plus secrets, IaC,
               container, template and memory-safety scanners
  advisory/    offline DB, semver, manifest parsing, feed importers
  detection/   language + framework auto-detection
  parsing/     tree-sitter parsers for all eight languages
  reporting/   HTML, JSON, SARIF renderers
  rules/       declarative rule model + per-language rule sets
  data/        bundled advisory seed databases
  web/         browser interface (sast server)
  engine.py    orchestration
  cli.py       command-line interface
examples/      vulnerable fixtures (raw-php, laravel-app, symfony-app,
               spring-app, express-app, react-app, angular-app)
tests/         unittest suite
```

## Extending

Rules are declarative. Add a `SinkRule`, `TaintSource`, `SanitizerRule` or
`PatternRule` to `sast/rules/php_rules.py`, `java_rules.py` or `js_rules.py`
and it is picked up automatically. A new language for the generic engine is a
profile plus a rule set. Advisory entries go in `sast/data/advisories/seed.json`
(Packagist), `seed-java.json` (Maven `groupId:artifactId`) or `seed-npm.json`
(npm package name).

## What it does not find

The limits are documented rather than hidden:

- Access control, authorization and business logic (OWASP A01/A04) are not
  expressible as source-to-sink and are out of scope by construction.
- Context-sensitive escaping: `htmlspecialchars()` is treated as sound for XSS
  (PHP 8.1 escapes quotes by default), but not inside `<script>` or an
  unquoted attribute.
- Maven transitive dependencies: commit a `gradle.lockfile` or
  `mvn dependency:tree` output for full coverage.
- PHP variable variables (`$$name`), Vue/Svelte single-file components, and
  dynamic imports are not followed.
- C/C++ analysis is function-local: no pointer or alias analysis, so heap-shape
  bugs beyond the dedicated use-after-free checker are out of reach.
- IaC rules are textual: values computed by a module are not resolved.
- Container images are not unpacked: only the Dockerfile and any SBOM are read.
- Reachability reads first-party code only: it is import and call-site
  evidence, not an exploitability claim.

## Tests

```bash
python -m unittest tests.test_sast -v
```

243 tests, plus a binary smoke test (`make smoke`) that runs the frozen
executable against one vulnerable fixture per engine on both platforms in CI.
