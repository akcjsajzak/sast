# SAST — offline framework-aware static analysis for PHP & Java

A fully offline, dependency-free-at-runtime static application security testing
(SAST) engine targeting **PHP** (Laravel, Symfony, raw) and **Java** (Spring,
Spring Boot, raw). It auto-detects the framework, performs interprocedural
**source-to-sink taint analysis**, and reports validated findings as HTML,
JSON, or **SARIF**.

Think of it as an offline, framework-aware Snyk / SonarQube.

## Features

- **Framework auto-detection** — `composer.json` → Laravel / Symfony;
  `pom.xml` / `build.gradle` + Spring annotations → Spring / Spring Boot.
- **Source-to-sink taint analysis** — interprocedural, sanitizer-aware, with a
  full trace (source → intermediate hops → sink) and code citations.
- **OWASP Top 10 + framework/dependency-specific rules**:
  - SQL injection (raw `mysqli`/PDO, Laravel `DB::raw`/`whereRaw`, Doctrine DQL,
    JDBC/JPA/JdbcTemplate)
  - XSS (echo/print, Blade `{!! !!}`, Servlet response writer)
  - Command injection, SSRF, path traversal/LFI, insecure deserialization,
    XXE, LDAP injection, open redirect, SpEL injection, mass assignment,
    CSRF/authorization misconfig, weak crypto.
- **Dependency vulnerability scanning** — matches `composer.lock`,
  `pom.xml`/`build.gradle` against a bundled offline advisory DB with semantic
  version ranges; import OSV, NVD (1.1 & 2.0), or a custom JSON feed.
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
```

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

# Use an extra advisory DB
sast scan /path/to/project --advisory-db my-advisories.json
```

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
2. **Parse** every source file with tree-sitter (PHP & Java grammars).
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
  analysis/    AST utils, symbol tables, taint engines (PHP + Java)
  advisory/    offline DB, semver, composer/maven parsing, feed importers
  detection/   language + framework auto-detection
  parsing/     tree-sitter PHP/Java parsers
  reporting/   HTML, JSON, SARIF renderers
  rules/       declarative rule model + PHP/Java rule sets
  data/        bundled advisory seed databases
  engine.py    orchestration
  cli.py       command-line interface
examples/      vulnerable fixtures (raw-php, laravel-app, symfony-app, spring-app)
tests/         unittest suite
```

## Extending

Rules are declarative. Add a `SinkRule`, `TaintSource`, `SanitizerRule`, or
`PatternRule` to `sast/rules/php_rules.py` or `sast/rules/java_rules.py` and it
is picked up automatically. Add advisory entries to
`sast/data/advisories/seed.json` (Packagist) or `seed-java.json` (Maven
`groupId:artifactId`).

## Tests

```bash
python -m unittest tests.test_sast -v
```

## Limitations

- Vendor/third-party code is modeled via rules rather than parsed; only
  first-party source is scanned.
- Java interprocedural analysis resolves `this`/implicit and type-inferred
  local receivers; arbitrary framework call graphs are modeled by rules.
- Blade templates are analyzed by a dedicated unescaped-output (`{!! !!}`)
  scanner, not full template taint.
