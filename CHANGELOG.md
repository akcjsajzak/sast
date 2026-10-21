# Changelog

Release notes for each tagged version. The release workflow publishes the
section matching the tag as the GitHub release description, so every tag
needs an entry here.

## 1.1.0

- **Accepting a finding.** Inline `sast:ignore` / `sast:ignore-next-line`
  comments, which may name rules and carry a reason, and a baseline file
  written by `sast baseline` so `--fail-on` gates on new findings only.
  Accepted findings stay in the reports, marked and explained, rather than
  disappearing; both mechanisms are keyed on fingerprints that survive code
  moving.
- **SARIF fidelity.** Repository-relative paths under `%SRCROOT%`,
  `partialFingerprints` on every result, explanations on trace steps,
  vulnerable dependencies reported as results located at their manifest, and
  suppressions expressed in SARIF's own model.
- **Per-language engine isolation.** A stage that crashes no longer ends the
  whole scan: every other language and sweep still reports, the failure is
  named in the summary, the JSON and HTML reports and the SARIF invocation,
  and the command exits non-zero because the run is incomplete.

## 1.0.0

First stable release: an offline, single-binary scanner for code,
dependencies, secrets, infrastructure as code and containers.

- **Taint analysis in eight languages**, framework-aware: PHP (Laravel,
  Symfony), Java (Spring, Jakarta EE), JavaScript/TypeScript (Express, Koa,
  NestJS, React, Angular, Next.js, Vue), Python (Django, Flask, FastAPI,
  GraphQL resolvers), Go (net/http, Gin, Echo, Fiber, Gorilla), C# (ASP.NET)
  and C/C++, with full source-to-sink traces.
- **Attack surface mapping.** Routes are extracted per framework, findings are
  tied to the request that reaches them, and each comes with a request
  skeleton. `--audit` adds IDOR and missing-authorisation candidates.
- **Dependency scanning with reachability.** Embedded OSV advisories for
  Packagist, Maven, npm, PyPI, Go and NuGet; findings are ranked by whether
  your code calls, imports or never uses the vulnerable package.
- **Secrets, IaC, containers, templates and configuration** in the same pass.
- **Reports** in HTML (with triage marking), JSON and SARIF, plus `--fail-on`
  severity gating for CI.
- **Web interface** (`sast server`) with scan history, a bounded scan queue,
  ZIP and git sources, and a code browser with syntax highlighting that opens
  each finding at its line.
- Validated against OWASP Benchmark (score 56.8) and more than twenty
  deliberately vulnerable applications, including Juice Shop, WebGoat, DVWA,
  bWAPP, Mutillidae, NodeGoat, pygoat, DVGA and VulnerableApp.
