# Changelog

Release notes for each tagged version. The release workflow publishes the
section matching the tag as the GitHub release description, so every tag
needs an entry here.

## 1.1.0

Also in this release, from scanning twenty widely-used projects that are not
deliberately vulnerable (curl, redis, Laravel, composer, phpMyAdmin,
Newtonsoft.Json, Vue, FastAPI and others). None crashed; what they exposed
was precision, and the total fell from 1844 findings to 1453 with no change
on the vulnerable corpora or the OWASP Benchmark:

- **C memory safety** misread the ordinary way C grows a buffer. Freeing
  `x->f` marked the whole struct, so every later read of any other field was
  a use after free; `v[i]` freed the array rather than the element; writing
  the fresh block back (`ab->b = new;`) counted as a use; and a `free` on a
  branch that returns was carried past the `if` it could not escape. Writing
  to an lvalue now rebinds it, with only the pointers dereferenced on the way
  counted as uses. curl 196 -> 110 findings, redis 462 -> 387.
- **Array bounds leaked between files.** `char table[256]` in one file was
  cited as the bound for `ht->table[h]` in another. Sizes are scoped to the
  file that declares them, and an indexed field is no longer attributed to
  the variable it hangs off.
- **`assert()` in PHP** only evaluates a string. Matching the call itself
  reported every `assert($x instanceof Y)` — 108 across composer and
  phpMyAdmin. The pattern now requires the string form, and a tainted
  argument is caught by a sink instead.
- **Test code was only recognised by Java and PHP conventions.** `Foo.Tests/`,
  `UnitTests/`, `FooTest.cs` and `parser_test.cc` were all scanned as
  application code: 708 of Newtonsoft.Json's 950 files were its test suite.

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
