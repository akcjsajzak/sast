# Handoff — false-negative sweep against known-vulnerable apps

Work in progress on branch `claude/tender-lamport-ixu34k`. This run took the
engine from 56.6% to 88.2% recall on OWASP Benchmark and fixed structural taint
losses in the Python, C/C++ and Java engines. The remaining work is listed at
the bottom, roughly in the order worth doing.

## How this was measured

Vulnerable apps were cloned into a scratch directory (not committed):
BenchmarkJava, DVWA, Vulnerable-Web-Application, DSVW, pygoat, Tiredful-API,
OpenDoor, NodeGoat, dvna, dvws-node, nodejs-goof, govwa,
Damn_Vulnerable_C_Program, railsgoat.

Three throwaway harnesses drove it:

* `bench.py` — scans the Benchmark test code and scores it against
  `expectedresults-1.2.csv` (recall, precision, specificity, TPR−FPR).
* `fn3.py` — differential attribution: for each category, the call APIs that
  appear in *missed* tests but not in *found* ones. This is what turned "178
  XSS misses" into "`printf`/`format` are not sinks and `getParameterNames` is
  not a source".
* `apps.py` — scans every app and prints a per-rule breakdown.

They were deliberately left out of the repo; recreate them from the recipe
above if the measurement needs repeating. Note that a per-rule breakdown
printed with `most_common(8)` will silently hide rules that *are* firing — that
cost an hour of chasing two rules that worked all along.

## OWASP Benchmark, before and after

| | recall | precision | specificity | score (TPR−FPR) |
|---|---|---|---|---|
| start of run | 56.6% | 79.4% | 84.3% | 40.9 |
| now | **88.2%** | 71.4% | 62.3% | **50.5** |

Per category now: crypto 100%, weakrand 100%, xpathi 93.3%, cmdi 91.3%,
securecookie 91.7%, sqli 90.4%, ldapi 88.9%, pathtraver 85.7%, trustbound
83.1%, xss 79.7%, hash 69.0%.

**The precision drop is the main thing to look at next.** Benchmark pairs each
true positive with a sibling that routes the same value through a real
sanitizer. Reaching more sinks therefore surfaces the sanitizers the engine
does not yet model, and those show up as false positives rather than as
anything newly wrong. 499 FPs against 1248 TPs.

## What was fixed

### Engine bugs (these were losing taint silently)

* `java_dataflow.handle_if` / `handle_loop` only recursed into children typed
  `block` or `statement`. A braceless branch body is the bare statement node,
  so `if (values != null) param = values[0];` was skipped entirely. The
  Benchmark's whole `getParameterMap` source shape ends in that line, which is
  why so many flows stopped at a null guard. `handle_loop` now also excludes
  the for/foreach *header* children so the element binding is not clobbered.
* `java_dataflow` `object_creation_expression` returned `None`, so wrapping a
  value in any object dropped it: `new String(bytes)`, `new StringBuilder(s)`,
  `new File(path)`. A Base64 round trip looked like sanitising. Now propagates
  its arguments.
* `generic_dataflow.strip` took the *first* child of a transparent node, so a
  cast became its type: `(char *)malloc(n)` lost the call. It now prefers the
  grammar's `value` field. In C, where casting a malloc is the norm, this alone
  hid the sink.
* `generic_dataflow.taint_of` returned early for a binary expression whose
  operator is not a concatenation, without evaluating the operands. Every sink
  inside a condition was invisible: `while (fread(&buf, ...) > 0)`,
  `if (system(cmd) == 0)`. Operands are now evaluated; the comparison's own
  result still carries no taint. The ternary condition is likewise evaluated
  for its sinks.
* `generic_dataflow.build_symbols` found no formal parameters for C/C++,
  because the `parameter_list` hangs off the declarator rather than the
  function node, and a name sits inside a `pointer_declarator`. Every C
  function was recorded with no parameters, so no taint could cross a call.
  `Damn_Vulnerable_C_Program` reported 0 findings before this.
* `generic_dataflow.handle_assignment` evaluated `x = y = value` as an
  expression, leaving every target but the innermost clean.

### New rule-model capabilities

* `TaintSource.out_args` / `out_only` — C reads input by handing a function
  somewhere to write, so the interesting value is never the return:
  `fread(&img, ...)`, `recv(fd, buf, ...)`, `scanf("%d", &n)`. The C rule set
  now declares the out-parameter positions per function (`_INPUT_FUNCTIONS`),
  and `out_only` keeps a byte count from being taken for attacker data.
* `TaintSource.file_requires` — a regex the file must contain. Lets
  `self.path` be a source in an `http.server` handler without tainting every
  `.path` attribute in every codebase.
* `SinkRule.receiver_tainted` — fires on taint in the receiver rather than an
  argument. `untrusted.format(x)` can walk attributes out of `x`; `"lit
  {}".format(untrusted)` is ordinary formatting, so checking the arguments
  would invert the rule.

### New rules

* Java sources: `getParameterNames`, `getHeaderNames`, `getAttributeNames`,
  `getPathInfo`, `getRequestURI/URL`, `getServletPath`, `getRemote*`,
  `getAuthType`, `getContentType`, `getCharacterEncoding`, `getPart(s)`.
* Java sinks: the rest of Spring's `JdbcTemplate` surface
  (`queryForRowSet/Map/Long/Int/Stream`, `batchUpdate`) and JDBC batching
  (`addBatch`, `executeBatch`); `printf`/`format` on the response writer;
  `ProcessBuilder.command`/`directory`. `java-trustbound-*` moved from
  `arg_index=0` to any argument — it was missing every
  `putValue("userid", param)`.
* Java propagators: the Commons Codec Base64/Hex statics.
* Python sources: `http.server` handler attributes (`self.path`, `headers`,
  `rfile`, `requestline`, `client_address`), gated on the file naming a handler
  base class; the WSGI `environ`.
* Python sinks: `xpath()`; `wfile.write` (raw-response XSS); `send_header`
  (response splitting / open redirect); `str.format` SSTI via
  `receiver_tainted`.

## App results now

BenchmarkJava 2617, DVWA 63, OpenDoor 82, dvws-node 53, pygoat 42,
Vulnerable-Web-Application 29, NodeGoat 18, dvna 18, DSVW 17, Tiredful-API 12,
govwa 11, nodejs-goof 11, railsgoat 10, Damn_Vulnerable_C_Program 6.

DSVW went 3 → 17 and now covers its documented SQLi, pickle RCE, path
traversal, command injection, XXE, XPath injection, `exec`, SSTI, raw XSS and
header injection. `Damn_Vulnerable_C_Program` went 0 → 6.

## Still open, highest value first

1. **Recover the precision.** 499 Benchmark FPs, concentrated in cmdi
   (specificity 24%), xpathi (25%), trustbound (30%), sqli (34%) and
   pathtraver (35%). Benchmark's sanitized siblings name the escaping APIs;
   run `fn3.py` inverted (APIs common in *false positives* but not in true
   ones) to get the list, then add them as `SanitizerRule`s. Expect this to be
   mostly ESAPI, `HtmlUtils`, and the validator/allow-list helpers in
   `org.owasp.benchmark.helpers`.
2. **`hash` is stuck at 69%** and was not touched this run. 40 misses, all
   attributed to `String` by the crude attribution — re-run `fn3.py` on just
   that category.
3. **C/C++ memory safety is not modelled at all.** The engine finds the
   taint-driven classes in `Damn_Vulnerable_C_Program` (3 × heap overflow via
   `memcpy`, path traversal, integer-overflow `malloc`) but not the local
   state classes it is mostly made of: use-after-free, double free,
   out-of-bounds index, divide by zero, memory leak, stack exhaustion. Those
   need an intra-procedural free/alloc state tracker, not taint. A C scanner
   without use-after-free has a visible hole.
4. **Go recall is unmeasured and looks low.** govwa reports 11 findings
   (2 SQLi, 3 weak hash, 1 XSS) against an app documenting many more. Run the
   same probe-by-shape method on the Go engine as was done for Java and
   Python — write a probe file with one flow shape per sink and see which
   shapes fail.
5. **C# is entirely unmeasured.** No C# vulnerable app was successfully
   cloned. Try `OWASP/WebGoat.NET` or `Cyber-Buddy/BadNetCore`.
6. **`py-ssti-format` may be too noisy.** 19 hits in OpenDoor, a CLI tool
   where `sys.argv` legitimately reaches `.format`. Check a sample; consider
   dropping it to low severity or requiring a high-confidence source.
7. **Python probe gaps that passed** are worth keeping as regression tests —
   tuple unpacking, `dict(genexp)`, comprehensions, for-loop binding,
   f-strings and chained assignment all work now and none are covered by
   `tests/test_sast.py`.
8. Longer-standing items, unchanged: suppression/baseline support; SARIF
   relative paths and `partialFingerprints`; dependency CVEs are missing from
   SARIF output.

## State of the tree

`python3 -m unittest tests.test_sast` — 191 tests, all passing. No new tests
were added for this run's fixes; items 7 above says which shapes deserve them.
