# Handoff — false-negative sweep against known-vulnerable apps

Work in progress on branch `claude/tender-lamport-ixu34k`. The engine went from
56.6% to 89.8% recall on OWASP Benchmark with precision roughly held, and the
Go, C#, Python and C/C++ engines each had structural taint losses fixed. The
remaining work is at the bottom, in the order worth doing.

## How this was measured

Vulnerable apps were cloned into a scratch directory (not committed):
BenchmarkJava, DVWA, Vulnerable-Web-Application, DSVW, pygoat, Tiredful-API,
OpenDoor, NodeGoat, dvna, dvws-node, nodejs-goof, govwa, WebGoat.NET,
Damn_Vulnerable_C_Program, railsgoat.

Throwaway harnesses, deliberately not committed — recreate from this recipe:

* `bench.py` — scans the Benchmark test code and scores it against
  `expectedresults-1.2.csv` (recall, precision, specificity, TPR−FPR).
* `fn3.py` — differential attribution: for each category, the call APIs that
  appear in *missed* tests but not in *found* ones. This turned "178 XSS
  misses" into "`printf`/`format` are not sinks, `getParameterNames` is not a
  source".
* `fpsrc.py` — the inverse for false positives, grouped by the trace the
  engine actually built. Guessing from the generator's comments stopped
  working once several templates co-occurred in one file; the finding's own
  trace is the only attribution that cannot be wrong.
* `apps.py` — scans every app and prints a per-rule breakdown.

Two measurement traps worth knowing. A per-rule breakdown printed with
`most_common(8)` silently hides rules that *are* firing — that cost an hour
chasing two rules that worked all along. And a probe file that is not valid
source gets error-recovered by tree-sitter in ways that swallow whole
functions: the first Go probe reported 13/24 purely because it had a duplicate
import.

**The probe-by-shape method is what found the Go and C# gaps**, and it is the
thing to reuse: write one file per language with a statement for every sink
shape the rules claim to cover, assert on line numbers, and check both
directions (must-fire and must-stay-silent).

## OWASP Benchmark

| | recall | precision | specificity | score (TPR−FPR) |
|---|---|---|---|---|
| start | 56.6% | 79.4% | 84.3% | 40.9 |
| now | **89.8%** | 74.4% | 67.0% | **56.8** |

Per category: crypto 100%, weakrand 100%, xpathi 93.3%, sqli 93.8%, cmdi
91.3%, securecookie 91.7%, ldapi 88.9%, pathtraver 88.7%, trustbound 84.3%,
xss 83.3%, hash 69.0%.

## What was fixed

### Taint being dropped silently

* **Braceless Java branch bodies were skipped outright.** `handle_if` and
  `handle_loop` recursed only into children typed `block` or `statement`, and
  a braceless body is the bare statement node. `if (values != null) param =
  values[0];` is the last line of the Benchmark's whole `getParameterMap`
  shape, so those flows all stopped at a null guard.
* **A Java switch was never processed as a statement at all**, falling through
  to the expression fallback, which reads children for taint but never writes
  the environment. `case 'A': bar = param;` did not taint and `case 'B': bar =
  "safe";` did not clear. Both directions wrong.
* **A Java constructor returned no taint**, so `new String(bytes)`,
  `new StringBuilder(s)` and `new File(path)` lost it; a Base64 round trip
  looked like sanitising.
* **`strip` took the wrong child of a cast.** `(char *)malloc(n)` became
  `char *` and `[]byte(q)` became `[]byte`. Grammars disagree on the field
  name (`value`, `operand`), so it now tries the ones they use.
* **A non-concatenation binary operator returned before evaluating its
  operands**, hiding every sink inside a condition: `while (fread(&buf, ...) >
  0)`, `if (system(cmd) == 0)`.
* **C/C++ functions bound no parameters** — the parameter list hangs off the
  declarator and the name sits inside a `pointer_declarator` — so no taint
  crossed any C call. `Damn_Vulnerable_C_Program` reported 0 findings.
* **Go methods bound their receiver in place of their parameters**, because a
  Go method declaration carries its receiver in a `parameter_list` too and the
  receiver comes first.
* **A C# generic call lost its name**: `ser.Deserialize<object>(x)` matched as
  "Deserialize<object>", hiding most of the JSON and EF Core surface.
* **A bodiless interface declaration shadowed the real implementation** in the
  symbol table, and one implementation was indexed per bare name, so
  WebGoat.NET's SQL layer resolved to a stub provider.
* `x = y = value` left every target but the innermost one clean.

### Precision

* **Constant folding.** A decidable condition has one live arm, and merging
  both is what let a constant assignment be overwritten by taint from a branch
  that never runs. `const_eval` folds integer and boolean arithmetic,
  comparisons, bitwise ops, string concatenation and equality, and the pure
  String methods (`"ABC".charAt(1)` is how a switch label gets picked), with
  Java's own 32-bit wraparound and toward-zero division. if, ternary and
  switch each walk only the live arm when the condition folds. Anything
  undecidable stays UNKNOWN and every arm is walked as before, so folding
  cannot hide a flow, and the constant join drops a value introduced, changed
  or discarded inside a branch.
* **One finding per rule and location.** Every engine keyed dedup on the taint
  source too, so a sink reached from several sources was reported once per
  source. Verified on govwa: 14 distinct locations before and after.
* `System.getProperty` no longer claims the JVM's own properties as request
  data (new `TaintSource.arg_not_literal`); a source's confidence was being
  dropped on the floor in the Java engine; `getRequestURL` and the rest of the
  request's own address no longer carry the `ssrf` tag.

### New rule-model capabilities

`TaintSource.out_args` / `out_only` (C fills a caller-supplied buffer and
returns a count), `TaintSource.file_requires` (a regex the file must contain,
so `self.path` is a source only in an `http.server` handler),
`TaintSource.arg_not_literal`, and `SinkRule.receiver_tainted` (for sinks
dangerous because of what they are called on — `untrusted.format(x)`,
`cmd.ExecuteReader()`).

### New rules

Java: the rest of Spring's `JdbcTemplate` surface and JDBC batching;
`printf`/`format` on the response writer; `ProcessBuilder.command`; the request
accessors that expose parameter and header *names*; Commons Codec Base64
propagators; `java-trustbound-*` on any argument rather than the first.

Python: `http.server` handler attributes gated on the base class; the WSGI
`environ`; `xpath()`; raw-response writes; `send_header`.

Go: `ioutil` file operations; the `fmt.Fprint*` family (the writer is the first
argument, not the receiver); `Header.Set`/`Add`.

C#: `Request["key"]` (the WebForms indexer, which has no member name and was
entirely invisible); the ADO.NET execute methods as receiver-tainted sinks;
`CommandText` as a property sink; the provider-specific command and adapter
classes where only the prefix differs (`MySqlCommand` and the rest); XPath,
stream-constructor and `MapPath` path sinks; header injection; unsafe
reflection.

## App results

BenchmarkJava 2182, DVWA 60, dvws-node 53, OpenDoor 55, pygoat 42,
WebGoat.NET 30, Vulnerable-Web-Application 29, NodeGoat 18, dvna 18, DSVW 17,
govwa 15, Tiredful-API 12, nodejs-goof 11, railsgoat 10,
Damn_Vulnerable_C_Program 5.

DSVW went 3 → 17 and now covers its documented SQLi, pickle RCE, path
traversal, command injection, XXE, XPath injection, `exec`, SSTI, raw XSS and
header injection. WebGoat.NET 22 → 30 with its SQL injection found. govwa
gained Go SQL injection traced through its `(p *Profile)` methods.
`Damn_Vulnerable_C_Program` 0 → 5.

## Still open, highest value first

1. **`hash` is stuck at 69%, and the reason is now known.** All 236 hash and
   crypto tests read the algorithm from a variable; the only thing separating
   vulnerable from safe is which properties key is used
   (`hashAlg1=MD5` vs `hashAlg2=SHA-256` in `benchmark.properties`). crypto
   reaches 100% only because its weak algorithm happens to appear as the
   literal default in the source. Fixing hash means **resolving a properties
   lookup against the config files in the repo** and feeding the result into
   `const_eval` — worth building, because weak crypto configured in a
   properties file is a real pattern no amount of taint analysis finds. Do not
   instead flag every non-literal algorithm: that would gain 40 true positives
   and add 107 false ones.
2. **C/C++ memory safety is not modelled at all.** The engine finds the
   taint-driven classes in `Damn_Vulnerable_C_Program` (heap overflow via
   `memcpy`, path traversal, integer-overflow `malloc`) but not the local
   state classes it is mostly made of: use-after-free, double free,
   out-of-bounds index, divide by zero, memory leak. Those need an
   intra-procedural alloc/free state tracker, not taint.
3. **Benchmark's remaining 437 false positives are mostly synthetic, and
   chasing them would make the tool worse on real code.** Partitioned: 24% is
   list index arithmetic (`valuesList.remove(0)` then `get(1)`, so `get(1)`
   returns the safe element), 11% a StringBuilder slice that drops the tainted
   part, 16% a map literal-key pick (`put("keyB", param)` then
   `get("keyA")`). Element-level precision on a collection is unsound in
   general — any dynamic index, alias or loop breaks it, and `get(1)` on a
   list the attacker partly controls is tainted in any realistic program. The
   map case is the one defensible piece: taint per *literal* map key, falling
   back to whole-container taint the moment a dynamic key or an escape appears.
   That is worth about 75 of the 437.
4. **Record what the probes proved.** The shapes now working are not covered
   by `tests/test_sast.py`: Python tuple unpacking, `dict(genexp)`,
   comprehensions, for-loop binding, f-strings, chained assignment; the Java
   constant-folding cases in both directions; the Go and C# probe files. These
   are the regression tests this work most needs and the cheapest thing left
   to do.
5. **A Benchmark lesson worth not relearning.** I pinned `Runtime.exec` to its
   first argument, reasoning that the environment array and working directory
   are not the command. Ground truth disagreed and it is right: an attacker
   who controls envp controls execution through LD_PRELOAD, IFS, PATH or
   BASH_ENV. Reverted, with the reasoning recorded at the rule.
6. Longer-standing, unchanged: suppression/baseline support; SARIF relative
   paths and `partialFingerprints`; dependency CVEs missing from SARIF output.

## State of the tree

`python3 -m unittest tests.test_sast` — 191 tests, all passing. No new tests
were added for this run's fixes; item 4 says which shapes deserve them.
