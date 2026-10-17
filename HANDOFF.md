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
* `bench_full.py` — the same scoring with the repository root in scope, which
  is what lets a configured crypto algorithm be resolved.

Correct-code negative controls, cloned alongside the vulnerable apps and just
as important: cJSON, sds and uthash for the C memory-safety checker. Any
change to it should be re-run against those before being believed.

Two measurement traps worth knowing. A per-rule breakdown printed with
`most_common(8)` silently hides rules that *are* firing — that cost an hour
chasing two rules that worked all along. And a probe file that is not valid
source gets error-recovered by tree-sitter in ways that swallow whole
functions: the first Go probe reported 13/24 purely because it had a duplicate
import.

**The probe-by-shape method is what found the Go, C#, PHP and JavaScript
gaps**, and it is the thing to reuse: write one file per language with a
statement for every sink shape the rules claim to cover, assert on line
numbers, and check both directions (must-fire and must-stay-silent). All six
engines have now been probed this way; redo it whenever a rule set grows.

It also surfaced a recurring failure mode worth naming: **a rule that cannot
fire at all.** PHP's `mail()` asked for an `email` tag no source produced, Go's
`ioutil` and `fmt.Fprintf` rules hinted on a receiver those calls never have,
and the JS header rules needed a `header` tag that did not exist. Each looked
complete in the rule file and detected nothing.

`TestRuleSetConsistency` now catches the mechanically detectable half of this
— an unreachable tag, a kind no engine dispatches on, a regex that does not
compile, a rule id used twice — so probes no longer have to rediscover it. It
found three duplicate ids the moment it was written, two of them pre-existing:
`js-nosqli-where` was two rules with one identity (the list held `$where` and
`where`, which collapse when the `$` is stripped), and `js-proto-defaultsdeep`
and `cs-sqli-sqlitecommand` were each declared twice. A report or a suppression
could only ever have meant one of the pair.

**An unsatisfiable `obj_hint` is the half still not covered**, since hints are
matched against receiver text at scan time. That is what hid the Go `ioutil`
and `fmt` rules, and only a probe finds it.

## OWASP Benchmark

| | recall | precision | score (TPR−FPR) |
|---|---|---|---|
| start | 56.6% | 79.4% | 40.9 |
| now, test-code directory only | 89.8% | 74.4% | 56.8 |
| now, repository root in scope | **92.7%** | 75.0% | **59.7** |

The two rows differ because `bench.py` points the scanner at the test-code
directory alone, which isolates the taint engines but leaves
`src/main/resources` out of scope — so a configured crypto algorithm cannot be
resolved. Scanning the repository root is the realistic case; `bench_full.py`
does that.

Per category (repository root): crypto 100%, hash 100%, weakrand 100%, sqli
93.8%, xpathi 93.3%, securecookie 91.7%, cmdi 91.3%, ldapi 88.9%, pathtraver
88.7%, trustbound 84.3%, xss 83.3%.

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
* **Only one declaration per bare name was ever analysed, in all four
  engines.** Each builds a symbol table keyed by name for *resolution* and
  then uses the same table to drive analysis, so a second declaration sharing
  a name was skipped outright: a `static` helper called `init` in several C
  files, two JavaScript modules exporting `handle` (module scoping is
  deliberately ignored, so this is the normal case), an unnamespaced PHP
  `handle()`, a second Java class called `Test`, and every Java method
  overload past the first. Each table now keeps an `all_*` list beside the
  keyed dicts. This changed nothing on any of the sixteen apps or on
  Benchmark — every one of them declares its sinks in uniquely named classes,
  which is exactly why it went unnoticed — but it gained findings in C#,
  Python and C, and the four new tests pin it per engine.
* **Arithmetic dropped all taint**, so `malloc(w * h)` was invisible while
  `malloc(w + h)` was found, purely because `+` doubles as string
  concatenation. Arithmetic now keeps the tags a language declares numeric and
  drops the rest: a quotient is not a string an attacker controls, but it is a
  number an attacker influences.

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

### New analyses

* **Use-after-free and double-free for C and C++** (`memory_safety.py`). The
  dominant C vulnerability class, and no taint path reaches it. Per function
  it holds ALLOCATED / FREED / MAYBE-FREED per local pointer; a use while
  FREED reports with high confidence, one while MAYBE with medium. Assigning
  or NULLing the pointer clears the state, so the recommended
  `free(p); p = NULL;` idiom is never reported. Direct aliasing is tracked;
  realloc marks its old pointer freed. A function containing a `goto` is
  skipped, because the order statements appear in is then not the order they
  run in. **Validated against 221 files of correct C** (cJSON, sds, uthash):
  zero findings. Out of scope by design, each needing an alias analysis to
  stay sound: crossing function boundaries, loop iterations, and pointers
  inside struct fields or array elements.
* **Attacker-influenced array indexing** (CWE-129), via a new `index` sink
  kind that fires on both reads and writes. Limited to fixed-size arrays; see
  the open items for why heap pointers need more than this.
* **Crypto algorithms chosen in configuration.** `load_properties` reads every
  `.properties` file under the scan root, keeping a key only when every file
  defining it agrees. `const_eval` resolves `props.getProperty("key")` (with
  the call's own default when the key is absent), and a `getInstance` check
  folds the argument to decide whether the algorithm is weak. The
  `.properties` files are also scanned on their own, so the configured value
  is reported at the line a developer has to change.

### New rules

Java: the rest of Spring's `JdbcTemplate` surface and JDBC batching;
`printf`/`format` on the response writer; `ProcessBuilder.command`; the request
accessors that expose parameter and header *names*; Commons Codec Base64
propagators; `java-trustbound-*` on any argument rather than the first.

Python: `http.server` handler attributes gated on the base class; the WSGI
`environ`; `xpath()`; raw-response writes; `send_header`.

Go: `ioutil` file operations; the `fmt.Fprint*` family (the writer is the first
argument, not the receiver); `Header.Set`/`Add`.

PHP: the `call_user_func` family and a call through a variable holding a
tainted name; `create_function`; `scandir`/`opendir`/`glob`; `preg_replace`
with the /e modifier; variable variables; and `mail()`, which had a rule but
no tag that could satisfy it.

JavaScript: the server-response sinks, which were missing entirely —
`res.send` is the most common sink in an Express application — plus
`res.render` (attacker-chosen template), `res.setHeader`, jsonp, cookies,
`spawn`'s argument array, and prototype pollution through `Object.assign`.
`SinkRule.arg_shape` keeps the response rules to string-shaped arguments,
since Express sends an object or array as JSON and a browser never renders
that as HTML.

C#: `Request["key"]` (the WebForms indexer, which has no member name and was
entirely invisible); the ADO.NET execute methods as receiver-tainted sinks;
`CommandText` as a property sink; the provider-specific command and adapter
classes where only the prefix differs (`MySqlCommand` and the rest); XPath,
stream-constructor and `MapPath` path sinks; header injection; unsafe
reflection.

## App results

BenchmarkJava 2257, DVWA 60, dvws-node 59, OpenDoor 58,
Damn_Vulnerable_C_Program 57, pygoat 43, WebGoat.NET 38,
Vulnerable-Web-Application 29, NodeGoat 18, dvna 18, DSVW 17, govwa 15,
Tiredful-API 12, nodejs-goof 11, railsgoat 10.

DSVW went 3 → 17 and now covers its documented SQLi, pickle RCE, path
traversal, command injection, XXE, XPath injection, `exec`, SSTI, raw XSS and
header injection. WebGoat.NET 22 → 30 with its SQL injection found. govwa
gained Go SQL injection traced through its `(p *Profile)` methods.
`Damn_Vulnerable_C_Program` 0 → 57, covering its documented heap overflows,
integer-overflow allocations, path traversal, double-free, use-after-free and
out-of-bounds indexing.

## Still open, highest value first

1. **Benchmark's remaining 437 false positives are mostly synthetic, and
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
2. **Out-of-bounds indexing on heap pointers.** `c-oob-index` reports an
   attacker-influenced index into a *fixed-size* array only. Extending it to
   heap pointers needs the index expression compared numerically against the
   allocation's: `malloc(n + 3)` with `buf[n + 1]` is correct and
   `malloc(n)` with `buf[n]` is off by one, and without that comparison the
   rule found 5 false positives in cJSON and 1 in sds against 10 real ones.
   An interval or offset analysis would close it; a heuristic will not.
   Memory leak and divide-by-zero are the other two C classes left, both
   lower value: a leak needs escape analysis to avoid reporting every pointer
   handed to a struct, and a divide-by-zero on a validated input is noise.
3. **A Benchmark lesson worth not relearning.** I pinned `Runtime.exec` to its
   first argument, reasoning that the environment array and working directory
   are not the command. Ground truth disagreed and it is right: an attacker
   who controls envp controls execution through LD_PRELOAD, IFS, PATH or
   BASH_ENV. Reverted, with the reasoning recorded at the rule.
4. Longer-standing, unchanged: suppression/baseline support; SARIF relative
   paths and `partialFingerprints`; dependency CVEs missing from SARIF output.

## State of the tree

`python3 -m unittest tests.test_sast` — 243 tests, all passing. 52 of them are
new and cover every shape this work fixed: the Python propagation shapes, the
C parameter and out-parameter handling, the Java constant folding in both
directions, the Go and C# probe shapes, configured crypto, finding
deduplication, numeric taint through arithmetic, same-named functions in
separate files, the PHP and JavaScript probe shapes, and the memory-safety
checker including its negative cases, plus the rule-set consistency checks.

I checked these actually fail without the fixes rather than trusting that they
passed: reverting the Go parameter binding and the Java braceless-branch walk
fails three of them.
