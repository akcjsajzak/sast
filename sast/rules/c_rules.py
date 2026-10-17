"""C and C++ rule set, focused on memory safety.

C and C++ differ from the managed languages: the dominant vulnerability class
is memory corruption, and several library functions are unsafe *regardless* of
whether their input is attacker-controlled (`gets()` cannot be used safely at
all). Those are expressed as sinks with no taint tags, which the generic engine
reports on sight.
"""
from __future__ import annotations

from .base import RuleSet, TaintSource, SinkRule, SanitizerRule, PatternRule

A01 = "A01:2021 — Broken Access Control"
A02 = "A02:2021 — Cryptographic Failures"
A03 = "A03:2021 — Injection"
A05 = "A05:2021 — Security Misconfiguration"

_ALL = ["buffer", "cmd", "fmt", "path", "lfi", "sql", "code", "int"]
_BUF = ["buffer"]


# Which argument each input function fills in, and whether its return value
# is data or just a count. C hands a function somewhere to write rather than
# returning the bytes, so a source rule that only tainted the return value
# described the wrong expression entirely. `_VARARG_TAIL` covers the scanf
# family, whose conversion targets run to the end of the call; indices past
# the end of a given call are ignored.
_VARARG_TAIL = tuple(range(1, 12))
_INPUT_FUNCTIONS = {
    # name:        (out_args,                      return is data)
    "getenv":      ((),                            True),
    "gets":        ((0,),                          True),
    "fgets":       ((0,),                          True),
    "readline":    ((),                            True),
    "getline":     ((0,),                          False),
    "read":        ((1,),                           False),
    "recv":        ((1,),                           False),
    "recvfrom":    ((1,),                           False),
    "fread":       ((0,),                           False),
    "scanf":       (_VARARG_TAIL,                  False),
    "fscanf":      (tuple(range(2, 12)),           False),
    "sscanf":      (tuple(range(2, 12)),           False),
}


def _sources() -> list[TaintSource]:
    s: list[TaintSource] = []
    for fn, (out_args, returns_data) in _INPUT_FUNCTIONS.items():
        s.append(TaintSource(
            kind="call", match=fn, tags=_ALL,
            description=f"Untrusted input read via {fn}()",
            out_args=out_args or None,
            out_only=bool(out_args) and not returns_data,
        ))
    s.append(TaintSource(
        kind="identifier", match="argv", tags=_ALL,
        description="Untrusted data from command-line arguments (argv)",
    ))
    for m in ("c_str", "data", "str"):
        s.append(TaintSource(
            kind="call", match=m, tags=_ALL, confidence="low",
            description=f"Buffer obtained via {m}() — tainted if its source is",
        ))
    return s


def _sinks() -> list[SinkRule]:
    k: list[SinkRule] = []

    def sink(rid, match, title, severity, cwe, category, desc, fix, tags,
             arg_index=-1, owasp=A03, confidence="high"):
        k.append(SinkRule(rule_id=rid, kind="call", match=match, title=title,
                          severity=severity, cwe=cwe, owasp=owasp,
                          category=category, description=desc, remediation=fix,
                          tags=tags, arg_index=arg_index, confidence=confidence))

    # Unconditionally unsafe: no tags, so these are reported on sight.
    sink("c-unsafe-gets", "gets", "Use of gets()", "critical", "CWE-242",
         "buffer-overflow",
         "gets() has no way to limit how much it writes, so the destination "
         "buffer can always be overflowed. It was removed from C11.",
         "Use fgets() with an explicit size, or getline().", [])
    for fn, fix in (("strcpy", "strncpy / strlcpy"), ("strcat", "strncat / strlcat"),
                    ("sprintf", "snprintf"), ("vsprintf", "vsnprintf")):
        sink(f"c-unsafe-{fn}", fn, f"Unbounded string operation: {fn}()",
             "high", "CWE-120", "buffer-overflow",
             f"{fn}() writes without a destination bound, so a longer source "
             "overflows the destination buffer.",
             f"Use {fix} with the destination size, and check truncation.", [])
    for fn in ("alloca",):
        sink(f"c-unsafe-{fn}", fn, "Stack allocation with alloca()", "medium",
             "CWE-770", "resource-exhaustion",
             "alloca() allocates on the stack with no failure path; a large or "
             "attacker-influenced size smashes the stack.",
             "Use malloc()/free(), or a fixed-size buffer.", [])
    sink("c-unsafe-tmpnam", "tmpnam", "Insecure temporary file name", "medium",
         "CWE-377", "insecure-temp-file",
         "tmpnam()/tempnam() return a name, not an open file, leaving a "
         "time-of-check/time-of-use window for a symlink attack.",
         "Use mkstemp(), which creates and opens atomically.", [], owasp=A05)
    sink("c-unsafe-tempnam", "tempnam", "Insecure temporary file name", "medium",
         "CWE-377", "insecure-temp-file",
         "tempnam() leaves a race between name generation and file creation.",
         "Use mkstemp().", [], owasp=A05)

    # Taint-driven: dangerous only with attacker-controlled input.
    for fn in ("system", "popen", "execl", "execlp", "execle", "execv",
               "execvp", "execvpe"):
        sink(f"c-cmdi-{fn}", fn, f"Command injection via {fn}()", "critical",
             "CWE-78", "command-injection",
             f"{fn}() executes a command built from attacker-controlled data.",
             "Use execve() with a fixed program and a validated argument array; "
             "never pass a constructed string to a shell.",
             ["cmd"], arg_index=0)
    for fn in ("printf", "fprintf", "sprintf", "snprintf", "vprintf",
               "vfprintf", "syslog"):
        sink(f"c-fmt-{fn}", fn, f"Format string vulnerability in {fn}()",
             "high", "CWE-134", "format-string",
             "An attacker-controlled format string can read and write arbitrary "
             "memory through %n and %s.",
             'Pass a literal format string: printf("%s", user_input).',
             ["fmt"], arg_index=0)
    for fn in ("memcpy", "memmove", "strncpy", "strncat", "snprintf", "bcopy"):
        sink(f"c-buf-{fn}", fn, f"Attacker-controlled length in {fn}()",
             "high", "CWE-787", "buffer-overflow",
             "The size argument is attacker-controlled, so the copy can run "
             "past the end of the destination.",
             "Clamp the length to the destination's size and validate it.",
             _BUF, arg_index=2, confidence="medium")
    for fn in ("malloc", "calloc", "realloc"):
        sink(f"c-int-{fn}", fn, f"Attacker-controlled allocation size in {fn}()",
             "medium", "CWE-190", "integer-overflow",
             "An attacker-controlled size can overflow the multiplication or "
             "wrap to a small allocation, which a later write then overruns.",
             "Validate the size and check for overflow before allocating.",
             ["int", "buffer"], arg_index=0, confidence="medium")
    for fn in ("fopen", "open", "freopen", "remove", "unlink", "rename"):
        sink(f"c-path-{fn}", fn, f"Path traversal via {fn}()", "high",
             "CWE-22", "path-traversal",
             "An attacker-controlled path allows access outside the intended "
             "directory.",
             "Canonicalise with realpath() and verify the allowed prefix.",
             ["path", "lfi"], arg_index=0, owasp=A01)
    # An attacker-influenced index. C performs no bounds check, so the read
    # or write simply lands outside the buffer; `match` is unused because the
    # engine matches the subscript itself rather than a callee name.
    k.append(SinkRule(
        rule_id="c-oob-index", kind="index", match="*",
        title="Attacker-controlled index into a buffer",
        severity="high", cwe="CWE-129", owasp=A01,
        category="out-of-bounds-access",
        description="The index is derived from attacker-controlled input and "
                    "is not bounds-checked here, so the access can fall "
                    "outside the buffer. A write past the end is memory "
                    "corruption; a read past it discloses adjacent memory.",
        remediation="Reject the index unless it is within the buffer's length, "
                    "and remember that a signed index can also be negative.",
        tags=["int", "buffer"], confidence="medium"))
    sink("c-sqli-exec", "sqlite3_exec", "SQL injection via sqlite3_exec()",
         "high", "CWE-89", "sql-injection",
         "The statement is built from attacker-controlled data.",
         "Use sqlite3_prepare_v2() with bound parameters.",
         ["sql"], arg_index=1)
    sink("c-sqli-query", "mysql_query", "SQL injection via mysql_query()",
         "high", "CWE-89", "sql-injection",
         "The statement is built from attacker-controlled data.",
         "Use prepared statements with bound parameters.",
         ["sql"], arg_index=1)
    return k


def _sanitizers() -> list[SanitizerRule]:
    s: list[SanitizerRule] = []
    for fn in ("atoi", "atol", "atoll", "strtol", "strtoul", "strtod"):
        s.append(SanitizerRule(
            kind="call", match=fn,
            neutralize=["cmd", "fmt", "path", "lfi", "sql", "code"]))
    s.append(SanitizerRule(kind="call", match="basename",
                           neutralize=["path", "lfi"]))
    s.append(SanitizerRule(
        kind="call", match="realpath", neutralize=["path"], weak=True,
        note="realpath() canonicalises a path but does not confine it to a "
             "directory; compare the result against the allowed prefix"))
    return s


def _patterns() -> list[PatternRule]:
    p: list[PatternRule] = []

    def pat(rid, match, title, desc, fix, severity="medium", cwe="", owasp=A05,
            category="security-misconfiguration", node_type="*",
            confidence="high", ignore_case=False):
        p.append(PatternRule(
            rule_id=rid, node_type=node_type, match=match, match_field="text",
            title=title, severity=severity, cwe=cwe, owasp=owasp,
            category=category, description=desc, remediation=fix, regex=True,
            confidence=confidence, ignore_case=ignore_case))

    pat("c-weak-random", r"\b(?:rand|srand|random|drand48)\s*\(",
        "Predictable random number generator",
        "rand() is not cryptographically secure; keys or tokens derived from "
        "it are guessable.",
        "Use getrandom(), /dev/urandom, or a vetted CSPRNG.",
        cwe="CWE-338", owasp=A02, category="weak-random", node_type="call_expression")
    pat("c-weak-hash", r"\b(?:MD5|SHA1)_(?:Init|Update|Final)\s*\(",
        "Weak cryptographic hash (MD5/SHA-1)",
        "MD5 and SHA-1 are broken for signatures and integrity.",
        "Use SHA-256 or better.",
        severity="low", cwe="CWE-328", owasp=A02, category="weak-crypto",
        node_type="call_expression")
    pat("c-strlen-alloc", r"malloc\s*\(\s*strlen\s*\([^)]*\)\s*\)",
        "Allocation misses the NUL terminator",
        "malloc(strlen(s)) allocates one byte too few for a copy of s, so the "
        "terminating NUL is written out of bounds.",
        "Allocate strlen(s) + 1.",
        severity="high", cwe="CWE-787", owasp=A03, category="buffer-overflow")
    pat("c-scanf-unbounded", r"\bscanf\s*\(\s*\"[^\"]*%s",
        "Unbounded %s in scanf()",
        "%s without a width reads an unlimited number of characters into a "
        "fixed buffer.",
        "Specify a maximum field width, e.g. %63s.",
        severity="high", cwe="CWE-120", owasp=A03, category="buffer-overflow")
    pat("c-memcpy-sizeof-src",
        r"memcpy\s*\([^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*sizeof\s*\(\s*\1\s*\)",
        "memcpy sized by the source operand",
        "Sizing a copy by the source rather than the destination overflows the "
        "destination whenever the source is larger.",
        "Size the copy by the destination, and clamp to it.",
        severity="high", cwe="CWE-787", owasp=A03, category="buffer-overflow",
        confidence="medium")
    pat("c-system-constant", r"\bsystem\s*\(",
        "Use of system()",
        "system() invokes a shell, so any interpolated value becomes shell "
        "syntax and the PATH is attacker-influenceable.",
        "Use execve() with an absolute path and an argument array.",
        severity="low", cwe="CWE-78", owasp=A03, category="command-injection",
        confidence="low", node_type="call_expression")
    return p


def build_c_rules() -> RuleSet:
    return RuleSet(sources=_sources(), sinks=_sinks(),
                   sanitizers=_sanitizers(), patterns=_patterns())
