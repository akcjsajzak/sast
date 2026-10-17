"""Broken access control candidates: IDOR and missing authorisation.

OWASP A01 is the largest category in the Top 10 and the one every engine
here declares out of scope, because "can this user do this" is not a
source-to-sink question. There is no sink: the code is dangerous for what it
*fails* to do.

What is tractable is the shape of the omission. An object reference the
client supplies, used to read or write that object, with nothing tying it to
whoever is logged in, is the IDOR shape. A route that changes state while
every neighbouring route is guarded is the missing-authorisation shape.
Neither is proof, and this module does not pretend otherwise — it produces
*candidates*, ranked, each naming the evidence and what to check.

That trade only makes sense for a human reading the output. A list that is
half false positives is a morning's work for an auditor and an unusable
build gate, so none of this runs unless `--audit` asks for it.

Three things in here were learned from real applications rather than
guessed, and each one changed the design:

* govwa's `idor1ActionHandler` *does* read the session, then compares the
  submitted `uid` against a **cookie** the attacker also controls. So
  "mentions the session" cannot be the test for safety; it only lowers
  confidence.
* dvna's IDOR is on a `Product`. Filtering to entities that sound
  user-owned — `user`, `account`, `profile` — would have missed it, so the
  operation decides, not the noun.
* BenchmarkJava's 2740 servlets all read a parameter and run SQL. They are
  not IDOR, and what keeps them out is that their parameters are not named
  like identifiers. The id-name filter is doing the precision work, which is
  why it is narrow on purpose.
"""
from __future__ import annotations

import os
import re

from ..models import Finding, Location, Severity, TaintStep
from .requests import _PARAM_PATTERNS, PATH, QUERY, BODY, COOKIE, HEADER
from .routes import _CALL_TYPES, _FUNCTION_TYPES, _args, _callee, _text, _walk

A01 = "A01:2021 — Broken Access Control"

# Parameter names that denote "which object". An IDOR needs the client to
# name the object, so a parameter that is not an identifier cannot be one.
# This is the main precision control: without it every servlet that reads a
# parameter and touches a database becomes a candidate.
_ID_NAMES = (
    "id", "uid", "pk", "key", "ref", "no", "num", "number", "guid", "uuid",
    "oid", "sid", "eid", "gid", "idx", "index", "seq", "slug", "code",
)
_ID_SUFFIXES = ("_id", "id", "_pk", "pk", "_no", "_num", "_uuid", "_guid",
                "_key", "_ref")
# Entities whose identifier is nearly always a per-user object. Does not gate
# anything — it raises confidence, because dvna proved the inverse filter
# loses real bugs.
_OWNED_HINTS = (
    "user", "account", "profile", "member", "customer", "order", "invoice",
    "payment", "card", "message", "memo", "note", "document", "doc", "file",
    "ticket", "booking", "address", "subscription", "allocation", "benefit",
    "transfer", "cart", "wishlist", "session", "token", "setting",
)

# Calls that read a stored object. Deliberately generic: the filter that
# makes this usable is that a client-supplied identifier has to appear in the
# arguments, not that the callee is distinctive.
_READ_CALLS = (
    "find", "findone", "findbyid", "findbypk", "findall", "findfirst",
    "get", "getbyid", "getby", "getdata", "fetch", "fetchone", "fetchall",
    "load", "first", "where", "filter", "query", "queryforobject",
    "queryforlist", "select", "read", "retrieve", "lookup", "exists",
    "getuser", "getprofile", "getaccount", "getorder", "single",
    "singleordefault", "firstordefault", "getbyuserid",
)
# Calls that change a stored object. A write keyed by a client-supplied
# identifier is the stronger half of the signal: a read leaks, a write
# corrupts someone else's data.
_WRITE_CALLS = (
    "save", "update", "updateone", "updatemany", "create", "insert",
    "insertone", "add", "delete", "deleteone", "deletemany", "destroy",
    "remove", "put", "patch", "modify", "set", "upsert", "replace",
    "updateprofile", "saveorupdate", "persist", "merge", "executeupdate",
    "updateuser", "deleteuser", "removeuser", "transfer", "withdraw",
)
# SQL that names a row. Used when the access is a raw statement rather than
# an ORM call.
_SQL_READ = re.compile(r"\bselect\b.{0,200}?\bfrom\b", re.I | re.S)
_SQL_WRITE = re.compile(r"\b(?:update|delete\s+from|insert\s+into)\b", re.I)

# Evidence that the handler consulted whoever is logged in. Its presence does
# not clear the handler — see govwa above — but its absence is a much
# stronger claim, so the two are reported at different confidence.
_PRINCIPAL_PATTERNS = (
    r"\$_SESSION\b", r"Auth::(?:user|id|check)", r"auth\(\)\s*->\s*user",
    r"getUserPrincipal", r"SecurityContextHolder", r"getRemoteUser",
    r"@AuthenticationPrincipal", r"\bPrincipal\b", r"getSession\s*\(",
    r"req(?:uest)?\.user\b", r"req(?:uest)?\.session\b", r"ctx\.state\.user",
    r"\bcurrentUser\b", r"\bcurrent_user\b", r"res\.locals\.user",
    r"request\.user\b", r"\bg\.user\b", r"session\s*\[", r"session\.get",
    r"User\.Identity", r"HttpContext\.User", r"\bSession\s*\[",
    r"User\.IsInRole", r"GetSession\s*\(", r"\bsess\.", r"\bsession\.",
)
_PRINCIPAL = re.compile("|".join(_PRINCIPAL_PATTERNS))

# Methods that change server state, for the missing-authorisation check.
_STATE_CHANGING = ("POST", "PUT", "PATCH", "DELETE")

# Routes that are unauthenticated by design. Reporting them is not a
# borderline call, it is simply wrong: a login form nobody can reach without
# logging in first is not a vulnerability. dvna and govwa both put `/login`,
# `/forgotpw` and `/resetpw` at the top of the candidate list until this
# existed, which is exactly the kind of noise that teaches someone to stop
# reading the output.
_PUBLIC_ROUTE_WORDS = (
    "login", "signin", "sign-in", "logout", "signout", "sign-out",
    "register", "signup", "sign-up", "forgot", "reset", "recover",
    "password-reset", "activate", "confirm", "verify-email", "oauth",
    "callback", "sso", "saml", "token", "refresh", "health", "healthz",
    "status", "ping", "metrics", "webhook", "hook", "csrf", "captcha",
    "subscribe", "newsletter", "contact", "feedback", "search", "setup",
    "install", "robots", "favicon",
)


def _is_public_by_design(path: str) -> bool:
    low = (path or "").lower()
    return any(word in low for word in _PUBLIC_ROUTE_WORDS)


# Names that identify the *caller*, not an object the caller is asking for.
# A session id arrives in a cookie and is looked up on every request; that is
# how a session works, not a direct object reference. pygoat's
# `AF_session_id.objects.get(session_id=cookie)` was reported until this
# existed, and the advice it gave — tie this identifier to the principal —
# was circular, since the identifier *is* the principal.
_CREDENTIAL_NAMES = (
    "session", "sessionid", "session_id", "sid", "sessid", "token",
    "accesstoken", "access_token", "refreshtoken", "refresh_token", "jwt",
    "csrf", "csrftoken", "csrf_token", "xsrf", "auth", "authtoken",
    "apikey", "api_key", "secret", "nonce", "state", "code_verifier",
)


def _is_id_name(name: str) -> bool:
    low = re.sub(r"[^a-z0-9_]", "", (name or "").lower())
    if not low:
        return False
    if low in _CREDENTIAL_NAMES:
        return False
    if low in _ID_NAMES:
        return True
    return any(low.endswith(suffix) for suffix in _ID_SUFFIXES)


def _looks_owned(text: str) -> bool:
    low = (text or "").lower()
    return any(hint in low for hint in _OWNED_HINTS)


# Request containers destructured wholesale. NodeGoat writes
# `const { userId } = req.params`, where the parameter is named on the left
# and the accessor on the right says only which part of the request it came
# from. Matching accessors alone missed it entirely.
_CONTAINER_PATTERNS = (
    (r"req(?:uest)?\.params\b", PATH),
    (r"req(?:uest)?\.query\b", QUERY),
    (r"req(?:uest)?\.body\b", BODY),
    (r"req(?:uest)?\.cookies\b", COOKIE),
    (r"req(?:uest)?\.headers\b", HEADER),
    (r"request\.(?:GET|args)\b", QUERY),
    (r"request\.(?:POST|form|data)\b", BODY),
    (r"\$_GET\b", QUERY),
    (r"\$_POST\b", BODY),
    (r"\$_REQUEST\b", QUERY),
)
_CONTAINERS = re.compile("|".join(p for p, _ in _CONTAINER_PATTERNS))


def _is_container(text: str) -> bool:
    """True when the text is a bare request container being destructured."""
    return bool(_CONTAINERS.search(text or ""))


# Verbs that open a call name for a stored-object access. Matched as a
# prefix on the original casing so `getByUserIdAndThreshold` counts while
# `settings` does not become a `set`, and `address` does not become an
# `add`. Exact-name matching missed every DAO method an application names
# after what it fetches, which is most of them.
_READ_PREFIXES = ("find", "get", "fetch", "load", "select", "query",
                  "retrieve", "read", "lookup", "list", "show", "view")
_WRITE_PREFIXES = ("save", "update", "create", "insert", "delete", "destroy",
                   "remove", "modify", "upsert", "replace", "persist",
                   "merge", "edit", "transfer", "withdraw", "approve",
                   "cancel", "revoke", "grant", "reset")
_VERB_BOUNDARY = r"(?:[A-Z_0-9]|$)"


def _verb_kind(tail: str) -> str:
    """'read', 'write' or '' for a callee's last segment."""
    low = tail.lower()
    if low in _WRITE_CALLS:
        return "write"
    if low in _READ_CALLS:
        return "read"
    for prefix in _WRITE_PREFIXES:
        if re.match("^" + prefix + _VERB_BOUNDARY, tail, re.I if len(tail) == len(prefix) else 0):
            return "write"
    for prefix in _READ_PREFIXES:
        if re.match("^" + prefix + _VERB_BOUNDARY, tail, re.I if len(tail) == len(prefix) else 0):
            return "read"
    return ""


def _request_reads(text: str) -> list:
    """Every (name, where) a chunk of source reads out of the request."""
    found: list = []
    for pattern, where in _PARAM_PATTERNS:
        for match in re.finditer(pattern, text):
            name = match.group(1)
            if name and (name, where) not in found:
                found.append((name, where))
    return found


# Nodes that bind a name to a value, across the six grammars.
_BIND_TYPES = (
    "assignment_expression", "assignment", "variable_declarator",
    "init_declarator", "short_var_declaration", "augmented_assignment",
    "expression_statement", "local_declaration_statement", "declaration",
    "lexical_declaration", "variable_declaration",
)


def _id_handles(body, source: str) -> set:
    """Names that hold a client-supplied object identifier.

    Two kinds go in. The raw accessor text, so `req.query.id` matches where
    it is used inline — which is how dvna writes it. And any variable whose
    initialiser *contains* such an accessor, so `uid := Escape(r.FormValue(
    "uid"))` is tracked through the wrapper, which is how govwa writes it.
    Destructuring counts too: NodeGoat's `const { userId } = req.params`
    binds the name on the left to a parameter named on the right.
    """
    handles: set = set()
    for node in _walk(body):
        text = _text(node)
        if not text or len(text) > 400:
            continue
        reads = _request_reads(text)
        # A destructured container has no accessor to find, so skipping on
        # "no accessor" here hid every `const { userId } = req.params`.
        if not reads and not _is_container(text):
            continue
        # The accessor itself, when it names an identifier parameter.
        if node.type not in _BIND_TYPES and len(text) < 80:
            if any(_is_id_name(name) for name, _ in reads):
                handles.add(text.strip())
        if node.type not in _BIND_TYPES:
            continue
        left = node.child_by_field_name("left") \
            or node.child_by_field_name("name") \
            or node.child_by_field_name("declarator")
        right = node.child_by_field_name("right") \
            or node.child_by_field_name("value")
        if right is None or left is None:
            continue
        right_text = _text(right)
        # `const { userId } = req.params` carries no accessor to match: the
        # right side names only the part of the request, and the parameter
        # is the name bound on the left.
        destructured = _is_container(right_text)
        if not destructured and not _request_reads(right_text):
            continue
        bound = [n for n in _walk(left) if n.type in (
            "identifier", "shorthand_property_identifier_pattern",
            "shorthand_property_identifier", "property_identifier",
            "field_identifier", "variable_name", "name")]
        names = [_text(n).strip().lstrip("$") for n in bound] or []
        # `const { userId } = req.params` names the parameter on the *left*,
        # so the left-hand name is what decides whether this is an
        # identifier, not the accessor on the right.
        right_reads = _request_reads(_text(right))
        for name in names:
            if _is_id_name(name) or any(_is_id_name(r) for r, _ in right_reads):
                handles.add(name)
    return {h for h in handles if h}


_STRINGY = (
    "string", "string_literal", "interpreted_string_literal",
    "raw_string_literal", "encapsed_string", "string_content",
    "string_fragment", "verbatim_string_literal", "character_literal",
    "comment",
)


def _searchable(node) -> str:
    """The node's source with string literals and comments blanked out.

    `request.POST.get('code')` reads the request; it does not read a stored
    object. Matching the handle `code` against the quoted `'code'` turned
    every parameter read into its own data access, which put four findings
    on pygoat pointing at the line that merely fetches the parameter.

    The blanking is done in place, over the byte range, rather than by
    rebuilding the text from the nodes that survive. Rebuilding flattened
    `req.query.id` into three separate leaves, and dvna and dvws-node —
    whose handles *are* dotted accessors — stopped matching entirely.
    """
    raw = node.text
    if not raw:
        return ""
    buf = bytearray(raw)
    start = node.start_byte
    for inner in _walk(node):
        if inner.type not in _STRINGY:
            continue
        lo, hi = inner.start_byte - start, inner.end_byte - start
        if 0 <= lo < hi <= len(buf):
            buf[lo:hi] = b" " * (hi - lo)
    return buf.decode("utf-8", "replace")


def _mentions_handle(node, handles: set) -> str:
    """The identifier handle used inside a node, if any."""
    text = _searchable(node)
    if not text:
        return ""
    for handle in handles:
        if not handle:
            continue
        if re.search(r"(?<![\w.$])" + re.escape(handle) + r"(?![\w])", text):
            return handle
    return ""


def _accesses(body, handles: set) -> list:
    """Data accesses in this body keyed by a client-supplied identifier.

    Returns (node, kind, callee, handle) with kind 'read' or 'write'. The
    identifier has to appear in the call's *arguments*: a database call that
    merely sits in the same function as a request read says nothing, and
    checking the whole body instead of the arguments was the difference
    between a usable list and one nobody would read.
    """
    found: list = []
    for node in _walk(body):
        if node.type not in _CALL_TYPES:
            continue
        callee = _callee(node)
        if not callee:
            continue
        tail = re.split(r"[.:>\-]+", callee)[-1]
        args = _args(node)
        if not args:
            continue
        arg_text = " ".join(_text(a) for a in args)
        handle = ""
        for a in args:
            handle = _mentions_handle(a, handles)
            if handle:
                break
        if not handle:
            continue
        kind = _verb_kind(tail)
        if not kind:
            if _SQL_WRITE.search(arg_text):
                kind = "write"
            elif _SQL_READ.search(arg_text):
                kind = "read"
        if kind:
            found.append((node, kind, callee, handle))
    return found


def _loc(sf, node) -> Location:
    return Location(
        file=sf.path,
        line=node.start_point.row + 1,
        column=node.start_point.column + 1,
        end_line=node.end_point.row + 1,
        end_column=node.end_point.column + 1,
        code=sf.node_line(node),
    )


_WHERE_WORDS = {
    PATH: "the URL path", QUERY: "the query string", BODY: "the request body",
    COOKIE: "a cookie", HEADER: "a request header",
}


class AuthzScanner:
    """Finds broken-access-control candidates in one language pass."""

    def __init__(self, language: str, framework: str = "raw") -> None:
        self.language = language
        self.framework = framework
        self.findings: list = []
        self._seen: set = set()

    # ------------------------------------------------------------------
    def analyze(self, files: list, routes: list) -> list:
        for sf in files:
            for fn in self._functions(sf.root):
                self._check_function(fn, sf)
        self._check_routes(routes)
        return self.findings

    @staticmethod
    def _functions(root):
        for node in _walk(root):
            if node.type in _FUNCTION_TYPES:
                yield node

    def _check_function(self, fn, sf) -> None:
        body = fn.child_by_field_name("body") or fn
        source = _text(body)
        if not source or len(source) > 40000:
            return
        handles = _id_handles(body, source)
        if not handles:
            return
        accesses = _accesses(body, handles)
        if not accesses:
            return
        principal = bool(_PRINCIPAL.search(source))
        # One finding per function: a handler that reads a row and then
        # updates it would otherwise be reported twice for the same omission,
        # and the fix is the same ownership check either way. A write is the
        # more serious of the two, so it wins the report.
        writes = [a for a in accesses if a[1] == "write"]
        node, kind, callee, handle = (writes or accesses)[0]
        self._report_idor(fn, node, sf, kind, callee, handle, principal,
                          len(accesses))

    def _report_idor(self, fn, node, sf, kind, callee, handle, principal,
                     count) -> None:
        loc = _loc(sf, node)
        key = ("authz-idor-candidate", loc.file, loc.line, loc.column)
        if key in self._seen:
            return
        self._seen.add(key)

        owned = _looks_owned(callee) or _looks_owned(handle)
        if principal:
            # The handler does consult the session somewhere. It may well
            # compare correctly — or, as in govwa, compare the submitted id
            # against a cookie the client also controls. Either way it needs
            # a human, so it is reported quieter rather than dropped.
            confidence = "low"
        elif kind == "write" or owned:
            confidence = "medium"
        else:
            confidence = "low"
        severity = "high" if (kind == "write" and not principal) else "medium"

        verb = "updates" if kind == "write" else "reads"
        checked = (
            "The handler does reference the session elsewhere, so a check may "
            "exist — confirm it compares this identifier against the session "
            "and not against another client-supplied value such as a cookie "
            "or a second parameter."
            if principal else
            "Nothing in this handler references the logged-in user, so there "
            "is nothing here that could be restricting the object to its "
            "owner."
        )
        self.findings.append(Finding(
            rule_id="authz-idor-candidate",
            title="Possible insecure direct object reference",
            severity=Severity(severity), cwe="CWE-639", owasp=A01,
            category="broken-access-control",
            description=(
                f"'{handle}' comes from the request and {verb} an object "
                f"through {callee}(). " + checked + " If the identifier can "
                "be changed to one belonging to another user, this is a "
                "horizontal privilege escalation: "
                + ("their data is modified."
                   if kind == "write" else "their data is disclosed.")
            ),
            remediation=(
                "Scope the query to the authenticated principal — add the "
                "session's user id to the WHERE clause rather than trusting "
                "the one supplied — or verify ownership before acting and "
                "fail closed when it does not match."
            ),
            confidence=confidence, framework=self.framework,
            language=self.language, location=loc, source=None,
            trace=[TaintStep(location=loc,
                             description=f"object {verb} by client-supplied "
                                         f"'{handle}'",
                             code=loc.code)],
            tags=["access-control", "idor", kind],
        ))

    # ------------------------------------------------------------------
    def _check_routes(self, routes: list) -> None:
        """State-changing routes left unguarded where neighbours are guarded.

        Reported only when the application demonstrably guards *something*.
        An app with no guards anywhere either has none, or keeps them
        somewhere this cannot see — a proxy, a filter, a gateway — and in
        both cases listing every route as a finding tells nobody anything.
        DVWA would have produced 163 of them.
        """
        # Only routes with a declaration site. A file that is served
        # directly has nowhere for a guard to be written, so "none found
        # here" says nothing about it — DVWA produced 32 findings this way,
        # every one of them a page that does authenticate, inside its body.
        mine = [r for r in routes
                if r.language == self.language and r.declared]
        # Group by the directory the routes are declared in, and judge each
        # group on its own. A repository is not always one application:
        # pygoat keeps several standalone labs under `dockerized_labs/`, and
        # comparing a lab that has no login at all against a *different*
        # lab's `@login_required` reported both of its routes. The premise
        # of this check is an inconsistency *within* one application, so the
        # comparison has to stay inside one.
        groups: dict = {}
        for route in mine:
            groups.setdefault(os.path.dirname(route.file), []).append(route)
        for group in groups.values():
            self._check_route_group(group)

    def _check_route_group(self, mine: list) -> None:
        guarded = [r for r in mine if not r.open]
        if not guarded or len(guarded) == len(mine):
            return
        ratio = len(guarded) / float(len(mine))
        for route in mine:
            if not route.open:
                continue
            methods = (route.method or "").replace(",", " ").split()
            if not any(m in _STATE_CHANGING for m in methods):
                continue
            if _is_public_by_design(route.path):
                continue
            # A bare "/" or "*" is almost always a sub-router's root or a
            # catch-all, and this analysis cannot resolve the prefix it is
            # mounted under. "POST / has no guard" tells a reader nothing
            # they can act on, so it is not worth a line in the report.
            if route.path.strip() in ("/", "*", "", "/*"):
                continue
            loc = Location(file=route.file, line=route.line, column=1,
                           end_line=route.line, end_column=1, code="")
            key = ("authz-missing-check", loc.file, loc.line, route.path)
            if key in self._seen:
                continue
            self._seen.add(key)
            self.findings.append(Finding(
                rule_id="authz-missing-check",
                title="State-changing route with no authorisation check",
                severity=Severity("medium"), cwe="CWE-862", owasp=A01,
                category="broken-access-control",
                description=(
                    f"{route.method} {route.path} changes state, and no "
                    "authorisation check was found where it is declared, "
                    f"while {len(guarded)} of {len(mine)} routes in this "
                    "application do have one. That inconsistency is worth a "
                    "look: either this route is deliberately public, or it "
                    "was missed. Authorisation applied in a filter, a "
                    "security configuration or a gateway is not visible "
                    "here, so confirm before concluding it is absent."
                ),
                remediation=(
                    "Apply the same guard the other routes use, or record "
                    "why this one is public."
                ),
                confidence="low" if ratio < 0.5 else "medium",
                framework=self.framework, language=self.language,
                location=loc, source=None, trace=[],
                tags=["access-control", "missing-authorization"],
            ))


def scan_authz(files: list, routes: list, language: str,
               framework: str = "raw") -> list:
    """Entry point: broken-access-control candidates for one language."""
    return AuthzScanner(language, framework).analyze(files, routes)
