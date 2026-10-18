"""HTTP route extraction: the application's attack surface.

Every engine in this package answers "where are the bugs". That is the second
question an auditor asks. The first is "what can I reach", and nothing here
answered it: the taint engines recognise `getParameter` and `req.query` as
untrusted, then discard which handler they were in, so a finding could say
what was wrong without ever saying how a request gets there.

This module recovers that. It walks the parsed trees for the route
constructs of each supported framework and builds an inventory of method,
path, handler and any authorisation guard in scope. Two things come out of
it. The inventory itself is useful with no findings attached at all — on an
unfamiliar codebase it is the target list, and assembling it by hand is a
day's work. And once handlers are known, a finding can be tied to the entry
point that reaches it, which turns "SQL injection at Foo.java:42" into a
request someone can actually send.

On guards, the honest position matters more than the coverage. A detected
guard is evidence; *no* detected guard is not evidence of the opposite. An
app can authorise in a servlet filter, a Spring `SecurityConfig`, a reverse
proxy or an API gateway, none of which is visible at the route declaration.
So a route with nothing found is reported as "no guard found here", never as
"unauthenticated", and `Route.open` is named for what was observed rather
than what is true.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

# Methods worth distinguishing. Anything else a framework offers (`all`,
# `use`, `any`) collapses to ANY, which sorts and reads the same way.
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
ANY = "ANY"

# Substrings that mark a wrapper, decorator, annotation or middleware as an
# authorisation check. Matched case-insensitively against the identifier, so
# `AuthCheck`, `requireLogin`, `@PreAuthorize` and `ensureAuthenticated` all
# hit. Deliberately broad: a guard missed is a finding wrongly promoted to
# the top of the report, which is worse than one wrongly demoted.
GUARD_HINTS = (
    "auth", "login", "session", "permission", "role", "acl",
    "token", "jwt", "csrf", "verify", "ensureuser", "requireuser",
    "signedin", "loggedin", "principal", "guard", "protect",
    "restrict", "secured", "credential",
)
# `admin` was a hint and had to be dropped. It appears far more often in the
# name of the thing being protected than the protection — dvws-node's
# `controller.adminCreateUser` was read as a guard, which both lost the
# handler and marked an unauthenticated admin endpoint as protected. A hint
# that silently demotes findings is worse than a missing one.
# Identifiers that contain a hint but are not guards. `authController` is the
# thing being protected, not the protection, and logging middleware named
# `requestLogger` would otherwise never match anyway.
GUARD_EXCEPTIONS = (
    "authcontroller", "authroute", "authrouter", "authservice", "authview",
    "authhandler", "logout", "loginview", "loginhandler", "loginpage",
    "logincontroller", "authenticate_url", "unauthorized", "unauthenticated",
    "allowanonymous", "anonymous", "permitall",
)
# Annotations and decorators that explicitly turn a guard *off* for one
# route. These beat an inherited class-level guard, which is the whole point
# of writing them.
GUARD_OPT_OUT = ("allowanonymous", "permitall", "csrf_exempt", "public")


@dataclass
class Route:
    """One reachable HTTP entry point."""
    method: str                     # GET, POST, ... or ANY
    path: str                       # as written, e.g. "/user/{id}"
    handler: str = ""               # the function or class that serves it
    file: str = ""                  # where the route is declared
    line: int = 0
    framework: str = ""
    language: str = ""
    # Path/query parameters named in the declaration, when the framework
    # states them. An empty list means none were declared, not that the
    # route takes none.
    params: list = field(default_factory=list)
    # Guard identifiers found in scope, e.g. ['AuthCheck'] or ['@PreAuthorize'].
    guards: list = field(default_factory=list)
    # The handler body, for tying findings to this route. Set once the
    # handler is resolved; (file, start_line, end_line).
    body: tuple = ()
    # False when the route is a directly-requestable file rather than a
    # declaration. It matters for anything reasoning about guards: a file
    # route has no declaration site, so "no guard written here" is vacuous
    # rather than suspicious.
    declared: bool = True

    @property
    def open(self) -> bool:
        """True when no authorisation guard was found at this declaration.

        Named for the observation, not the conclusion: see the module
        docstring on why this is not the same as "unauthenticated".
        """
        return not self.guards

    @property
    def signature(self) -> str:
        return f"{self.method} {self.path}"

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "path": self.path,
            "handler": self.handler,
            "file": self.file,
            "line": self.line,
            "framework": self.framework,
            "language": self.language,
            "params": self.params,
            "guards": self.guards,
            "guarded": not self.open,
            "declared": self.declared,
        }


# ---------------------------------------------------------------------------
# Shared AST primitives.
#
# Six languages declare routes six ways, but every one of them needs the same
# four things from a node: what is being called, which strings it was passed,
# which names it was passed, and which function encloses it. Writing those
# once per language produced six near-copies, so they are factored here and
# keyed on node type instead.

_CALL_TYPES = (
    "call", "call_expression", "invocation_expression",
    "function_call_expression", "member_call_expression",
    "scoped_call_expression", "method_invocation", "object_creation_expression",
)
_STRING_TYPES = (
    "string", "string_literal", "interpreted_string_literal",
    "raw_string_literal", "encapsed_string", "string_value",
    "verbatim_string_literal", "string_fragment", "concatenated_string",
)
_FUNCTION_TYPES = (
    "function_definition", "function_declaration", "method_declaration",
    "method_definition", "function_item", "arrow_function",
    "function_expression", "function", "lambda",
    "local_function_statement", "constructor_declaration",
)
_CLASS_TYPES = (
    "class_declaration", "class_definition", "class_specifier",
    "class_declaration_statement", "record_declaration", "struct_declaration",
)


def _text(node) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", "replace")


def _walk(root):
    """Every named node under `root`, parents before children."""
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.named_children))


def _calls(root):
    for node in _walk(root):
        if node.type in _CALL_TYPES:
            yield node


def _callee(node) -> str:
    """The called expression's text, e.g. `app.get` or `Route::post`."""
    for field_name in ("function", "constructor", "name"):
        child = node.child_by_field_name(field_name)
        if child is not None:
            return _text(child).strip()
    kids = [c for c in node.named_children if c.type != "comment"]
    return _text(kids[0]).strip() if kids else ""


def _args(node) -> list:
    """The argument nodes of a call, however the grammar spells the list."""
    for field_name in ("arguments", "argument_list", "parameters"):
        holder = node.child_by_field_name(field_name)
        if holder is not None:
            return [c for c in holder.named_children
                    if c.type not in ("comment", ")", "(")]
    for child in node.named_children:
        if child.type in ("argument_list", "arguments"):
            return [c for c in child.named_children if c.type != "comment"]
    return []


def _unwrap_arg(node):
    """Look through an `argument` wrapper node to the expression inside."""
    while node is not None and node.type in ("argument", "parenthesized_expression"):
        kids = [c for c in node.named_children if c.type != "comment"]
        if not kids:
            return node
        node = kids[0]
    return node


def _string_value(node) -> str:
    """The literal text of a string node, quotes and prefixes stripped."""
    node = _unwrap_arg(node)
    if node is None:
        return ""
    if node.type not in _STRING_TYPES:
        # Some grammars wrap the body in a child fragment node.
        for child in node.named_children:
            if child.type in _STRING_TYPES:
                node = child
                break
        else:
            return ""
    raw = _text(node)
    for child in node.named_children:
        if child.type in ("string_fragment", "string_content"):
            return _text(child)
    return raw.strip().lstrip("rbfuRBFU@$").strip("'\"`")


def _first_string(node) -> str:
    """The first string literal among a call's arguments."""
    for arg in _args(node):
        value = _string_value(arg)
        if value:
            return value
    return ""


_NAME_TYPES = (
    "identifier", "selector_expression", "member_access_expression",
    "field_expression", "attribute", "member_expression", "scoped_identifier",
    "qualified_name", "name", "variable_name", "simple_identifier",
    "class_constant_access_expression",
)


def _names_passed(node) -> list:
    """Names a call is passed, outermost wrapper first.

    `r.GET("/x", mw.Logging(mw.AuthCheck(h)))` must yield the dotted
    `mw.AuthCheck` so the guard check sees it, and `h` last so the handler
    can be read off the end. Three things are deliberately not descended
    into, each of which produced visible nonsense before:

    * a function body — reading `app.get('/x', (req, res) => { ... })` to the
      bottom harvested every local in the handler, which made the handler
      name whatever happened to be mentioned last and invented guards out of
      words like `admin` appearing in the body;
    * a string literal, whose contents are not identifiers;
    * a keyword argument, since `methods=['POST']` and `name='home'` name a
      parameter rather than a handler.

    Dotted names are kept whole for the same reason: splitting
    `mw.AuthCheck` into `mw` and `AuthCheck` made the receiver look like the
    handler.
    """
    found: list = []

    def visit(current) -> None:
        current = _unwrap_arg(current)
        if current is None:
            return
        kind = current.type
        if kind in _STRING_TYPES or kind in _FUNCTION_TYPES:
            return
        if kind in ("keyword_argument", "named_argument", "comment"):
            return
        if kind in _CALL_TYPES:
            callee = _callee(current)
            if callee:
                found.append(callee)
            for inner in _args(current):
                visit(inner)
            return
        if kind in _NAME_TYPES:
            text = _text(current).strip()
            if text:
                found.append(text)
            return
        for child in current.named_children:
            visit(child)

    for arg in _args(node):
        visit(arg)
    return list(dict.fromkeys(found))


def _enclosing(node, types) -> object:
    """The nearest ancestor of one of `types`, or None."""
    current = node.parent
    while current is not None:
        if current.type in types:
            return current
        current = current.parent
    return None


def _name_of(node) -> str:
    """A function or class declaration's own name."""
    if node is None:
        return ""
    named = node.child_by_field_name("name")
    if named is not None:
        return _text(named).strip()
    declarator = node.child_by_field_name("declarator")
    while declarator is not None:
        if declarator.type == "identifier":
            return _text(declarator)
        nxt = declarator.child_by_field_name("declarator")
        if nxt is None:
            kids = [c for c in declarator.named_children if c.type != "comment"]
            nxt = kids[0] if kids else None
        declarator = nxt
    return ""


def _body_span(node, path: str) -> tuple:
    """The (file, start, end) line span a handler covers."""
    if node is None:
        return ()
    return (path, node.start_point.row + 1, node.end_point.row + 1)


def _is_guard(name: str) -> bool:
    """True when an identifier names an authorisation check.

    Judged on the *last* segment first. Testing the whole dotted name meant
    `authHandler.isAuthenticated` matched the `authhandler` exception —
    written to keep a controller called `authHandler` from reading as its own
    guard — and dvna's entire authenticated surface was reported as open. The
    namespace is only consulted when the tail carries no signal of its own,
    so `auth.check(...)` still counts.
    """
    low = name.lower().lstrip("@#[").rstrip("]")
    if not low:
        return False
    tail = re.split(r"[.:>\-]+", low)[-1] or low

    def excepted(value: str) -> bool:
        return any(value == e or value.startswith(e) for e in GUARD_EXCEPTIONS)

    def hinted(value: str) -> bool:
        return any(hint in value for hint in GUARD_HINTS)

    if excepted(tail):
        return False
    if hinted(tail):
        return True
    return hinted(low) and not excepted(low)


def _guards_in(names) -> list:
    out: list = []
    for name in names:
        if _is_guard(name) and name not in out:
            out.append(name)
    return out


def _path_params(path: str) -> list:
    """Parameter names a route path declares.

    Covers the four spellings in use: `:id`, `{id}`, `<int:id>` and `$id`.
    """
    found: list = []
    for match in re.finditer(r"[:{<]\s*([A-Za-z_][\w]*)\s*[>}]?|\{(\w+)\}", path):
        name = match.group(1) or match.group(2)
        if not name:
            continue
        # Django writes `<int:challenge>`; the converter is not the name.
        if ":" in path and name in ("int", "str", "slug", "uuid", "path"):
            continue
        if name not in found:
            found.append(name)
    return found


def _join(prefix: str, suffix: str) -> str:
    """Join a class-level route prefix to a method-level path."""
    prefix = (prefix or "").strip()
    suffix = (suffix or "").strip()
    if not prefix:
        return suffix or "/"
    if not suffix:
        return prefix or "/"
    return prefix.rstrip("/") + "/" + suffix.lstrip("/")


def _method_from(name: str) -> str:
    """The HTTP method a route-registering identifier implies."""
    tail = name.rsplit(".", 1)[-1].rsplit("::", 1)[-1].lstrip("@#[").rstrip("]")
    upper = tail.upper()
    for method in METHODS:
        if upper == method or upper == "MAP" + method or \
                upper == "HTTP" + method or upper == method + "MAPPING":
            return method
    return ANY


# ---------------------------------------------------------------------------
# Decorator and annotation routes: Flask, FastAPI, Spring, NestJS, Symfony,
# ASP.NET Core. All six attach the path to the handler itself, so one walk
# over functions and their classes covers them.

# The identifiers that introduce a route when they decorate or annotate.
_ROUTE_MARKERS = (
    "route", "get", "post", "put", "patch", "delete", "head", "options",
    "requestmapping", "getmapping", "postmapping", "putmapping",
    "patchmapping", "deletemapping", "webservlet", "httpget", "httppost",
    "httpput", "httppatch", "httpdelete", "controller", "restcontroller",
    "websocket", "api",
)


def _annotations(node) -> list:
    """Decorator/annotation nodes attached to a declaration.

    Each grammar hangs these somewhere different — Python puts the function
    inside a `decorated_definition`, Java and C# put them among the
    declaration's own children, PHP 8 uses `attribute_list`. Rather than
    encode all of that, look in both places and keep whatever matches.
    """
    found: list = []
    holders = [node]
    parent = node.parent
    if parent is not None and parent.type in (
            "decorated_definition", "attributed_declaration"):
        holders.append(parent)
    for holder in holders:
        for child in holder.named_children:
            if child.type in ("decorator", "annotation", "marker_annotation",
                              "attribute_list", "attribute", "modifiers",
                              "attribute_group", "attribute_declaration"):
                found.append(child)
    return found


def _annotation_entries(node):
    """Flatten an annotation holder into (name, node) pairs."""
    if node.type in ("modifiers", "attribute_list", "attribute_group",
                     "attribute_declaration"):
        for child in node.named_children:
            yield from _annotation_entries(child)
        return
    text = _text(node).strip()
    name = text.lstrip("@#[").split("(")[0].split("{")[0].strip().rstrip("]")
    name = name.rsplit(".", 1)[-1].rsplit("\\", 1)[-1]
    yield name, node


def _annotation_path(node) -> str:
    """The path a route annotation carries, if any.

    Handles `@GetMapping("/x")`, `@GetMapping(value = "/x")`,
    `@app.route('/x')` and `#[Route('/x')]` alike by taking the first string
    literal inside the annotation.
    """
    for inner in _walk(node):
        if inner.type in _STRING_TYPES:
            value = _string_value(inner)
            if value:
                return value
    return ""


def _annotation_methods(node) -> list:
    """HTTP methods named inside an annotation's arguments.

    `@app.route('/x', methods=['POST'])` and
    `@RequestMapping(method = RequestMethod.POST)` both state the method
    somewhere other than the annotation name.
    """
    text = _text(node).upper()
    found = [m for m in METHODS if re.search(r"\b" + m + r"\b", text)]
    return found


def _annotated_routes(sf, framework: str, language: str) -> list:
    """Routes declared by decorating or annotating their handler."""
    routes: list = []
    for node in _walk(sf.root):
        if node.type not in _FUNCTION_TYPES and node.type not in _CLASS_TYPES:
            continue
        is_class = node.type in _CLASS_TYPES
        own: list = []
        for holder in _annotations(node):
            own.extend(_annotation_entries(holder))
        markers = [(name, anno) for name, anno in own
                   if name.lower() in _ROUTE_MARKERS]
        guards = _guards_in([name for name, _ in own])
        opted_out = any(name.lower() in GUARD_OPT_OUT for name, _ in own)
        if opted_out:
            guards = []
        if is_class:
            continue  # class-level data is picked up as a prefix below
        # A handler's class may carry a path prefix and a guard of its own.
        prefix = ""
        owner = _enclosing(node, _CLASS_TYPES)
        if owner is not None:
            for holder in _annotations(owner):
                for name, anno in _annotation_entries(holder):
                    if name.lower() in _ROUTE_MARKERS:
                        prefix = prefix or _annotation_path(anno)
                    elif _is_guard(name):
                        if not opted_out and name not in guards:
                            guards.append(name)
        if not markers:
            # A servlet has no per-method annotation: the class carries the
            # path and doGet/doPost are the handlers by name.
            if prefix and _text(node.child_by_field_name("name")).lower() in (
                    "doget", "dopost", "doput", "dodelete", "service"):
                verb = _text(node.child_by_field_name("name"))[2:].upper()
                routes.append(Route(
                    method=verb if verb in METHODS else ANY,
                    path=prefix, handler=_name_of(owner) or _name_of(node),
                    file=sf.path, line=node.start_point.row + 1,
                    framework=framework, language=language,
                    params=_path_params(prefix), guards=guards,
                    body=_body_span(node, sf.path)))
            continue
        for name, anno in markers:
            path = _join(prefix, _annotation_path(anno))
            stated = _annotation_methods(anno)
            implied = _method_from(name)
            methods = stated or ([implied] if implied != ANY else [ANY])
            for method in methods:
                routes.append(Route(
                    method=method, path=path,
                    handler=_name_of(node),
                    file=sf.path, line=node.start_point.row + 1,
                    framework=framework, language=language,
                    params=_path_params(path), guards=list(guards),
                    body=_body_span(node, sf.path)))
    return routes


# ---------------------------------------------------------------------------
# Call-registered routes: Express, Koa, Fastify, Gin, Echo, Fiber, Gorilla,
# net/http, Laravel, Slim, Django. These register a path against a handler in
# a call, so the walk is over calls rather than declarations.

# Callee tails that register a route, mapped to how to read the method.
_REGISTER_TAILS = {
    "get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH",
    "delete": "DELETE", "head": "HEAD", "options": "OPTIONS",
    "all": ANY, "any": ANY, "match": ANY, "map": ANY,
    "handle": ANY, "handlefunc": ANY, "handlefuncs": ANY,
    "add": ANY, "addroute": ANY, "route": ANY, "resource": ANY,
    "apiresource": ANY, "path": ANY, "re_path": ANY, "url": ANY,
    # aiohttp: app.router.add_get('/x', h), and add_route('GET', '/x', h),
    # which states the method as its first string.
    "add_get": "GET", "add_post": "POST", "add_put": "PUT",
    "add_patch": "PATCH", "add_delete": "DELETE", "add_head": "HEAD",
    "add_view": ANY, "add_route": ANY,
}
_HTTP_VERBS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
# Receivers that plausibly own routes. Without this, every `foo.get(key)` in
# the codebase would read as a route declaration — a map lookup, an HTTP
# client call and a getter all spell themselves the same way.
_ROUTER_RECEIVERS = (
    "app", "router", "route", "r", "e", "mux", "server", "srv", "api",
    "http", "https", "web", "group", "g", "v1", "v2", "sub", "subrouter",
    "admin", "public", "routes", "handler", "engine", "fiber", "echo",
    "blueprint", "bp", "urlpatterns", "s",
)


def _looks_like_router(receiver: str) -> bool:
    low = receiver.lower().lstrip("$")
    if not low:
        return False
    if low in _ROUTER_RECEIVERS:
        return True
    return any(low.endswith(suffix) or low.startswith(suffix)
               for suffix in ("router", "route", "app", "mux", "api",
                              "blueprint", "group"))


def _registered_routes(sf, framework: str, language: str) -> list:
    """Routes registered by a call that pairs a path with a handler."""
    routes: list = []
    globals_guards = _global_middleware(sf)
    for call in _calls(sf.root):
        callee = _callee(call)
        if not callee:
            continue
        tail = callee.rsplit(".", 1)[-1].rsplit("::", 1)[-1].rsplit("->", 1)[-1]
        method = _REGISTER_TAILS.get(tail.lower())
        if method is None:
            continue
        # `@app.route('/x')` is both a decorator and a call. The decorator
        # walk already recorded it, with the handler it is attached to;
        # matching it again here produced a second, handler-less copy of
        # every Flask and FastAPI route.
        if _enclosing(call, ("decorator", "decorated_definition",
                             "annotation", "marker_annotation",
                             "attribute", "attribute_list")) is not None:
            continue
        receiver = callee[:len(callee) - len(tail)].rstrip(".:->")
        # Django's `path(...)` and Laravel's `Route::get(...)` have no
        # receiver worth checking; everything else must look like a router or
        # this matches half the codebase.
        bare_ok = tail.lower() in ("path", "re_path", "url") or \
            callee.lower().startswith("route::") or \
            callee.lower().startswith("http.")
        if not bare_ok and not _looks_like_router(receiver):
            continue
        if tail.lower() in ("route", "path", "at") and _is_chain_base(call):
            continue
        path = _first_string(call) or _receiver_path(call)
        if tail.lower() == "add_route":
            # The method comes first: add_route('GET', '/x', handler).
            strings = [v for v in (_string_value(a) for a in _args(call)) if v]
            if len(strings) >= 2 and strings[0].upper() in _HTTP_VERBS + ("*",):
                if strings[0] != "*":
                    method = strings[0].upper()
                path = strings[1]
        if not path:
            continue
        if not (path.startswith("/") or path.startswith("*")
                or tail.lower() in ("path", "re_path", "url")):
            continue
        names = _names_passed(call)
        guards = _guards_in(names) + [g for g in globals_guards]
        # The handler is the last name passed that is not a guard; for an
        # inline function there is no name, so fall back to the enclosing
        # declaration for a label.
        handler = ""
        for name in reversed(names):
            if not _is_guard(name):
                handler = name
                break
        body = _inline_handler_span(call, sf.path)
        if body and not handler:
            # Written in place, so it has no name to report. The span is
            # what matters for binding findings; the label just has to say
            # where to look.
            handler = f"(inline at {os.path.basename(sf.path)}:" \
                      f"{call.start_point.row + 1})"
        if method == ANY:
            stated = _annotation_methods(call)
            if stated:
                method = stated[0]
        routes.append(Route(
            method=method, path=path, handler=handler,
            file=sf.path, line=call.start_point.row + 1,
            framework=framework, language=language,
            params=_path_params(path),
            guards=list(dict.fromkeys(guards)), body=body))
    return routes


_MEMBER_TYPES = (
    "member_expression", "member_access_expression", "selector_expression",
    "field_expression", "attribute", "scoped_call_expression",
    "member_call_expression", "navigation_expression",
)


def _receiver_path(call) -> str:
    """The path set earlier in a chained registration.

    Express lets a path be declared once and the verbs hung off it:
    `router.route('/upload').post(validateToken, controller.post)`. The verb
    call carries the method, the guard and the handler but no path, and the
    `route()` call carries the path and nothing else, so reading either alone
    gets half a route. This finds the path for the half that matters.
    """
    callee = None
    for field_name in ("function", "constructor", "name"):
        callee = call.child_by_field_name(field_name)
        if callee is not None:
            break
    if callee is None:
        return ""
    for inner in _walk(callee):
        if inner.type in _CALL_TYPES:
            tail = _callee(inner).rsplit(".", 1)[-1].rsplit("::", 1)[-1]
            if tail.lower() in ("route", "path", "at"):
                value = _first_string(inner)
                if value:
                    return value
    return ""


def _is_chain_base(call) -> bool:
    """True when this call only exists to receive a verb call after it.

    `router.route('/upload')` on its own serves nothing; the `.post(...)`
    hung off it does. Without this the inventory listed both, the base as a
    method-less, handler-less duplicate of the real route.
    """
    current = call.parent
    while current is not None and current.type in _MEMBER_TYPES:
        parent = current.parent
        if parent is not None and parent.type in _CALL_TYPES:
            return True
        current = parent
    return False


def _inline_handler_span(call, path: str) -> tuple:
    """The span of a function written directly in the route registration."""
    for arg in _args(call):
        inner = _unwrap_arg(arg)
        if inner is not None and inner.type in _FUNCTION_TYPES:
            return _body_span(inner, path)
    return ()


def _global_middleware(sf) -> list:
    """Guards installed for every route in the file via `use(...)`.

    `app.use(requireAuth)` protects everything registered after it. Treating
    it as covering the whole file is imprecise in both directions, but it is
    the difference between calling an authenticated app wide open and not,
    so it is worth more than ignoring it.
    """
    found: list = []
    for call in _calls(sf.root):
        callee = _callee(call)
        tail = callee.rsplit(".", 1)[-1]
        if tail.lower() not in ("use", "usemiddleware", "middleware"):
            continue
        if not _looks_like_router(callee[:len(callee) - len(tail)].rstrip(".")):
            continue
        for guard in _guards_in(_names_passed(call)):
            if guard not in found:
                found.append(guard)
    return found


# ---------------------------------------------------------------------------
# Routes that are a file rather than a declaration.
#
# Raw PHP and ASP.NET WebForms have no route table: the URL *is* the path to
# the file, and the handler is whatever runs at the top of it. Both turn up
# constantly in audits of older applications, and without this an entire
# codebase can produce an empty inventory while serving a hundred endpoints.

# Files that are reachable as a URL in a document-root deployment.
_WEB_FILE_SUFFIXES = (".php", ".aspx", ".ashx", ".asmx", ".jsp", ".cfm")
# ... except these, which are included rather than requested.
_NON_ENDPOINT_HINTS = (
    "/vendor/", "/node_modules/", "/tests/", "/test/", "/config/",
    "/includes/", "/inc/", "/lib/", "/libs/", "/src/", "/app/",
)


def _file_routes(sf, framework: str, language: str, root: str) -> list:
    """The route a directly-requestable source file serves."""
    low = sf.path.lower()
    # A WebForms page's logic lives in `Page.aspx.cs`, whose extension is
    # `.cs`; the thing a browser requests is the `.aspx`. Matching only the
    # final extension missed every code-behind, which is the whole of an
    # ASP.NET WebForms app's surface.
    code_behind = any(low.endswith(s + ".cs") or low.endswith(s + ".vb")
                      for s in _WEB_FILE_SUFFIXES)
    suffix = os.path.splitext(sf.path)[1].lower()
    if suffix not in _WEB_FILE_SUFFIXES and not code_behind:
        return []
    rel = os.path.relpath(sf.path, root).replace(os.sep, "/")
    if any(hint in "/" + rel.lower() for hint in _NON_ENDPOINT_HINTS):
        return []
    url = "/" + rel
    for tail in (".aspx.cs", ".ashx.cs", ".asmx.cs", ".aspx.vb"):
        if url.lower().endswith(tail):
            url = url[:-3]
            break
    # Which request verbs it reads tells us the methods it really serves.
    text = sf.content.decode("utf-8", "replace")
    methods = []
    if re.search(r"\$_POST|\bRequest\.Form|\bIsPostBack", text):
        methods.append("POST")
    if re.search(r"\$_GET|\bRequest\.QueryString|\bRequest\[", text):
        methods.append("GET")
    params = sorted(set(
        re.findall(r"\$_(?:GET|POST|REQUEST)\s*\[\s*['\"]([\w.-]+)['\"]", text)
        + re.findall(r"Request(?:\.QueryString|\.Form)?\s*\[\s*\"([\w.-]+)\"",
                     text)
    ))
    guards = _guards_in(re.findall(r"(?:require|include)(?:_once)?\s*\(?\s*"
                                   r"['\"]([\w./-]+)['\"]", text))
    # A page that is served directly enforces its own access control in its
    # body, not at a declaration. DVWA writes
    # `dvwaPageStartup( array( 'authenticated' ) )`, where neither the
    # function name nor an include carries the signal — the argument does.
    # Reading only include names reported 163 of its 169 pages as open.
    guards += re.findall(
        r"\b(\w*(?:authenticat|authoris|authoriz|is_?logged_?in|"
        r"check_?auth|require_?login|must_?login|ensure_?login|"
        r"login_?required|is_?admin)\w*)\b", text, re.I)[:3]
    return [Route(
        method=methods[0] if len(methods) == 1 else (ANY if not methods else "GET,POST"),
        path=url, handler=os.path.basename(rel),
        file=sf.path, line=1, framework=framework, language=language,
        params=params, guards=list(dict.fromkeys(guards)),
        body=(sf.path, 1, max(1, text.count("\n") + 1)),
        declared=False)]


def _chained_guards(routes: list, sf) -> None:
    """Attach `->middleware('auth')` written after the route registration.

    Laravel and Slim return the route object so the guard can be chained on,
    which puts it in a sibling call rather than inside the registration this
    module matched. Scanning the declaration's own line for the chain is
    enough for the single-line form, which is how it is almost always
    written.
    """
    lines = sf.content.decode("utf-8", "replace").splitlines()
    for route in routes:
        if route.file != sf.path or route.line < 1 or route.line > len(lines):
            continue
        window = " ".join(lines[route.line - 1:route.line + 1])
        chained = re.findall(
            r"->(?:middleware|add)\s*\(\s*\[?\s*['\"]([\w:.|,\- ]+)['\"]",
            window)
        for group in chained:
            for name in re.split(r"[|,]", group):
                name = name.strip()
                if name and _is_guard(name) and name not in route.guards:
                    route.guards.append(name)
        if re.search(r"->(?:withoutMiddleware|allowAnonymous)\s*\(", window):
            route.guards.clear()


_ASSIGN_TYPES = (
    "assignment_expression", "assignment", "variable_declarator",
    "init_declarator", "pair", "property_assignment", "field_declaration",
    "short_var_declaration", "lexical_declaration", "property",
)


def _definition_index(files: list) -> dict:
    """Map every function-ish name to the spans that define it.

    Declarations alone are not enough. An Express controller is usually
    written `exports.get = async (req, res) => {...}` or as a property in an
    exported object, neither of which is a named function declaration — which
    is why only 5 of dvws-node's 36 handlers resolved before this.
    """
    spans: dict = {}

    def record(name: str, node, path: str) -> None:
        if name and node is not None:
            spans.setdefault(name, []).append(_body_span(node, path))

    for sf in files:
        for node in _walk(sf.root):
            if node.type in _FUNCTION_TYPES:
                record(_name_of(node), node, sf.path)
                continue
            if node.type not in _ASSIGN_TYPES:
                continue
            # `name = <function>` in any of its spellings.
            left = node.child_by_field_name("left") \
                or node.child_by_field_name("name") \
                or node.child_by_field_name("key") \
                or node.child_by_field_name("declarator")
            right = node.child_by_field_name("right") \
                or node.child_by_field_name("value")
            if left is None or right is None:
                continue
            if right.type not in _FUNCTION_TYPES:
                continue
            label = _text(left).strip()
            record(label, right, sf.path)
            tail = re.split(r"[.\[\]'\"]+", label)[-1]
            if tail and tail != label:
                record(tail, right, sf.path)
    return spans


def _resolve_handlers(routes: list, files: list) -> None:
    """Fill in the body span of routes whose handler is named elsewhere.

    `r.GET("/x", AuthCheck(sqli1Handler))` names a function defined further
    down the file or in another one. Without its span, nothing found inside
    it can be tied back to this route, which is most of the value.

    A name that several files define is only resolved when one of those
    definitions is in the route's own file, or when there is exactly one
    candidate overall. Dozens of Express controllers export a function
    called `get`; binding a route to whichever happened to be indexed first
    would attribute findings to the wrong endpoint, and a wrong entry point
    is worse than none — someone would go and test the wrong request.
    """
    spans = _definition_index(files)
    for route in routes:
        if route.body or not route.handler:
            continue
        tail = re.split(r"[.@:]", route.handler)[-1]
        for key in (route.handler, tail):
            candidates = spans.get(key) or []
            if not candidates:
                continue
            local = [c for c in candidates if c[0] == route.file]
            if len(local) == 1:
                route.body = local[0]
                break
            if len(candidates) == 1:
                route.body = candidates[0]
                break


def scan_routes(files: list, language: str, framework: str,
                root: str) -> list:
    """Every HTTP entry point one language pass can see."""
    routes: list = []
    for sf in files:
        found = _annotated_routes(sf, framework, language)
        found += _registered_routes(sf, framework, language)
        if language in ("php", "csharp"):
            found += _file_routes(sf, framework, language, root)
        _chained_guards(found, sf)
        routes.extend(found)
    _resolve_handlers(routes, files)
    return _dedupe(routes)


def _dedupe(routes: list) -> list:
    """One entry per method, path and declaration site."""
    seen: set = set()
    out: list = []
    for route in sorted(routes, key=lambda r: (r.path, r.method, r.file, r.line)):
        key = (route.method, route.path, route.file, route.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(route)
    return out


# ---------------------------------------------------------------------------
# Tying findings to the request that reaches them.

# Where a finding is reported last, in the order the binding tries them. The
# taint source comes first on purpose: it is where untrusted data entered,
# which is the handler the request actually hits. The sink can be several
# calls deep in a shared helper that a hundred routes reach, so binding on it
# first would attribute the finding to whichever route happened to match.
def _candidate_points(finding) -> list:
    points: list = []
    if finding.source is not None:
        points.append((finding.source.file, finding.source.line))
    for step in finding.trace:
        location = getattr(step, "location", None)
        if location is not None:
            points.append((location.file, location.line))
    points.append((finding.location.file, finding.location.line))
    seen: set = set()
    out: list = []
    for point in points:
        if point not in seen:
            seen.add(point)
            out.append(point)
    return out


def _handler_index(routes: list) -> dict:
    """Map each file to the handler spans it holds, narrowest first.

    A servlet's class span contains its `doGet` span, and a controller class
    contains every action. Sorting by width means the most specific handler
    wins, so a finding lands on the method that serves it rather than on the
    whole class.
    """
    index: dict = {}
    for route in routes:
        if not route.body:
            continue
        path, start, end = route.body
        index.setdefault(path, []).append((end - start, start, end, route))
    for spans in index.values():
        spans.sort(key=lambda s: (s[0], s[1]))
    return index


def bind_entry_points(findings: list, routes: list) -> int:
    """Attach the route that reaches each finding. Returns how many bound."""
    from ..models import EntryPoint

    index = _handler_index(routes)
    if not index:
        return 0
    bound = 0
    for finding in findings:
        match = None
        for file_path, line in _candidate_points(finding):
            for _, start, end, route in index.get(file_path, ()):
                if start <= line <= end:
                    match = route
                    break
            if match is not None:
                break
        if match is None:
            continue
        finding.entry_point = EntryPoint(
            method=match.method, path=match.path, handler=match.handler,
            guards=list(match.guards), file=match.file, line=match.line)
        bound += 1
    return bound


# Sort order for how exposed a finding is. Lower sorts first.
#
# "No guard found" leads, because that is where an auditor starts. "Guarded"
# sorts last, since reaching it needs credentials first. Findings with no
# entry point sit between the two rather than at the bottom: route extraction
# is incomplete by nature, and a library, a CLI tool or a C program has no
# routes at all — burying everything in those below guarded web routes would
# hide real bugs behind an artefact of this analysis. The dependency
# reachability ranking makes the same choice for the same reason.
EXPOSURE_OPEN, EXPOSURE_UNKNOWN, EXPOSURE_GUARDED = 0, 1, 2


def exposure_rank(finding) -> int:
    entry = getattr(finding, "entry_point", None)
    if entry is None:
        return EXPOSURE_UNKNOWN
    return EXPOSURE_GUARDED if entry.guarded else EXPOSURE_OPEN


def exposure_label(finding) -> str:
    entry = getattr(finding, "entry_point", None)
    if entry is None:
        return "no entry point found"
    if entry.guarded:
        return "guarded by " + ", ".join(entry.guards)
    return "no guard found"


def surface_summary(routes: list) -> dict:
    """Counts for the report header."""
    return {
        "total": len(routes),
        "open": sum(1 for r in routes if r.open),
        "guarded": sum(1 for r in routes if not r.open),
        "frameworks": sorted({r.framework for r in routes if r.framework}),
    }
