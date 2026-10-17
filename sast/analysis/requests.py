"""Turn an entry-point-bound finding into the shape of a request to send.

A trace proves a path through the code. It does not tell you what to send.
Once a finding knows its route, the last gap is mechanical: the route gives
the method and the URL, and the taint source gives the parameter name and
where in the request it travels. Putting those together produces a `curl`
skeleton that targets exactly the input the finding flows from, which is the
artefact an audit hands over.

The parameter's value is left as a named placeholder, e.g.
`<sql-injection payload>`, rather than a concrete string. The skeleton's job
is to point at the right input in the right request; which payload confirms
the bug is the tester's call, and this tool does not ship an exploit
catalogue. The host is a placeholder too, because the only thing worse than
no request is a correct-looking one aimed at the wrong target.
"""
from __future__ import annotations

import re

# Stand-in for the host under test. Deliberately not a real default: a
# tester substitutes it once, and nobody fires a request at localhost by
# accident because the command looked complete.
TARGET = "http://TARGET"

# Where in a request a parameter travels, which decides the curl flag.
QUERY, BODY, HEADER, COOKIE, PATH = "query", "body", "header", "cookie", "path"

# How each framework names the thing it read, and where that thing lives.
# Matched against the source line of the taint origin, which is the line the
# engine already stores for every finding.
_PARAM_PATTERNS = (
    # Java servlet / Spring
    (r'getParameterValues?\s*\(\s*"([^"]+)"', QUERY),
    (r'getHeaders?\s*\(\s*"([^"]+)"', HEADER),
    (r'getCookies?\s*\(\s*"([^"]+)"', COOKIE),
    (r'@RequestParam\s*\(\s*(?:value\s*=\s*)?"([^"]+)"', QUERY),
    (r'@PathVariable\s*\(\s*(?:value\s*=\s*)?"([^"]+)"', PATH),
    (r'@RequestHeader\s*\(\s*(?:value\s*=\s*)?"([^"]+)"', HEADER),
    # PHP
    (r'\$_GET\s*\[\s*[\'"]([^\'"]+)', QUERY),
    (r'\$_(?:POST|FILES)\s*\[\s*[\'"]([^\'"]+)', BODY),
    (r'\$_REQUEST\s*\[\s*[\'"]([^\'"]+)', QUERY),
    (r'\$_COOKIE\s*\[\s*[\'"]([^\'"]+)', COOKIE),
    (r'\$_SERVER\s*\[\s*[\'"]HTTP_([A-Z_]+)', HEADER),
    # Node / Express
    (r'req(?:uest)?\.query(?:\.|\[\s*[\'"])(\w+)', QUERY),
    (r'req(?:uest)?\.body(?:\.|\[\s*[\'"])(\w+)', BODY),
    (r'req(?:uest)?\.params(?:\.|\[\s*[\'"])(\w+)', PATH),
    (r'req(?:uest)?\.headers(?:\.|\[\s*[\'"])([\w-]+)', HEADER),
    (r'req(?:uest)?\.cookies(?:\.|\[\s*[\'"])(\w+)', COOKIE),
    # Python: Flask and Django
    (r'request\.args(?:\.get)?\s*[\(\[]\s*[\'"]([^\'"]+)', QUERY),
    (r'request\.form(?:\.get)?\s*[\(\[]\s*[\'"]([^\'"]+)', BODY),
    (r'request\.GET(?:\.get)?\s*[\(\[]\s*[\'"]([^\'"]+)', QUERY),
    (r'request\.POST(?:\.get)?\s*[\(\[]\s*[\'"]([^\'"]+)', BODY),
    (r'request\.headers(?:\.get)?\s*[\(\[]\s*[\'"]([^\'"]+)', HEADER),
    (r'request\.COOKIES(?:\.get)?\s*[\(\[]\s*[\'"]([^\'"]+)', COOKIE),
    (r'request\.data(?:\.get)?\s*[\(\[]\s*[\'"]([^\'"]+)', BODY),
    # Go
    (r'\.Query\s*\(\s*"([^"]+)"', QUERY),
    (r'\.PostForm(?:Value)?\s*\(\s*"([^"]+)"', BODY),
    (r'\.FormValue\s*\(\s*"([^"]+)"', QUERY),
    (r'\.Param\s*\(\s*"([^"]+)"', PATH),
    (r'\.GetHeader\s*\(\s*"([^"]+)"', HEADER),
    # C# / ASP.NET
    (r'Request\.QueryString\s*\[\s*"([^"]+)"', QUERY),
    (r'Request\.Form\s*\[\s*"([^"]+)"', BODY),
    (r'Request\.Headers\s*\[\s*"([^"]+)"', HEADER),
    (r'Request\.Cookies\s*\[\s*"([^"]+)"', COOKIE),
    (r'Request\s*\[\s*"([^"]+)"', QUERY),
)

# A path parameter has to be filled in with something for the URL to be
# valid; the value is rarely what is being tested.
_PATH_PLACEHOLDER = "1"
_PATH_TOKEN = re.compile(r"\{[^}]*\}|<[^>]*>|:[A-Za-z_]\w*|\*")


def _placeholder(category: str) -> str:
    """A named stand-in for the value the tester supplies.

    Carries the finding's own category so the skeleton says what kind of
    input belongs there without embedding a payload.
    """
    cat = (category or "input").lower()
    return f"<{cat} payload>"


def _param_of(finding) -> tuple:
    """The parameter carrying the taint, as (name, where).

    Read from the source line first, then the trace, because the origin is
    where the request was unpacked. Returns ('', '') when no framework
    accessor is recognisable — a second-order flow out of a database has no
    request parameter to name, and inventing one would be a lie.
    """
    lines: list = []
    if finding.source is not None and finding.source.code:
        lines.append(finding.source.code)
    for step in finding.trace:
        code = getattr(step, "code", "") or ""
        if code:
            lines.append(code)
    if finding.location.code:
        lines.append(finding.location.code)
    for line in lines:
        for pattern, where in _PARAM_PATTERNS:
            match = re.search(pattern, line)
            if match and match.group(1):
                return match.group(1), where
    return "", ""


def _fill_path(path: str) -> str:
    """Substitute a concrete value for each declared path parameter."""
    filled = _PATH_TOKEN.sub(_PATH_PLACEHOLDER, path or "/")
    if not filled.startswith("/"):
        filled = "/" + filled
    return filled


def _quote(value: str) -> str:
    """Single-quote for a POSIX shell."""
    return "'" + value.replace("'", "'\\''") + "'"


def _method_for(entry, where: str) -> str:
    """The verb to send.

    A route registered for several methods, or for none in particular, still
    has to be sent as one. Where the parameter lives decides it: a body
    parameter cannot ride a GET.
    """
    declared = [m for m in (entry.method or "").replace(",", " ").split() if m]
    if where == BODY:
        for candidate in ("POST", "PUT", "PATCH"):
            if candidate in declared:
                return candidate
        return "POST"
    for candidate in declared:
        if candidate != "ANY":
            return candidate
    return "GET"


def build_request(finding) -> str:
    """A curl skeleton reproducing one finding, or '' if it has no entry point."""
    entry = getattr(finding, "entry_point", None)
    if entry is None:
        return ""
    name, where = _param_of(finding)
    value = _placeholder(finding.category)
    url = TARGET + _fill_path(entry.path)
    method = _method_for(entry, where)

    parts = ["curl -i"]
    if method != "GET":
        parts.append("-X " + method)
    if entry.guards:
        # The route has an authorisation check, so the request needs a
        # credential before it proves anything. Naming the guard that was
        # found is more use than a bare placeholder.
        parts.append("-H " + _quote("Authorization: <credential for "
                                    + ", ".join(entry.guards) + ">"))
    if not name:
        parts.append(_quote(url))
        return " ".join(parts) + \
            "   # parameter not identified; taint source is not a request accessor"
    if where == PATH:
        url = TARGET + _fill_path(entry.path).replace(
            "/" + _PATH_PLACEHOLDER, "/" + value, 1)
        parts.append(_quote(url))
    elif where == HEADER:
        parts.extend([_quote(url), "-H " + _quote(f"{name}: {value}")])
    elif where == COOKIE:
        parts.extend([_quote(url), "-b " + _quote(f"{name}={value}")])
    elif where == BODY:
        parts.extend([_quote(url),
                      "--data-urlencode " + _quote(f"{name}={value}")])
    else:
        parts.extend(["-G", _quote(url),
                      "--data-urlencode " + _quote(f"{name}={value}")])
    return " ".join(parts)


def build_requests(findings: list) -> int:
    """Attach a request skeleton to every finding that has an entry point."""
    built = 0
    for finding in findings:
        skeleton = build_request(finding)
        if skeleton:
            finding.request = skeleton
            built += 1
    return built
