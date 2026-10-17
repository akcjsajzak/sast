"""JavaScript / TypeScript parsing via tree-sitter.

Three grammars are needed: the JavaScript grammar already understands JSX, so
it covers .js/.jsx/.mjs/.cjs, while TypeScript needs its own and TSX a third
(the `<T>` of a type assertion and the `<div>` of JSX are ambiguous, which is
why upstream ships them separately).
"""
from __future__ import annotations

import os

import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language, Parser

from .source import SourceFile

_JS_LANGUAGE = Language(tree_sitter_javascript.language())
_TS_LANGUAGE = Language(tree_sitter_typescript.language_typescript())
_TSX_LANGUAGE = Language(tree_sitter_typescript.language_tsx())

# Extension -> grammar. Angular is TypeScript and React is often TSX, so both
# are needed for framework coverage rather than being a nicety.
_BY_EXTENSION = {
    ".js": _JS_LANGUAGE,
    ".jsx": _JS_LANGUAGE,
    ".mjs": _JS_LANGUAGE,
    ".cjs": _JS_LANGUAGE,
    ".ts": _TS_LANGUAGE,
    ".mts": _TS_LANGUAGE,
    ".cts": _TS_LANGUAGE,
    ".tsx": _TSX_LANGUAGE,
}


class JsParser:
    """Parser for JavaScript and TypeScript, picking a grammar per file."""

    def __init__(self) -> None:
        self._parsers = {}

    def _parser_for(self, path: str) -> Parser:
        ext = os.path.splitext(path)[1].lower()
        language = _BY_EXTENSION.get(ext, _JS_LANGUAGE)
        parser = self._parsers.get(id(language))
        if parser is None:
            parser = Parser(language)
            self._parsers[id(language)] = parser
        return parser

    def parse(self, path: str, content: bytes) -> SourceFile:
        tree = self._parser_for(path).parse(content)
        return SourceFile(path=path, content=content, tree=tree, language="javascript")

    def parse_text(self, path: str, text: str) -> SourceFile:
        return self.parse(path, text.encode("utf-8"))
