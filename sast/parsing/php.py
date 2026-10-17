"""PHP parsing via tree-sitter."""
from __future__ import annotations

import tree_sitter
import tree_sitter_php
from tree_sitter import Language, Parser

from .source import SourceFile

_PHP_LANGUAGE = Language(tree_sitter_php.language_php())


class PhpParser:
    """Parser for PHP source. Reusable across files (single-threaded)."""

    def __init__(self) -> None:
        self._parser = Parser(_PHP_LANGUAGE)

    def parse(self, path: str, content: bytes) -> SourceFile:
        tree = self._parser.parse(content)
        return SourceFile(path=path, content=content, tree=tree, language="php")

    def parse_text(self, path: str, text: str) -> SourceFile:
        return self.parse(path, text.encode("utf-8"))
