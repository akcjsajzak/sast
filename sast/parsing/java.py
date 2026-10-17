"""Java parsing via tree-sitter."""
from __future__ import annotations

import tree_sitter
import tree_sitter_java
from tree_sitter import Language, Parser

from .source import SourceFile

_JAVA_LANGUAGE = Language(tree_sitter_java.language())


class JavaParser:
    def __init__(self) -> None:
        self._parser = Parser(_JAVA_LANGUAGE)

    def parse(self, path: str, content: bytes) -> SourceFile:
        tree = self._parser.parse(content)
        return SourceFile(path=path, content=content, tree=tree, language="java")
