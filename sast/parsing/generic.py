"""Parsing for the languages served by the generic taint engine."""
from __future__ import annotations

import os

from tree_sitter import Language, Parser

from .source import SourceFile

_LANGUAGES: dict = {}


def _load(name: str):
    """Import a tree-sitter grammar lazily, so one missing grammar does not
    prevent the whole tool from starting."""
    if name in _LANGUAGES:
        return _LANGUAGES[name]
    lang = None
    try:
        if name == "python":
            import tree_sitter_python as m
            lang = Language(m.language())
        elif name == "go":
            import tree_sitter_go as m
            lang = Language(m.language())
        elif name == "csharp":
            import tree_sitter_c_sharp as m
            lang = Language(m.language())
        elif name == "c":
            import tree_sitter_c as m
            lang = Language(m.language())
        elif name == "cpp":
            import tree_sitter_cpp as m
            lang = Language(m.language())
    except Exception:  # noqa: BLE001 — a missing grammar disables one language
        lang = None
    _LANGUAGES[name] = lang
    return lang


# Extension -> engine language name. C headers are parsed as C++ so that a
# header shared between the two still parses when it uses C++ constructs.
EXTENSION_LANGUAGE = {
    ".py": "python", ".pyi": "python",
    ".go": "go",
    ".cs": "csharp",
    ".c": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".c++": "cpp",
    ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp",
    ".h": "cpp",
}


class GenericParser:
    """Parses any language the generic engine supports."""

    def __init__(self, language: str) -> None:
        self.language = language
        self._parser = None
        lang = _load(language)
        if lang is not None:
            self._parser = Parser(lang)

    @property
    def available(self) -> bool:
        return self._parser is not None

    def parse(self, path: str, content: bytes) -> SourceFile:
        tree = self._parser.parse(content)
        return SourceFile(path=path, content=content, tree=tree,
                          language=self.language)

    def parse_text(self, path: str, text: str) -> SourceFile:
        return self.parse(path, text.encode("utf-8"))


def language_for(path: str) -> str:
    return EXTENSION_LANGUAGE.get(os.path.splitext(path)[1].lower(), "")
