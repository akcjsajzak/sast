"""Rule registry: holds per-language rule sets and filters by framework."""
from __future__ import annotations

from .base import RuleSet
from .c_rules import build_c_rules
from .csharp_rules import build_csharp_rules
from .go_rules import build_go_rules
from .java_rules import build_java_rules
from .js_rules import build_js_rules
from .php_rules import build_php_rules, TAG_LABELS
from .python_rules import build_python_rules


class Registry:
    def __init__(self) -> None:
        _c_rules = build_c_rules()  # C and C++ share a rule set
        self._by_language = {
            "php": build_php_rules(),
            "java": build_java_rules(),
            "javascript": build_js_rules(),
            "python": build_python_rules(),
            "go": build_go_rules(),
            "csharp": build_csharp_rules(),
            "c": _c_rules,
            "cpp": _c_rules,
        }
        self.tag_labels = TAG_LABELS

    def add_language(self, language: str, ruleset: RuleSet) -> None:
        self._by_language[language] = ruleset

    def rules_for(self, language: str, framework: str) -> RuleSet:
        rs = self._by_language.get(language)
        if rs is None:
            return RuleSet()
        return rs.for_framework(framework)
