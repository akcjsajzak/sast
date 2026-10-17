"""Rule registry: holds per-language rule sets and filters by framework."""
from __future__ import annotations

from .base import RuleSet
from .java_rules import build_java_rules
from .php_rules import build_php_rules, TAG_LABELS


class Registry:
    def __init__(self) -> None:
        self._by_language = {
            "php": build_php_rules(),
            "java": build_java_rules(),
        }
        self.tag_labels = TAG_LABELS

    def add_language(self, language: str, ruleset: RuleSet) -> None:
        self._by_language[language] = ruleset

    def rules_for(self, language: str, framework: str) -> RuleSet:
        rs = self._by_language.get(language)
        if rs is None:
            return RuleSet()
        return rs.for_framework(framework)
