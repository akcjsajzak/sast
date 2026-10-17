"""Offline dependency vulnerability advisory database and matching."""
from .db import AdvisoryDB, Advisory
from .analyzer import analyze_dependencies
from .composer import parse_composer_lock

__all__ = ["AdvisoryDB", "Advisory", "analyze_dependencies", "parse_composer_lock"]
