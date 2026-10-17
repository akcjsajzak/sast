"""Language and framework detection."""
from .language import detect_language, collect_source_files
from .framework import detect_framework, ProjectProfile

__all__ = [
    "detect_language",
    "collect_source_files",
    "detect_framework",
    "ProjectProfile",
]
