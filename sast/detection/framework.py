"""Framework auto-detection for PHP and Java projects."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional

# PHP frameworks — composer package → framework name.
COMPOSER_FRAMEWORKS = [
    ("laravel/framework", "Laravel"),
    ("symfony/framework-bundle", "Symfony"),
    ("symfony/http-kernel", "Symfony"),
    ("symfony/http-foundation", "Symfony"),
    ("cakephp/cakephp", "CakePHP"),
    ("yiisoft/yii2", "Yii"),
    ("codeigniter4/framework", "CodeIgniter"),
    ("slim/slim", "Slim"),
]

# Java frameworks — maven artifact → framework name.
MAVEN_FRAMEWORKS = [
    ("spring-boot-starter-parent", "Spring Boot"),
    ("spring-boot-starter-web", "Spring Boot"),
    ("spring-boot", "Spring Boot"),
    ("spring-context", "Spring"),
    ("spring-web", "Spring"),
    ("spring-webmvc", "Spring"),
    ("spring-boot-starter", "Spring Boot"),
    ("jakarta.servlet", "Jakarta EE"),
    ("javax.servlet", "Jakarta EE"),
]

# Spring Boot / Spring annotation markers in source.
_SPRING_BOOT_RE = re.compile(r"@SpringBootApplication\b")
_SPRING_RE = re.compile(
    r"@(RestController|Controller|Service|Component|Repository|Autowired|"
    r"RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|"
    r"PathVariable|RequestParam|RequestBody|Configuration|Bean)\b"
)


@dataclass
class ProjectProfile:
    """Everything the engine knows about a scanned project."""
    root: str
    language: str                          # "php" | "java"
    framework: str = "raw"                 # "Laravel", "Symfony", "Spring", "Spring Boot", "raw", ...
    version: Optional[str] = None
    manifest_files: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    @property
    def is_framework(self) -> bool:
        return self.framework not in ("raw", "none", "")

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "language": self.language,
            "framework": self.framework,
            "version": self.version,
            "manifest_files": self.manifest_files,
            "notes": self.notes,
        }


def _read_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def _detect_php_framework(root: str) -> tuple[str, Optional[str], list[str], list[str]]:
    composer_path = os.path.join(root, "composer.json")
    if not os.path.isfile(composer_path):
        return "raw", None, [], []
    data = _read_json(composer_path)
    if not data:
        return "raw", None, [composer_path], ["composer.json unreadable"]

    deps = {}
    deps.update(data.get("require", {}) or {})
    deps.update(data.get("require-dev", {}) or {})

    for pkg, framework in COMPOSER_FRAMEWORKS:
        if pkg in deps:
            version = deps[pkg]
            return framework, version, [composer_path], []

    # Symfony components without the full framework bundle.
    symfony_components = [k for k in deps if k.startswith("symfony/")]
    if symfony_components:
        return "Symfony", None, [composer_path], []

    return "raw", None, [composer_path], []


def _detect_java_framework(root: str, source_files: list[str]) -> tuple[str, Optional[str], list[str], list[str]]:
    manifest_files: list[str] = []
    notes: list[str] = []

    pom = os.path.join(root, "pom.xml")
    gradle = os.path.join(root, "build.gradle")

    manifest_text = ""
    if os.path.isfile(pom):
        manifest_files.append(pom)
        with open(pom, "r", encoding="utf-8", errors="replace") as fh:
            manifest_text += fh.read()
    if os.path.isfile(gradle):
        manifest_files.append(gradle)
        with open(gradle, "r", encoding="utf-8", errors="replace") as fh:
            manifest_text += fh.read()

    found = None
    found_version = None
    for artifact, framework in MAVEN_FRAMEWORKS:
        if artifact in manifest_text:
            found = framework
            m = re.search(
                rf"{re.escape(artifact)}[^0-9]*?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
                manifest_text,
            )
            if m:
                found_version = m.group(1)
            break

    if found:
        return found, found_version, manifest_files, notes

    # Fall back to scanning source for Spring annotations.
    for sf in source_files[:200]:
        try:
            with open(sf, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        if _SPRING_BOOT_RE.search(text):
            return "Spring Boot", None, manifest_files, notes
        if _SPRING_RE.search(text):
            return "Spring", None, manifest_files, notes

    return "raw", None, manifest_files, notes


def detect_framework(root: str, language: str, source_files: list[str]) -> ProjectProfile:
    """Auto-detect the framework (if any) for a project."""
    if language == "php":
        framework, version, manifests, notes = _detect_php_framework(root)
    elif language == "java":
        framework, version, manifests, notes = _detect_java_framework(root, source_files)
    else:
        framework, version, manifests, notes = "raw", None, [], []

    return ProjectProfile(
        root=root,
        language=language,
        framework=framework,
        version=version,
        manifest_files=manifests,
        notes=notes,
    )
