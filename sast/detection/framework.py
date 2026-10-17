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

# JavaScript frameworks — npm package → framework name. Ordered so the most
# specific wins: a Next.js app also depends on react, and NestJS on express.
NPM_FRAMEWORKS = [
    ("@angular/core", "Angular"),
    ("@nestjs/core", "NestJS"),
    ("next", "Next.js"),
    ("react", "React"),
    ("react-dom", "React"),
    ("express", "Express"),
    ("koa", "Koa"),
    ("fastify", "Fastify"),
    ("vue", "Vue"),
    ("@sveltejs/kit", "SvelteKit"),
]

# Source markers, used when package.json is absent or uninformative.
_ANGULAR_RE = re.compile(r"@(?:Component|NgModule|Injectable)\s*\(|@angular/core")
_REACT_RE = re.compile(r"from\s+['\"]react['\"]|require\(['\"]react['\"]\)|"
                       r"React\.(?:createElement|Component)|useState\s*\(")
_EXPRESS_RE = re.compile(r"require\(['\"]express['\"]\)|from\s+['\"]express['\"]")
_NODE_RE = re.compile(r"require\(['\"](?:fs|path|child_process|http|crypto)['\"]\)|"
                      r"from\s+['\"]node:|module\.exports|process\.env")

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
    # Directories holding a dependency manifest. For a single-module project
    # this is just [root]; for a monorepo it is every module found.
    module_dirs: list = field(default_factory=list)

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
            "module_dirs": self.module_dirs,
        }


# How deep below the scan root to look for module manifests.
_MAX_MANIFEST_DEPTH = 4


def find_manifest_dirs(root: str, names: tuple, max_depth: int = _MAX_MANIFEST_DEPTH) -> list[str]:
    """Directories under `root` containing any of `names`, shallowest first.

    Lets a monorepo or multi-module Maven build be recognised instead of
    resolving to "raw" because the root holds no manifest of its own.
    """
    from .language import IGNORED_DIRS

    found: list[str] = []
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = dirpath[len(root):].count(os.sep)
        if depth >= max_depth:
            dirnames[:] = []
        dirnames[:] = [
            d for d in dirnames if d not in IGNORED_DIRS and not d.startswith(".")
        ]
        if any(n in filenames for n in names):
            found.append(dirpath)
    found.sort(key=lambda p: (p[len(root):].count(os.sep), p))
    return found


def _read_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def _detect_php_framework(root: str) -> tuple[str, Optional[str], list[str], list[str], list[str]]:
    module_dirs = find_manifest_dirs(root, ("composer.json",))
    if not module_dirs:
        return "raw", None, [], [], []

    manifests: list[str] = []
    notes: list[str] = []
    fallback_symfony = False

    for mod in module_dirs:
        composer_path = os.path.join(mod, "composer.json")
        manifests.append(composer_path)
        data = _read_json(composer_path)
        if not data:
            notes.append(f"{composer_path} unreadable")
            continue

        deps = {}
        deps.update(data.get("require", {}) or {})
        deps.update(data.get("require-dev", {}) or {})

        for pkg, framework in COMPOSER_FRAMEWORKS:
            if pkg in deps:
                return framework, deps[pkg], manifests, notes, module_dirs

        # Symfony components without the full framework bundle.
        if any(k.startswith("symfony/") for k in deps):
            fallback_symfony = True

    if fallback_symfony:
        return "Symfony", None, manifests, notes, module_dirs
    return "raw", None, manifests, notes, module_dirs


def _detect_java_framework(root: str, source_files: list[str]) -> tuple[str, Optional[str], list[str], list[str], list[str]]:
    manifest_files: list[str] = []
    notes: list[str] = []

    # Aggregate every module's manifest, so a multi-module build whose root
    # pom declares nothing still resolves to the right framework.
    module_dirs = find_manifest_dirs(root, ("pom.xml", "build.gradle", "build.gradle.kts"))
    manifest_text = ""
    for mod in module_dirs:
        for name in ("pom.xml", "build.gradle", "build.gradle.kts"):
            path = os.path.join(mod, name)
            if not os.path.isfile(path):
                continue
            manifest_files.append(path)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    manifest_text += fh.read()
            except OSError:
                notes.append(f"{path} unreadable")

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
        return found, found_version, manifest_files, notes, module_dirs

    # Fall back to scanning source for Spring annotations.
    for sf in source_files[:200]:
        try:
            with open(sf, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        if _SPRING_BOOT_RE.search(text):
            return "Spring Boot", None, manifest_files, notes, module_dirs
        if _SPRING_RE.search(text):
            return "Spring", None, manifest_files, notes, module_dirs

    return "raw", None, manifest_files, notes, module_dirs


def _detect_js_framework(root: str, source_files: list[str]) -> tuple:
    """Detect the JS framework from package.json, then from source markers."""
    module_dirs = find_manifest_dirs(root, ("package.json",))
    manifests: list[str] = []
    notes: list[str] = []
    best: tuple = ()

    for mod in module_dirs:
        pkg_path = os.path.join(mod, "package.json")
        manifests.append(pkg_path)
        data = _read_json(pkg_path)
        if not data:
            notes.append(f"{pkg_path} unreadable")
            continue
        deps = {}
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            deps.update(data.get(section, {}) or {})
        for index, (pkg, framework) in enumerate(NPM_FRAMEWORKS):
            if pkg in deps:
                # Keep the earliest (most specific) match across all modules.
                if not best or index < best[0]:
                    best = (index, framework, deps[pkg])
                break

    if best:
        return best[1], best[2], manifests, notes, module_dirs

    # No manifest match — fall back to markers in the source itself.
    found = None
    for sf in source_files[:200]:
        try:
            with open(sf, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(20000)
        except OSError:
            continue
        if _ANGULAR_RE.search(text):
            return "Angular", None, manifests, notes, module_dirs
        if _REACT_RE.search(text):
            return "React", None, manifests, notes, module_dirs
        if _EXPRESS_RE.search(text):
            return "Express", None, manifests, notes, module_dirs
        if found is None and _NODE_RE.search(text):
            found = "Node.js"
    return found or "raw", None, manifests, notes, module_dirs


def detect_framework(root: str, language: str, source_files: list[str]) -> ProjectProfile:
    """Auto-detect the framework (if any) for a project."""
    if language == "php":
        framework, version, manifests, notes, modules = _detect_php_framework(root)
    elif language == "java":
        framework, version, manifests, notes, modules = _detect_java_framework(root, source_files)
    elif language == "javascript":
        framework, version, manifests, notes, modules = _detect_js_framework(root, source_files)
    else:
        framework, version, manifests, notes, modules = "raw", None, [], [], []

    return ProjectProfile(
        root=root,
        language=language,
        framework=framework,
        version=version,
        manifest_files=manifests,
        notes=notes,
        module_dirs=modules or [root],
    )
