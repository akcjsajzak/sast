"""Container and image scanning.

Two parts:

1. **Dockerfile analysis** — build-time decisions that become runtime
   exposure: running as root, pinning to `latest`, baking secrets into layers,
   piping a remote script into a shell.
2. **Base image vulnerability matching** — the `FROM` line names an image and
   tag, which is matched against the advisory database the same way a package
   dependency is. OS distro advisories (Alpine, Debian, Ubuntu) are available
   as OSV ecosystems, so an outdated base image is reported like any other
   vulnerable dependency.

Pulling and unpacking an image is deliberately out of scope: it needs a
daemon and a network, and this tool must run fully offline. Where a build has
already produced an SBOM, that is ingested instead.
"""
from __future__ import annotations

import json
import os
import re

from ..models import DependencyIssue, Finding, Location, Severity, TaintStep

A05 = "A05:2021 — Security Misconfiguration"
A07 = "A07:2021 — Identification and Authentication Failures"
A08 = "A08:2021 — Software and Data Integrity Failures"

DOCKERFILE_NAMES = ("dockerfile", "containerfile")


class _Rule:
    def __init__(self, rule_id, pattern, title, description, remediation,
                 severity="medium", cwe="CWE-16", owasp=A05,
                 category="container-misconfiguration", confidence="high"):
        self.rule_id = rule_id
        self.regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        self.title = title
        self.description = description
        self.remediation = remediation
        self.severity = severity
        self.cwe = cwe
        self.owasp = owasp
        self.category = category
        self.confidence = confidence


_RULES = [
    _Rule("container-latest-tag",
          r"^\s*FROM\s+\S+:latest(?:\s|$)|^\s*FROM\s+([a-z0-9._\-/]+)\s*$",
          "Base image is unpinned",
          "An image without a pinned tag or digest means the build is not "
          "reproducible and a rebuild can silently pull in different — possibly "
          "backdoored — content.",
          "Pin to an explicit version, ideally by digest (image@sha256:...).",
          severity="low", cwe="CWE-1104", owasp=A08, category="supply-chain"),
    _Rule("container-curl-pipe-shell",
          r"(?:curl|wget)[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k|)sh",
          "Remote script piped into a shell",
          "Downloading a script and executing it unverified means whoever "
          "controls that URL (now or later) controls your build.",
          "Download to a file, verify a checksum or signature, then run it.",
          severity="high", cwe="CWE-494", owasp=A08, category="supply-chain"),
    _Rule("container-add-remote",
          r"^\s*ADD\s+https?://",
          "ADD used to fetch a remote URL",
          "ADD silently fetches and unpacks remote content with no integrity "
          "check.",
          "Use COPY for local files; fetch remote content explicitly and verify it.",
          severity="medium", cwe="CWE-494", owasp=A08, category="supply-chain"),
    _Rule("container-secret-in-env",
          r"^\s*(?:ENV|ARG)\s+[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|"
          r"API_?KEY|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*[\s=]+\S{6,}",
          "Credential baked into an image layer",
          "ENV and ARG values persist in the image history, so anyone who can "
          "pull the image can read the credential — deleting it in a later "
          "layer does not remove it.",
          "Pass secrets at runtime, or use BuildKit secret mounts.",
          severity="critical", cwe="CWE-798", owasp=A07, category="hardcoded-secret"),
    _Rule("container-sudo",
          r"^\s*RUN\s+.*\bsudo\b",
          "sudo used inside a container build",
          "sudo in a container is unnecessary (builds already run as root) and "
          "it leaves a privilege-escalation path in the final image.",
          "Drop sudo and use USER to switch accounts.",
          severity="low", cwe="CWE-250", owasp=A05,
          category="excessive-permissions"),
    _Rule("container-apt-no-verify",
          r"--allow-unauthenticated|--force-yes|--no-check-certificate|"
          r"GPGCHECK\s*=\s*0|sslverify\s*=\s*false",
          "Package signature or certificate verification disabled",
          "Disabling verification means packages installed into the image are "
          "not authenticated.",
          "Leave verification on and add the correct keys or CA bundle.",
          severity="high", cwe="CWE-494", owasp=A08, category="supply-chain"),
    _Rule("container-chmod-777",
          r"chmod\s+(?:-R\s+)?777",
          "World-writable permissions set",
          "chmod 777 makes files writable by any process in the container.",
          "Grant the narrowest permissions the process needs.",
          severity="medium", cwe="CWE-732", owasp=A05,
          category="excessive-permissions"),
    _Rule("container-ssh-exposed",
          r"^\s*EXPOSE\s+(?:.*\s)?22(?:\s|/|$)",
          "SSH port exposed from a container",
          "Running SSH inside a container adds an authentication surface that "
          "the orchestrator already provides better (exec/attach).",
          "Remove sshd; use the orchestrator's exec facility instead.",
          severity="medium", cwe="CWE-284", owasp=A05,
          category="network-exposure"),
]

# `USER root` (or no USER at all) is checked across the whole file rather than
# line by line, so it gets its own handling below.
_USER_RE = re.compile(r"^\s*USER\s+(\S+)", re.IGNORECASE | re.MULTILINE)
_FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?([A-Za-z0-9._\-/:@]+)(?:\s+AS\s+\S+)?\s*$",
    re.IGNORECASE | re.MULTILINE,
)

# Base images mapped to the OSV ecosystem that carries their advisories.
_DISTRO_ECOSYSTEMS = {
    "alpine": "Alpine",
    "debian": "Debian",
    "ubuntu": "Ubuntu",
    "centos": "Rocky Linux",
    "rockylinux": "Rocky Linux",
    "almalinux": "AlmaLinux",
}


def collect_dockerfiles(root: str) -> list[str]:
    from ..detection.language import IGNORED_DIRS

    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames if d not in IGNORED_DIRS and not d.startswith(".")
        ]
        for fname in filenames:
            low = fname.lower()
            if low in DOCKERFILE_NAMES or low.startswith("dockerfile."):
                out.append(os.path.join(dirpath, fname))
            elif low.endswith(".dockerfile"):
                out.append(os.path.join(dirpath, fname))
    out.sort()
    return out


def scan_dockerfiles(paths: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        lines = text.splitlines()

        for rule in _RULES:
            seen: set = set()
            for m in rule.regex.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                if line_no in seen:
                    continue
                seen.add(line_no)
                code = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
                if rule.category == "hardcoded-secret":
                    code = _redact(code)
                findings.append(_finding(rule, path, line_no, code))

        # Final USER: root (or absent) means the container runs as uid 0.
        users = _USER_RE.findall(text)
        if not users or users[-1].strip().lower() in ("root", "0"):
            line_no = 1
            # Point at the instruction that decides it: the last USER, or
            # with none, the last FROM (the stage that runs). Line 1 may be
            # a comment, as in `# FROM node:6` above the real one.
            for m in (_USER_RE if users else _FROM_RE).finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
            code = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
            findings.append(_finding(_Rule(
                "container-runs-as-root", r"x",
                "Container runs as root",
                "No non-root USER is set, so the entrypoint runs as uid 0. Any "
                "code-execution flaw in the application then has root inside the "
                "container, which is the starting point for most escapes.",
                "Create an unprivileged user and add a USER instruction before "
                "the entrypoint.",
                severity="medium", cwe="CWE-250", owasp=A05,
                category="excessive-permissions",
            ), path, line_no, code))
    return findings


def base_images(paths: list[str]) -> list[tuple[str, str, str, int]]:
    """Return [(path, image, tag, line)] for every FROM instruction."""
    out: list[tuple[str, str, str, int]] = []
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for m in _FROM_RE.finditer(text):
            ref = m.group(1)
            if ref.lower() in ("scratch",) or ref.startswith("$"):
                continue
            # Ignore references to an earlier build stage.
            image, _, tag = ref.partition(":")
            if "@" in tag:
                tag = tag.split("@", 1)[0]
            line_no = text.count("\n", 0, m.start()) + 1
            out.append((path, image, tag or "latest", line_no))
    return out


def scan_base_images(paths: list[str], db) -> list[DependencyIssue]:
    """Match base images against distro advisories in the offline DB."""
    issues: list[DependencyIssue] = []
    seen: set = set()
    for _path, image, tag, _line in base_images(paths):
        name = image.rsplit("/", 1)[-1].lower()
        version = _numeric_version(tag)
        if not version:
            continue
        candidates = [name]
        if name in _DISTRO_ECOSYSTEMS:
            candidates.append(f"{_DISTRO_ECOSYSTEMS[name].lower()}:{name}")
        for candidate in candidates:
            for adv in db.match(candidate, version):
                key = (candidate, version, adv.cve)
                if key in seen:
                    continue
                seen.add(key)
                issues.append(DependencyIssue(
                    package=f"{image} (base image)",
                    version=tag,
                    cve=adv.cve,
                    severity=Severity(adv.severity),
                    title=adv.title or f"Known vulnerability in base image {image}",
                    description=adv.description,
                    fixed_in=adv.fixed_in,
                    cwe=adv.cwe,
                    references=adv.references,
                ))
    return issues


def ingest_sbom(root: str) -> list[tuple[str, str]]:
    """Read a CycloneDX or SPDX SBOM if the build produced one.

    An SBOM is how image contents become visible without a daemon or network,
    so it is used when present rather than attempting to unpack an image.
    """
    names = ("sbom.json", "bom.json", "cyclonedx.json", "sbom.spdx.json",
             "spdx.json")
    out: list[tuple[str, str]] = []
    seen: set = set()
    for name in names:
        path = os.path.join(root, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        # CycloneDX
        for comp in data.get("components", []) or []:
            pkg, version = comp.get("name"), comp.get("version")
            if pkg and version and (pkg, version) not in seen:
                seen.add((pkg, version))
                out.append((pkg, version))
        # SPDX
        for comp in data.get("packages", []) or []:
            pkg = comp.get("name")
            version = comp.get("versionInfo")
            if pkg and version and (pkg, version) not in seen:
                seen.add((pkg, version))
                out.append((pkg, version))
    return out


def _numeric_version(tag: str) -> str:
    m = re.match(r"v?(\d+(?:\.\d+)*)", tag or "")
    return m.group(1) if m else ""


def _redact(line: str) -> str:
    parts = line.split("=", 1)
    if len(parts) == 2 and parts[1].strip():
        return f"{parts[0]}= {'*' * min(len(parts[1].strip()), 12)} (redacted)"
    tokens = line.split()
    if len(tokens) >= 3:
        return " ".join(tokens[:2]) + " " + "*" * 12 + " (redacted)"
    return line


def _finding(rule: _Rule, path: str, line_no: int, code: str) -> Finding:
    loc = Location(file=path, line=line_no, column=1, end_line=line_no,
                   end_column=len(code) + 1, code=code)
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=Severity(rule.severity),
        cwe=rule.cwe,
        owasp=rule.owasp,
        category=rule.category,
        description=rule.description,
        remediation=rule.remediation,
        confidence=rule.confidence,
        framework="docker",
        language="container",
        location=loc,
        source=None,
        trace=[TaintStep(location=loc, description=rule.title, code=code)],
        tags=["container"],
    )
