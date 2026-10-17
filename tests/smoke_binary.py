#!/usr/bin/env python3
"""Smoke-test the frozen executable.

The unit suite imports the Python package, so nothing it does says whether the
*binary* works. A grammar missing from the PyInstaller bundle, a data file not
bundled, or an advisory database that failed to embed would all pass every
test and still fail for anyone running the executable.

This runs the built binary against a fixture holding one deliberately
vulnerable file per supported language, plus IaC, a Dockerfile and a secret,
and fails if any engine reports nothing.

Usage:  python tests/smoke_binary.py dist/sast
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

# One file per engine, each containing a finding that engine must report.
FIXTURES = {
    "legacy/index.php": '<?php system($_GET["c"]);',
    "api/src/main/java/A.java": (
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController public class A {\n"
        "  @GetMapping(\"/r\") public void r(@RequestParam String q) throws Exception {\n"
        "    Runtime.getRuntime().exec(q);\n  }\n}\n"
    ),
    "web/app.js": "el.innerHTML = location.hash;\n",
    "web/component.tsx": (
        "export function C(){ const u: string = location.hash;\n"
        "  return <div dangerouslySetInnerHTML={{__html: u}} />; }\n"
    ),
    "svc/app.py": (
        "import os\nfrom flask import request\n"
        "def handler():\n    os.system('ls ' + request.args['d'])\n"
    ),
    "api-go/main.go": (
        'package main\n\nimport (\n\t"net/http"\n\t"os/exec"\n)\n\n'
        'func h(w http.ResponseWriter, r *http.Request) {\n'
        '\texec.Command("sh", "-c", r.FormValue("c"))\n}\n'
    ),
    "dotnet/App.cs": (
        'class C { void M() { var f = Request.Query["f"]; File.ReadAllText(f); } }\n'
    ),
    "native/main.c": (
        "#include <stdio.h>\nint main(void){ char b[64]; gets(b); return 0; }\n"
    ),
    "native/util.cpp": (
        "#include <cstring>\nvoid f(const char* s){ char d[8]; strcpy(d, s); }\n"
    ),
    "infra/main.tf": 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n',
    "infra/pod.yaml": (
        "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: x\n"
        "    securityContext:\n      privileged: true\n"
    ),
    "Dockerfile": "FROM alpine:3.14\nRUN curl -sL https://x.sh | sh\n",
    # Assembled so the repository holds no credential-shaped literal.
    "notes.md": "aws_key = " + "AKIA" + "IOSFODNN7" + "EXAMPLE\n",
    # Manifests, so each language is detected and its framework resolved.
    "legacy/composer.json": '{"require": {"php": "^8.0"}}',
    "api/pom.xml": (
        "<project><dependencies><dependency>"
        "<groupId>org.springframework.boot</groupId>"
        "<artifactId>spring-boot-starter-web</artifactId>"
        "<version>2.7.0</version></dependency></dependencies></project>"
    ),
    "web/package.json": '{"dependencies": {"react": "18.2.0", "lodash": "4.17.11"}}',
    "svc/requirements.txt": "flask==0.12.2\n",
    "api-go/go.mod": "module api\n",
}

# Each engine must produce at least one finding. These are the `language`
# values the report uses.
REQUIRED_ENGINES = [
    "php", "java", "javascript", "python", "go", "csharp", "c",
    "iac", "container", "secrets",
]


def build_fixture(root: str) -> None:
    for rel, content in FIXTURES.items():
        path = os.path.join(root, rel)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)


def main(argv: list) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    binary = argv[1]
    if not os.path.isfile(binary):
        print(f"smoke: executable not found: {binary}", file=sys.stderr)
        return 2

    root = tempfile.mkdtemp(prefix="sast-smoke-")
    build_fixture(root)

    proc = subprocess.run(
        [binary, "scan", root, "--format", "json"],
        capture_output=True, text=True, timeout=600,
    )
    # --fail-on is not set, so a non-zero status is a real failure.
    if proc.returncode != 0:
        print(f"smoke: scan exited {proc.returncode}", file=sys.stderr)
        print(proc.stderr[-4000:], file=sys.stderr)
        return 1

    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        print(f"smoke: report is not valid JSON: {exc}", file=sys.stderr)
        print(proc.stdout[:2000], file=sys.stderr)
        return 1

    found = {f["language"] for f in report.get("findings", [])}
    missing = [engine for engine in REQUIRED_ENGINES if engine not in found]

    print(f"smoke: languages detected  : {', '.join(report.get('languages', []))}")
    print(f"smoke: engines reporting   : {', '.join(sorted(found))}")
    print(f"smoke: findings            : {len(report.get('findings', []))}")
    print(f"smoke: dependency issues   : {len(report.get('dependency_issues', []))}")
    print(f"smoke: advisory DB         : {report.get('advisory_db', {})}")

    if missing:
        print(f"\nsmoke: FAIL — no findings from: {', '.join(missing)}",
              file=sys.stderr)
        print("A missing language usually means its tree-sitter grammar was "
              "not bundled (see --collect-all in the Makefile).", file=sys.stderr)
        return 1

    print("\nsmoke: PASS — every engine reported through the frozen binary")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
