"""Infrastructure-as-Code scanning.

Terraform/HCL, Kubernetes manifests, CloudFormation, Helm values and
docker-compose. These files decide whether a bucket is public, a database is
encrypted, or a container runs as root — exposures that no amount of
application taint analysis can find.

The scanners are deliberately textual: a full HCL/YAML parse buys little for
the kind of flat key/value assertions these rules make, and keeps the tool
dependency-free at runtime.
"""
from __future__ import annotations

import os
import re

from ..models import Finding, Location, Severity, TaintStep

A01 = "A01:2021 — Broken Access Control"
A02 = "A02:2021 — Cryptographic Failures"
A05 = "A05:2021 — Security Misconfiguration"
A09 = "A09:2021 — Security Logging and Monitoring Failures"


class _Rule:
    def __init__(self, rule_id, pattern, title, description, remediation,
                 severity="medium", cwe="CWE-16", owasp=A05,
                 category="iac-misconfiguration", confidence="high",
                 kinds=("terraform",), multiline=False):
        flags = re.IGNORECASE | re.MULTILINE | (re.DOTALL if multiline else 0)
        self.rule_id = rule_id
        self.regex = re.compile(pattern, flags)
        self.title = title
        self.description = description
        self.remediation = remediation
        self.severity = severity
        self.cwe = cwe
        self.owasp = owasp
        self.category = category
        self.confidence = confidence
        self.kinds = kinds


# --------------------------------------------------------------------------
# Terraform / HCL
# --------------------------------------------------------------------------
_TERRAFORM = [
    _Rule("iac-tf-sg-world-ingress",
          r"cidr_blocks\s*=\s*\[[^\]]*[\"']0\.0\.0\.0/0[\"']",
          "Security group open to the entire internet",
          "An ingress rule allows 0.0.0.0/0. Any service behind it is reachable "
          "from anywhere, which is how most exposed databases and admin panels "
          "are found.",
          "Restrict the CIDR to known ranges, or front the service with a load "
          "balancer or VPN.",
          severity="high", cwe="CWE-284", owasp=A01, category="network-exposure"),
    _Rule("iac-tf-sg-world-ipv6",
          r"ipv6_cidr_blocks\s*=\s*\[[^\]]*[\"']::/0[\"']",
          "Security group open to the entire IPv6 internet",
          "An ingress rule allows ::/0.",
          "Restrict the IPv6 CIDR to known ranges.",
          severity="high", cwe="CWE-284", owasp=A01, category="network-exposure"),
    _Rule("iac-tf-s3-public-acl",
          r"acl\s*=\s*[\"'](?:public-read|public-read-write)[\"']",
          "S3 bucket with a public ACL",
          "The bucket ACL grants read (or write) to everyone, exposing every "
          "object it holds.",
          "Use a private ACL and grant access through bucket policies or "
          "presigned URLs.",
          severity="critical", cwe="CWE-284", owasp=A01, category="public-exposure"),
    _Rule("iac-tf-s3-public-access-block-disabled",
          r"(?:block_public_acls|block_public_policy|ignore_public_acls|"
          r"restrict_public_buckets)\s*=\s*false",
          "S3 public access block disabled",
          "Disabling a public-access guard allows a later policy or ACL change "
          "to expose the bucket.",
          "Leave all four public access block settings enabled.",
          severity="high", cwe="CWE-284", owasp=A01, category="public-exposure"),
    _Rule("iac-tf-unencrypted-storage",
          r"(?:encrypted|storage_encrypted|encryption_enabled|"
          r"enable_encryption)\s*=\s*false",
          "Storage encryption disabled",
          "Data is stored unencrypted at rest, so anyone able to read the "
          "underlying volume or snapshot reads the data.",
          "Enable encryption at rest and supply a managed KMS key.",
          severity="high", cwe="CWE-311", owasp=A02, category="unencrypted-storage"),
    _Rule("iac-tf-iam-wildcard",
          r"[\"']Action[\"']\s*[:=]\s*\[?\s*[\"']\*[\"']",
          "IAM policy grants all actions",
          "A policy granting Action \"*\" permits every API call the principal "
          "could ever make, so any compromise becomes total.",
          "Grant only the specific actions required.",
          severity="high", cwe="CWE-732", owasp=A01, category="excessive-permissions"),
    _Rule("iac-tf-iam-wildcard-principal",
          r"[\"']Principal[\"']\s*[:=]\s*\{?\s*[\"']?(?:AWS[\"']?\s*[:=]\s*)?[\"']\*[\"']",
          "IAM policy grants access to any principal",
          "Principal \"*\" makes the resource accessible to every AWS account.",
          "Name the specific principals or accounts allowed.",
          severity="critical", cwe="CWE-732", owasp=A01, category="public-exposure"),
    _Rule("iac-tf-db-public",
          r"publicly_accessible\s*=\s*true",
          "Database instance is publicly accessible",
          "The database has a public endpoint, exposing it to internet-wide "
          "credential-stuffing and exploitation.",
          "Set publicly_accessible = false and reach it from inside the VPC.",
          severity="critical", cwe="CWE-284", owasp=A01, category="public-exposure"),
    _Rule("iac-tf-no-tls",
          r"(?:ssl|tls)_?(?:enabled|required|mode)\s*=\s*(?:false|[\"']none[\"']|[\"']disable[\"'])",
          "TLS disabled on a managed service",
          "Traffic to the service is unencrypted in transit.",
          "Require TLS and reject plaintext connections.",
          severity="high", cwe="CWE-319", owasp=A02, category="insecure-transport"),
    _Rule("iac-tf-logging-disabled",
          r"(?:logging|audit_logs?|cloudwatch_logs?|flow_logs?)_?(?:enabled)?\s*=\s*false",
          "Audit or access logging disabled",
          "Without logs there is no way to detect or investigate an incident on "
          "this resource.",
          "Enable access/audit logging and ship it off the host.",
          severity="low", cwe="CWE-778", owasp=A09, category="insufficient-logging"),
    _Rule("iac-tf-hardcoded-password",
          r"(?:password|secret|private_key|access_key)\s*=\s*[\"'][^\"'$\{][^\"']{6,}[\"']",
          "Credential hardcoded in Terraform",
          "A credential literal in Terraform ends up in version control and in "
          "the state file.",
          "Use a variable sourced from a secrets manager, and mark it sensitive.",
          severity="high", cwe="CWE-798", owasp=A05, category="hardcoded-secret",
          confidence="medium"),
    _Rule("iac-tf-imdsv1",
          r"http_tokens\s*=\s*[\"']optional[\"']",
          "EC2 instance metadata v1 allowed",
          "IMDSv1 is reachable through SSRF, which is the standard path from a "
          "web vulnerability to cloud credentials.",
          "Set http_tokens = \"required\" to enforce IMDSv2.",
          severity="high", cwe="CWE-918", owasp=A01, category="metadata-exposure"),
]

# --------------------------------------------------------------------------
# Kubernetes
# --------------------------------------------------------------------------
_KUBERNETES = [
    _Rule("iac-k8s-privileged",
          r"privileged\s*:\s*true",
          "Privileged container",
          "A privileged container has effectively unrestricted access to the "
          "host kernel; escaping to the node is trivial.",
          "Drop privileged and grant only the specific capabilities needed.",
          severity="critical", cwe="CWE-250", owasp=A01,
          category="excessive-permissions", kinds=("kubernetes",)),
    _Rule("iac-k8s-host-namespace",
          r"host(?:Network|PID|IPC)\s*:\s*true",
          "Container shares a host namespace",
          "Sharing the host network, PID or IPC namespace removes the isolation "
          "between the container and the node.",
          "Remove the hostNetwork/hostPID/hostIPC setting.",
          severity="high", cwe="CWE-653", owasp=A01,
          category="excessive-permissions", kinds=("kubernetes",)),
    _Rule("iac-k8s-run-as-root",
          r"runAsNonRoot\s*:\s*false|runAsUser\s*:\s*0\b",
          "Container runs as root",
          "A process running as uid 0 inside the container has far more to work "
          "with after a compromise.",
          "Set runAsNonRoot: true and a non-zero runAsUser.",
          severity="medium", cwe="CWE-250", owasp=A05,
          category="excessive-permissions", kinds=("kubernetes",)),
    _Rule("iac-k8s-privilege-escalation",
          r"allowPrivilegeEscalation\s*:\s*true",
          "Privilege escalation allowed",
          "The container may gain more privileges than its parent process.",
          "Set allowPrivilegeEscalation: false.",
          severity="medium", cwe="CWE-250", owasp=A05,
          category="excessive-permissions", kinds=("kubernetes",)),
    _Rule("iac-k8s-writable-root-fs",
          r"readOnlyRootFilesystem\s*:\s*false",
          "Writable container root filesystem",
          "A writable root filesystem lets an attacker drop tooling and persist "
          "inside the container.",
          "Set readOnlyRootFilesystem: true and mount writable volumes where needed.",
          severity="low", cwe="CWE-732", owasp=A05,
          category="security-misconfiguration", kinds=("kubernetes",)),
    _Rule("iac-k8s-capabilities-all",
          r"add\s*:\s*(?:\[[^\]]*[\"']?ALL[\"']?[^\]]*\]|\s*\n\s*-\s*[\"']?ALL)",
          "Container adds all Linux capabilities",
          "Granting ALL capabilities is close to running privileged.",
          "Drop ALL, then add back only what is required.",
          severity="high", cwe="CWE-250", owasp=A01,
          category="excessive-permissions", kinds=("kubernetes",)),
    _Rule("iac-k8s-secret-literal",
          r"(?:^|\n)\s*(?:password|token|apiKey|secretKey)\s*:\s*[\"']?[A-Za-z0-9+/=_\-]{8,}",
          "Credential literal in a Kubernetes manifest",
          "A credential written into a manifest is stored in the cluster and in "
          "version control in plaintext.",
          "Use a Secret sourced from an external secrets manager.",
          severity="high", cwe="CWE-798", owasp=A05, category="hardcoded-secret",
          confidence="medium", kinds=("kubernetes",)),
    _Rule("iac-k8s-service-account-automount",
          r"automountServiceAccountToken\s*:\s*true",
          "Service-account token automounted",
          "The pod receives a Kubernetes API token it probably does not need; "
          "any compromise then reaches the API server.",
          "Set automountServiceAccountToken: false unless the pod calls the API.",
          severity="low", cwe="CWE-732", owasp=A01,
          category="excessive-permissions", kinds=("kubernetes",)),
    _Rule("iac-k8s-no-resource-limits",
          r"resources\s*:\s*\{\s*\}",
          "Container has no resource limits",
          "Without limits a single workload can exhaust node CPU or memory, "
          "denying service to everything else on the node.",
          "Set CPU and memory requests and limits.",
          severity="low", cwe="CWE-770", owasp=A05,
          category="resource-exhaustion", kinds=("kubernetes",)),
]

# --------------------------------------------------------------------------
# CloudFormation / docker-compose / Helm
# --------------------------------------------------------------------------
_CLOUDFORMATION = [
    _Rule("iac-cfn-public-ingress",
          r"CidrIp\s*:\s*[\"']?0\.0\.0\.0/0",
          "Security group open to the entire internet",
          "An ingress rule allows 0.0.0.0/0.",
          "Restrict CidrIp to known ranges.",
          severity="high", cwe="CWE-284", owasp=A01, category="network-exposure",
          kinds=("cloudformation",)),
    _Rule("iac-cfn-public-bucket",
          r"AccessControl\s*:\s*[\"']?(?:PublicRead|PublicReadWrite)",
          "S3 bucket with a public ACL",
          "The bucket is readable (or writable) by anyone.",
          "Use Private and grant access explicitly.",
          severity="critical", cwe="CWE-284", owasp=A01, category="public-exposure",
          kinds=("cloudformation",)),
    _Rule("iac-cfn-wildcard-action",
          r"Action\s*:\s*[\"']?\*",
          "IAM policy grants all actions",
          "Action \"*\" permits every API call.",
          "Grant only the actions required.",
          severity="high", cwe="CWE-732", owasp=A01, category="excessive-permissions",
          kinds=("cloudformation",)),
]

_COMPOSE = [
    _Rule("iac-compose-privileged",
          r"privileged\s*:\s*true",
          "Privileged container in docker-compose",
          "A privileged container can escape to the host.",
          "Remove privileged: true.",
          severity="high", cwe="CWE-250", owasp=A01,
          category="excessive-permissions", kinds=("compose",)),
    _Rule("iac-compose-docker-socket",
          r"/var/run/docker\.sock",
          "Docker socket mounted into a container",
          "Access to the Docker socket is equivalent to root on the host.",
          "Remove the mount, or use a brokered API with restricted permissions.",
          severity="critical", cwe="CWE-250", owasp=A01,
          category="excessive-permissions", kinds=("compose",)),
    _Rule("iac-compose-host-network",
          r"network_mode\s*:\s*[\"']?host",
          "Container uses host networking",
          "Host networking removes network isolation between container and node.",
          "Use a bridge or user-defined network.",
          severity="medium", cwe="CWE-653", owasp=A05,
          category="security-misconfiguration", kinds=("compose",)),
]

_ALL_RULES = _TERRAFORM + _KUBERNETES + _CLOUDFORMATION + _COMPOSE

# --------------------------------------------------------------------------
_K8S_HINT = re.compile(r"^\s*(?:apiVersion|kind)\s*:", re.MULTILINE)
_K8S_KINDS = re.compile(
    r"^\s*kind\s*:\s*(?:Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|"
    r"ReplicaSet|Service|Ingress|Role|ClusterRole|RoleBinding|"
    r"ClusterRoleBinding|NetworkPolicy|Secret|ConfigMap|PodSecurityPolicy)\b",
    re.MULTILINE)
_CFN_HINT = re.compile(r"AWSTemplateFormatVersion|^\s*Resources\s*:\s*$", re.MULTILINE)


def classify(path: str, text: str) -> str:
    """Identify which IaC dialect a file is written in, or '' if none."""
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1].lower()

    if ext in (".tf", ".tfvars", ".hcl"):
        return "terraform"
    if name.startswith("docker-compose") or name.startswith("compose."):
        return "compose"
    if ext in (".yml", ".yaml", ".json"):
        if _CFN_HINT.search(text):
            return "cloudformation"
        if _K8S_KINDS.search(text) or (_K8S_HINT.search(text) and "spec:" in text):
            return "kubernetes"
        if name in ("values.yaml", "values.yml"):
            return "helm"
    return ""


def collect_iac_files(root: str) -> list[tuple[str, str]]:
    """Return [(path, kind)] for every IaC file under `root`."""
    from ..detection.language import IGNORED_DIRS

    out: list[tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames if d not in IGNORED_DIRS and not d.startswith(".")
        ]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in (".tf", ".tfvars", ".hcl", ".yml", ".yaml", ".json"):
                continue
            path = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(path) > 2 * 1024 * 1024:
                    continue
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            kind = classify(path, text)
            if kind:
                out.append((path, kind))
    out.sort()
    return out


def scan_iac(files: list[tuple[str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for path, kind in files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        lines = text.splitlines()
        # Helm values files are templated Kubernetes, so reuse those rules.
        effective = "kubernetes" if kind == "helm" else kind
        for rule in _ALL_RULES:
            if effective not in rule.kinds:
                continue
            seen_lines: set = set()
            for m in rule.regex.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                if line_no in seen_lines:
                    continue
                seen_lines.add(line_no)
                code = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
                if rule.category == "hardcoded-secret":
                    code = _redact(code)
                loc = Location(file=path, line=line_no, column=1, end_line=line_no,
                               end_column=len(code) + 1, code=code)
                findings.append(Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    severity=Severity(rule.severity),
                    cwe=rule.cwe,
                    owasp=rule.owasp,
                    category=rule.category,
                    description=rule.description,
                    remediation=rule.remediation,
                    confidence=rule.confidence,
                    framework=kind,
                    language="iac",
                    location=loc,
                    source=None,
                    trace=[TaintStep(location=loc, description=rule.title, code=code)],
                    tags=["iac", kind],
                ))
    return findings


def _redact(line: str) -> str:
    for sep in ("=", ":"):
        if sep in line:
            key, _, value = line.partition(sep)
            value = value.strip().strip("\"'")
            if not value:
                return line
            return f"{key}{sep} {'*' * min(len(value), 12)} (redacted)"
    return line
