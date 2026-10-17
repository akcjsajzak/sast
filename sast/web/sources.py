"""Resolve a scan request into a directory on disk.

Three input kinds, each with its own abuse potential. A scanner that shipped
zip-slip or argument injection would be an embarrassing thing to find in a
security tool, so the hardening here is deliberate rather than incidental:

* **ZIP upload** — archive entries are attacker-chosen paths. Absolute paths,
  `..` traversal, symlinks and device files are refused, and the extracted
  total is capped so a zip bomb cannot fill the disk.
* **Git URL** — `git clone` is reached through an argument list, never a
  shell. The scheme is allow-listed, which blocks `ext::<command>` (direct
  command execution) and `file://`; a URL that begins with `-` is refused so
  it cannot be read as an option such as `--upload-pack=`.
* **Local path** — the operator's own filesystem, which is the point of the
  feature, but the path is resolved and reported so what was scanned is never
  ambiguous.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile

# Caps for an uploaded archive.
MAX_ZIP_BYTES = 256 * 1024 * 1024        # compressed upload
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024  # 1 GiB expanded
MAX_ZIP_ENTRIES = 50_000

GIT_TIMEOUT_SECONDS = 300

# Transports that are safe to hand to `git clone`. Notably absent: `ext::`,
# which runs an arbitrary command, and `file://`, which would let a browser
# request read the server's filesystem.
_ALLOWED_GIT_SCHEMES = ("https://", "http://", "ssh://", "git://")
# scp-style shorthand, e.g. git@github.com:owner/repo.git
_SCP_LIKE_RE = re.compile(r"^[A-Za-z0-9_.\-]+@[A-Za-z0-9_.\-]+:[A-Za-z0-9_./\-~]+$")


class SourceError(Exception):
    """A scan request that cannot be satisfied, with a message for the user."""


# ---------------------------------------------------------------------------
# Local path
# ---------------------------------------------------------------------------
def resolve_local_path(raw: str) -> tuple:
    """Return (directory, label, cleanup) for a local path request."""
    if not raw or not raw.strip():
        raise SourceError("No path given.")
    path = os.path.abspath(os.path.expanduser(raw.strip()))
    if not os.path.exists(path):
        raise SourceError(f"Path does not exist: {path}")
    if not os.path.isdir(path):
        raise SourceError(f"Not a directory: {path}")
    if not os.access(path, os.R_OK):
        raise SourceError(f"Path is not readable: {path}")
    return path, path, None


# ---------------------------------------------------------------------------
# ZIP upload
# ---------------------------------------------------------------------------
def _is_unsafe_member(name: str) -> str:
    """Return a reason the archive entry is unsafe, or '' if it is fine."""
    if not name or name in (".", ".."):
        return "empty entry name"
    normalised = name.replace("\\", "/")
    if normalised.startswith("/"):
        return "absolute path"
    if re.match(r"^[A-Za-z]:", normalised):
        return "drive-letter path"
    parts = normalised.split("/")
    if ".." in parts:
        return "parent-directory traversal"
    return ""


def extract_zip(data: bytes, label: str = "upload.zip") -> tuple:
    """Extract an uploaded archive into a fresh directory.

    Returns (directory, label, cleanup).
    """
    if not data:
        raise SourceError("The uploaded file is empty.")
    if len(data) > MAX_ZIP_BYTES:
        raise SourceError(
            f"Archive is larger than the {MAX_ZIP_BYTES // (1024 * 1024)} MB limit.")

    workdir = tempfile.mkdtemp(prefix="sast-zip-")
    target = os.path.join(workdir, "src")
    os.makedirs(target, exist_ok=True)

    def cleanup():
        shutil.rmtree(workdir, ignore_errors=True)

    archive_path = os.path.join(workdir, "upload.zip")
    try:
        with open(archive_path, "wb") as fh:
            fh.write(data)
        with zipfile.ZipFile(archive_path) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                raise SourceError(
                    f"Archive holds more than {MAX_ZIP_ENTRIES} entries.")

            total = 0
            for info in infos:
                reason = _is_unsafe_member(info.filename)
                if reason:
                    raise SourceError(
                        f"Refusing to extract '{info.filename}': {reason}.")
                mode = info.external_attr >> 16
                # Only inspect the type when the archive actually recorded
                # one. Plenty of writers — Python's own writestr among them —
                # store permission bits alone, and treating those as "not a
                # regular file" would reject ordinary archives.
                if mode & 0o170000:
                    if stat.S_ISLNK(mode):
                        # A symlink in an archive can redirect a later write
                        # anywhere on the filesystem.
                        raise SourceError(
                            f"Refusing to extract symlink '{info.filename}'.")
                    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                        raise SourceError(
                            f"Refusing to extract special file '{info.filename}'.")
                total += info.file_size
                if total > MAX_EXTRACTED_BYTES:
                    raise SourceError(
                        "Archive expands beyond the "
                        f"{MAX_EXTRACTED_BYTES // (1024 * 1024)} MB limit.")

            real_target = os.path.realpath(target)
            for info in infos:
                destination = os.path.realpath(
                    os.path.join(target, info.filename))
                # Belt and braces: even after the checks above, confirm the
                # resolved destination stays inside the extraction directory.
                if not (destination == real_target
                        or destination.startswith(real_target + os.sep)):
                    raise SourceError(
                        f"Refusing to extract '{info.filename}' outside the "
                        "extraction directory.")
                zf.extract(info, target)
    except zipfile.BadZipFile:
        cleanup()
        raise SourceError("That file is not a valid ZIP archive.")
    except SourceError:
        cleanup()
        raise
    except Exception as exc:  # noqa: BLE001 — surface a clean message
        cleanup()
        raise SourceError(f"Could not read the archive: {exc}")
    finally:
        try:
            os.remove(archive_path)
        except OSError:
            pass

    # A GitHub-style archive wraps everything in one directory; scan that
    # rather than the wrapper so paths in the report are meaningful.
    entries = [e for e in os.listdir(target) if not e.startswith(".")]
    scan_root = target
    if len(entries) == 1:
        only = os.path.join(target, entries[0])
        if os.path.isdir(only):
            scan_root = only

    return scan_root, label, cleanup


# ---------------------------------------------------------------------------
# Git clone
# ---------------------------------------------------------------------------
def validate_git_url(raw: str) -> str:
    """Return a git URL that is safe to pass to `git clone`, or raise."""
    if not raw or not raw.strip():
        raise SourceError("No repository URL given.")
    url = raw.strip()

    if any(ch in url for ch in "\n\r\x00"):
        raise SourceError("Repository URL contains control characters.")
    if url.startswith("-"):
        # Otherwise `git clone --upload-pack=...` would be read as an option.
        raise SourceError("Repository URL may not begin with '-'.")

    lowered = url.lower()
    if lowered.startswith("ext::"):
        raise SourceError(
            "The ext:: transport executes arbitrary commands and is refused.")
    if lowered.startswith("file://") or url.startswith("/"):
        raise SourceError(
            "Local-filesystem URLs are refused here; use the Local path option.")

    if lowered.startswith(_ALLOWED_GIT_SCHEMES):
        return url
    if _SCP_LIKE_RE.match(url):
        return url
    raise SourceError(
        "Unsupported repository URL. Use https://, ssh://, git://, or "
        "git@host:owner/repo.git.")


def clone_repository(raw_url: str, branch: str = "") -> tuple:
    """Shallow-clone a repository into a temporary directory.

    Returns (directory, label, cleanup).
    """
    url = validate_git_url(raw_url)
    workdir = tempfile.mkdtemp(prefix="sast-git-")
    target = os.path.join(workdir, "repo")

    def cleanup():
        shutil.rmtree(workdir, ignore_errors=True)

    if shutil.which("git") is None:
        cleanup()
        raise SourceError("git is not installed on this machine.")

    # An argument list, so nothing in the URL can reach a shell. `--` ends
    # option parsing as a second line of defence behind the leading-dash check.
    command = ["git", "clone", "--depth", "1", "--single-branch",
               "--no-tags", "--quiet"]
    if branch and branch.strip():
        safe_branch = branch.strip()
        if safe_branch.startswith("-") or any(c in safe_branch for c in "\n\r\x00 "):
            cleanup()
            raise SourceError("Invalid branch name.")
        command += ["--branch", safe_branch]
    command += ["--", url, target]

    env = dict(os.environ)
    # Never block on a credential or host-key prompt: the server has no
    # terminal, so a prompt would hang the scan until the timeout.
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = ""
    env.setdefault("GIT_SSH_COMMAND", "ssh -oBatchMode=yes")

    try:
        proc = subprocess.run(command, capture_output=True, text=True,
                              timeout=GIT_TIMEOUT_SECONDS, env=env, check=False)
    except subprocess.TimeoutExpired:
        cleanup()
        raise SourceError(
            f"Clone timed out after {GIT_TIMEOUT_SECONDS}s.")
    except OSError as exc:
        cleanup()
        raise SourceError(f"Could not run git: {exc}")

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        message = detail[-1] if detail else f"git exited {proc.returncode}"
        cleanup()
        raise SourceError(f"Clone failed: {message}")

    # The checkout's own .git is of no interest to a scan and is large.
    shutil.rmtree(os.path.join(target, ".git"), ignore_errors=True)
    return target, url, cleanup


# ---------------------------------------------------------------------------
def resolve(source_type: str, value: str, upload: bytes = b"",
            filename: str = "", branch: str = "") -> tuple:
    """Dispatch to the right resolver. Returns (directory, label, cleanup)."""
    if source_type == "path":
        return resolve_local_path(value)
    if source_type == "zip":
        return extract_zip(upload, filename or "upload.zip")
    if source_type == "git":
        return clone_repository(value, branch)
    raise SourceError(f"Unknown source type: {source_type}")
