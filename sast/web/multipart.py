"""Minimal multipart/form-data parser.

The standard library's `cgi.FieldStorage` was the obvious tool for this, but
`cgi` was removed in Python 3.13. Rather than take on a dependency — the whole
point of this tool is that it runs with nothing installed — this parses the
one shape the upload form produces.
"""
from __future__ import annotations

import re

_DISPOSITION_NAME = re.compile(rb'name="([^"]*)"')
_DISPOSITION_FILENAME = re.compile(rb'filename="([^"]*)"')


class Part:
    __slots__ = ("name", "filename", "data")

    def __init__(self, name: str, filename: str, data: bytes) -> None:
        self.name = name
        self.filename = filename
        self.data = data

    @property
    def text(self) -> str:
        return self.data.decode("utf-8", "replace")


def parse_boundary(content_type: str) -> bytes:
    """Extract the boundary token from a Content-Type header."""
    if not content_type:
        return b""
    for chunk in content_type.split(";"):
        chunk = chunk.strip()
        if chunk.lower().startswith("boundary="):
            value = chunk[len("boundary="):].strip()
            if value.startswith('"') and value.endswith('"') and len(value) > 1:
                value = value[1:-1]
            return value.encode("utf-8", "replace")
    return b""


def parse(body: bytes, content_type: str) -> dict:
    """Parse a multipart body into {field name: Part}."""
    boundary = parse_boundary(content_type)
    if not boundary:
        return {}

    delimiter = b"--" + boundary
    parts: dict = {}
    for raw in body.split(delimiter):
        if not raw or raw in (b"--", b"--\r\n", b"\r\n"):
            continue
        chunk = raw[2:] if raw.startswith(b"\r\n") else raw
        if chunk.startswith(b"--"):
            continue  # closing delimiter
        header_blob, sep, data = chunk.partition(b"\r\n\r\n")
        if not sep:
            continue
        if data.endswith(b"\r\n"):
            data = data[:-2]

        name = ""
        filename = ""
        for line in header_blob.split(b"\r\n"):
            if not line.lower().startswith(b"content-disposition:"):
                continue
            m = _DISPOSITION_NAME.search(line)
            if m:
                name = m.group(1).decode("utf-8", "replace")
            m = _DISPOSITION_FILENAME.search(line)
            if m:
                filename = m.group(1).decode("utf-8", "replace")
        if name:
            parts[name] = Part(name, filename, data)
    return parts
