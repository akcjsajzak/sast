"""A parsed source file, wrapping the raw bytes and tree-sitter tree."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tree_sitter import Node, Tree


@dataclass
class SourceFile:
    path: str
    content: bytes
    tree: Tree
    language: str

    @property
    def root(self) -> Node:
        return self.tree.root_node

    @property
    def has_error(self) -> bool:
        return self.root.has_error

    def node_text(self, node: Node) -> str:
        """Return the source text covered by a node, decoded."""
        return node.text.decode("utf-8", "replace")

    def line_text(self, row: int) -> str:
        """Return the full text of a 0-based source line."""
        lines = self.content.decode("utf-8", "replace").splitlines()
        if 0 <= row < len(lines):
            return lines[row]
        return ""

    def node_line(self, node: Node) -> str:
        return self.line_text(node.start_point.row)

    def source_between(self, node: Node) -> str:
        return self.content[node.start_byte:node.end_byte].decode("utf-8", "replace")

    def walk(self):
        """Depth-first traversal of all nodes."""
        stack = [self.root]
        while stack:
            node = stack.pop()
            yield node
            # reverse so traversal order matches document order
            for child in reversed(node.children):
                stack.append(child)

    def named_children(self, node: Node):
        return [c for c in node.children if c.is_named]
