"""Trie-based generalization for observed resource paths and commands.

Collapses sets of observed paths into wildcard patterns suitable
for Cedar policy rules. No NLP, no model. Pure data structure operations.
"""

from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from apg.config import ObserveGeneralizationConfig


@dataclass
class TrieNode:
    """Node in a path trie. Tracks child segments and leaf file extensions."""

    children: dict[str, TrieNode] = field(default_factory=dict)
    leaf_count: int = 0
    leaf_extensions: set[str] = field(default_factory=set)
    leaf_files: set[str] = field(default_factory=set)  # actual filenames at this level


class PathGeneralizer:
    """Collapses observed file paths into wildcard patterns.

    Uses a trie to find common prefixes. When the number of distinct
    files in a directory exceeds the collapse threshold, the directory
    is wildcarded. Paths matching never_wildcard patterns are always
    listed individually.
    """

    def __init__(self, config: ObserveGeneralizationConfig):
        self._threshold = config.file_collapse_threshold
        self._max_depth = config.max_wildcard_depth
        self._extension_grouping = config.extension_grouping
        self._never_wildcard = config.never_wildcard

    def generalize(self, paths: list[str]) -> list[GeneralizedRule]:
        """Convert a list of observed paths into generalized patterns.

        Returns a list of GeneralizedRule objects, each containing the
        pattern string and metadata about what was collapsed.
        """
        if not paths:
            return []

        # Separate paths that must never be wildcarded
        protected: list[str] = []
        generalizable: list[str] = []

        for p in paths:
            clean = self._strip_prefix(p)
            if self._is_protected(clean):
                protected.append(clean)
            else:
                generalizable.append(clean)

        # Build trie from generalizable paths
        root = TrieNode()
        for p in generalizable:
            self._insert(root, p)

        # Walk trie and emit patterns
        rules = self._walk(root, [])

        # Add protected paths as individual rules
        for p in protected:
            rules.append(GeneralizedRule(
                pattern=p,
                source_count=1,
                source_files=[p],
                collapsed=False,
                flagged=True,
                flag_reason="matches never_wildcard pattern",
            ))

        return rules

    def _insert(self, root: TrieNode, path: str) -> None:
        """Insert a path into the trie."""
        parts = self._split_path(path)
        node = root
        for part in parts[:-1]:  # directory segments
            if part not in node.children:
                node.children[part] = TrieNode()
            node = node.children[part]

        # Last segment is the filename
        filename = parts[-1] if parts else path
        node.leaf_count += 1
        node.leaf_files.add(filename)

        _, ext = os.path.splitext(filename)
        if ext:
            node.leaf_extensions.add(ext)

    def _walk(self, node: TrieNode, prefix: list[str]) -> list[GeneralizedRule]:
        """Walk the trie and emit generalized patterns."""
        rules: list[GeneralizedRule] = []

        # If this node has leaves, decide whether to collapse
        if node.leaf_count > 0:
            dir_path = "/".join(prefix) if prefix else ""

            if node.leaf_count >= self._threshold:
                # Collapse to wildcard
                if self._extension_grouping and len(node.leaf_extensions) <= 3:
                    # Group by extension for tighter patterns
                    for ext in sorted(node.leaf_extensions):
                        pattern = f"{dir_path}/*{ext}" if dir_path else f"*{ext}"
                        matching = [f for f in node.leaf_files if f.endswith(ext)]
                        rules.append(GeneralizedRule(
                            pattern=pattern,
                            source_count=len(matching),
                            source_files=sorted(matching),
                            collapsed=True,
                        ))
                else:
                    pattern = f"{dir_path}/*" if dir_path else "*"
                    rules.append(GeneralizedRule(
                        pattern=pattern,
                        source_count=node.leaf_count,
                        source_files=sorted(node.leaf_files),
                        collapsed=True,
                    ))
            else:
                # List individually
                for filename in sorted(node.leaf_files):
                    full_path = f"{dir_path}/{filename}" if dir_path else filename
                    rules.append(GeneralizedRule(
                        pattern=full_path,
                        source_count=1,
                        source_files=[filename],
                        collapsed=False,
                    ))

        # Recurse into children
        for segment, child in sorted(node.children.items()):
            rules.extend(self._walk(child, prefix + [segment]))

        return rules

    def _split_path(self, path: str) -> list[str]:
        """Split a path into segments, handling both / and \\ separators."""
        path = path.replace("\\", "/")
        parts = [p for p in path.split("/") if p]
        return parts if parts else [path]

    def _strip_prefix(self, path: str) -> str:
        """Remove resource type prefix (file:, dir:, etc.)."""
        for prefix in ("file:", "dir:", "pattern:", "shell:", "url:", "unknown:"):
            if path.startswith(prefix):
                return path[len(prefix):]
        return path

    def _is_protected(self, path: str) -> bool:
        """Check if a path matches any never_wildcard pattern."""
        import fnmatch
        for pattern in self._never_wildcard:
            if fnmatch.fnmatch(path, pattern):
                return True
            # Also check the filename component alone
            basename = os.path.basename(path)
            if fnmatch.fnmatch(basename, pattern):
                return True
        return False


class CommandGeneralizer:
    """Collapses observed shell commands into prefix patterns.

    Uses token-based prefix matching. Known compound commands
    (like 'pip install') keep multiple tokens as the prefix.
    """

    def __init__(self, config: ObserveGeneralizationConfig):
        self._prefix_tokens = config.command_prefix_tokens
        self._compound_prefixes = config.compound_command_prefixes
        self._never_permit = config.never_permit_commands

    def generalize(self, commands: list[str]) -> list[GeneralizedRule]:
        """Convert observed commands into prefix-based patterns."""
        if not commands:
            return []

        # Separate dangerous commands
        safe: list[str] = []
        flagged: list[str] = []

        for cmd in commands:
            clean = self._strip_prefix(cmd)
            if self._is_dangerous(clean):
                flagged.append(clean)
            else:
                safe.append(clean)

        # Group safe commands by prefix
        prefix_groups: dict[str, list[str]] = defaultdict(list)
        for cmd in safe:
            prefix = self._extract_prefix(cmd)
            prefix_groups[prefix].append(cmd)

        rules: list[GeneralizedRule] = []
        for prefix, cmds in sorted(prefix_groups.items()):
            rules.append(GeneralizedRule(
                pattern=f"{prefix}*",
                source_count=len(cmds),
                source_files=sorted(set(cmds)),
                collapsed=len(cmds) > 1,
            ))

        # Add flagged commands
        for cmd in flagged:
            rules.append(GeneralizedRule(
                pattern=cmd,
                source_count=1,
                source_files=[cmd],
                collapsed=False,
                flagged=True,
                flag_reason="matches never_permit_commands pattern",
            ))

        return rules

    def _extract_prefix(self, command: str) -> str:
        """Extract the generalization prefix from a command string."""
        tokens = command.split()
        if not tokens:
            return command

        # Check compound prefixes first (longest match)
        for compound in sorted(self._compound_prefixes, key=len, reverse=True):
            if command.lower().startswith(compound.lower()):
                return compound + " "

        # Fall back to N-token prefix
        prefix_parts = tokens[:self._prefix_tokens]
        return " ".join(prefix_parts) + " "

    def _strip_prefix(self, cmd: str) -> str:
        if cmd.startswith("shell:"):
            return cmd[6:]
        return cmd

    def _is_dangerous(self, command: str) -> bool:
        """Check if a command matches any never_permit pattern."""
        cmd_lower = command.lower()
        for pattern in self._never_permit:
            if pattern.lower() in cmd_lower:
                return True
        return False


@dataclass
class GeneralizedRule:
    """A single generalized pattern with provenance metadata."""

    pattern: str
    source_count: int
    source_files: list[str]
    collapsed: bool = False
    flagged: bool = False
    flag_reason: str = ""
