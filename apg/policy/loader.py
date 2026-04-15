"""Cedar policy file loader with optional hot-reload."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class PolicyLoadError(Exception):
    """Raised when policies cannot be loaded."""


class PolicyLoader:
    """Loads and concatenates all .cedar files from the policy directory."""

    def __init__(self, policy_dir: str | Path):
        self._policy_dir = Path(policy_dir)
        self._cached_policies: str = ""
        self._last_hash: int = 0

    def load(self) -> str:
        """Load all .cedar files and return concatenated policy text.

        Raises PolicyLoadError if the directory doesn't exist.
        Returns empty string if directory exists but contains no .cedar files.
        """
        if not self._policy_dir.exists():
            raise PolicyLoadError(f"Policy directory not found: {self._policy_dir}")

        if not self._policy_dir.is_dir():
            raise PolicyLoadError(f"Policy path is not a directory: {self._policy_dir}")

        parts: list[str] = []
        for cedar_file in sorted(self._policy_dir.glob("*.cedar")):
            try:
                content = cedar_file.read_text(encoding="utf-8")
                parts.append(f"// --- {cedar_file.name} ---\n{content}")
            except OSError as exc:
                logger.error("Failed to read policy file %s: %s", cedar_file, exc)

        combined = "\n\n".join(parts)
        content_hash = hash(combined)

        if content_hash != self._last_hash:
            self._cached_policies = combined
            self._last_hash = content_hash
            file_count = len(parts)
            if file_count > 0:
                logger.info("Loaded %d policy file(s) from %s", file_count, self._policy_dir)
            else:
                logger.warning("No .cedar files found in %s", self._policy_dir)

        return self._cached_policies

    def reload_if_changed(self) -> tuple[bool, str]:
        """Reload policies if files have changed.

        Returns (changed: bool, policies: str).
        """
        old_hash = self._last_hash
        policies = self.load()
        return (self._last_hash != old_hash, policies)

    def has_policies(self) -> bool:
        """Check if any .cedar files exist in the policy directory."""
        if not self._policy_dir.exists():
            return False
        return any(self._policy_dir.glob("*.cedar"))
