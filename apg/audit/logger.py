"""Append-only JSONL audit logger with automatic secret redaction."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from apg.models import NormalizedRequest, PolicyDecision

logger = logging.getLogger(__name__)

REDACTION_PLACEHOLDER = "[REDACTED]"


class AuditLogger:
    """Writes structured audit events to a JSONL file.

    Every policy decision (allow or deny, enforce or observe) is recorded
    with full context for forensics and compliance. Sensitive argument
    values are redacted based on configurable key patterns.
    """

    def __init__(self, log_file: str | Path, redact_keys: list[str] | None = None):
        self._log_file = Path(log_file)
        self._log_file.parent.mkdir(parents=True, exist_ok=True)
        self._redact_keys = set(k.lower() for k in (redact_keys or []))

    def record(
        self,
        request: NormalizedRequest,
        decision: PolicyDecision,
        mode: str = "enforce",
    ) -> None:
        """Write a single audit event."""
        event: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "mode": mode,
            "agent_id": request.agent.agent_id,
            "owner": request.agent.owner,
            "team": request.agent.team,
            "session_id": request.session_id,
            "tool_name": request.tool_name,
            "action_type": request.action_type.value,
            "resource_path": request.resource_path,
            "risk_level": request.risk_level.value,
            "category": request.category,
            "environment": request.environment,
            "decision": decision.result.value,
            "reason": decision.reason,
            "arguments": self._redact(request.arguments),
        }

        try:
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, default=str) + "\n")
        except OSError as exc:
            logger.error("Failed to write audit event: %s", exc)

    def tail(self, n: int = 50) -> list[dict[str, Any]]:
        """Return the last N audit events."""
        if not self._log_file.exists():
            return []
        lines = self._log_file.read_text(encoding="utf-8").strip().split("\n")
        lines = [ln for ln in lines if ln.strip()]
        return [json.loads(ln) for ln in lines[-n:]]

    def _redact(self, data: dict[str, Any]) -> dict[str, Any]:
        """Recursively redact values whose keys match redact patterns."""
        if not self._redact_keys:
            return data
        return self._redact_recursive(data)

    def _redact_recursive(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            return {
                k: (REDACTION_PLACEHOLDER if k.lower() in self._redact_keys else self._redact_recursive(v))
                for k, v in obj.items()
            }
        if isinstance(obj, list):
            return [self._redact_recursive(item) for item in obj]
        return obj
