"""Observation collector for observe mode.

Captures every tool call as a structured record, stored per-agent.
In delta mode, only captures calls that would have been denied by current policy.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from apg.models import NormalizedRequest, PolicyDecision, DecisionResult

logger = logging.getLogger(__name__)


class ObservationRecord:
    """Single observed tool call."""

    def __init__(
        self,
        timestamp: str,
        agent_id: str,
        tool_name: str,
        action_type: str,
        resource_path: str,
        risk_level: str,
        category: str,
        environment: str,
        session_id: str = "",
        arguments: dict[str, Any] | None = None,
        would_deny: bool = False,
    ):
        self.timestamp = timestamp
        self.agent_id = agent_id
        self.tool_name = tool_name
        self.action_type = action_type
        self.resource_path = resource_path
        self.risk_level = risk_level
        self.category = category
        self.environment = environment
        self.session_id = session_id
        self.arguments = arguments or {}
        self.would_deny = would_deny

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "tool_name": self.tool_name,
            "action_type": self.action_type,
            "resource_path": self.resource_path,
            "risk_level": self.risk_level,
            "category": self.category,
            "environment": self.environment,
            "session_id": self.session_id,
            "would_deny": self.would_deny,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ObservationRecord:
        return cls(**{k: v for k, v in data.items() if k in cls.__init__.__code__.co_varnames})


class ObservationCollector:
    """Collects and persists tool call observations per agent.

    Observations are stored as JSONL files in the data directory,
    one file per agent. The collector supports two modes:

    - full: capture every tool call regardless of policy result
    - delta: only capture calls that would have been denied
    """

    def __init__(self, data_dir: str | Path, mode: str = "full"):
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._mode = mode  # full | delta
        self._start_time = datetime.now(UTC).isoformat()
        self._counts: dict[str, int] = {}  # agent_id -> observation count

    @property
    def start_time(self) -> str:
        return self._start_time

    @property
    def mode(self) -> str:
        return self._mode

    def collect(
        self,
        request: NormalizedRequest,
        decision: PolicyDecision,
    ) -> bool:
        """Record an observation if it passes the mode filter.

        Returns True if the observation was recorded, False if filtered out.
        """
        would_deny = decision.result == DecisionResult.DENY

        # In delta mode, only record calls that would be denied
        if self._mode == "delta" and not would_deny:
            return False

        record = ObservationRecord(
            timestamp=datetime.now(UTC).isoformat(),
            agent_id=request.agent.agent_id,
            tool_name=request.tool_name,
            action_type=request.action_type.value,
            resource_path=request.resource_path,
            risk_level=request.risk_level.value,
            category=request.category,
            environment=request.environment,
            session_id=request.session_id,
            would_deny=would_deny,
        )

        self._write_record(record)
        self._counts[request.agent.agent_id] = self._counts.get(request.agent.agent_id, 0) + 1
        return True

    def get_observations(self, agent_id: str) -> list[ObservationRecord]:
        """Load all observations for a specific agent."""
        obs_file = self._agent_file(agent_id)
        if not obs_file.exists():
            return []

        records: list[ObservationRecord] = []
        for line in obs_file.read_text(encoding="utf-8").strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                records.append(ObservationRecord.from_dict(data))
            except (json.JSONDecodeError, TypeError):
                continue
        return records

    def get_all_agent_ids(self) -> list[str]:
        """Return agent IDs that have observations."""
        agent_ids: list[str] = []
        for f in self._data_dir.glob("*.jsonl"):
            agent_ids.append(f.stem)
        return sorted(agent_ids)

    def get_stats(self) -> dict[str, Any]:
        """Return summary statistics for the observation window."""
        return {
            "start_time": self._start_time,
            "mode": self._mode,
            "agents_observed": len(self._counts),
            "total_observations": sum(self._counts.values()),
            "per_agent": dict(self._counts),
        }

    def clear(self, agent_id: str | None = None) -> None:
        """Clear observations. If agent_id is given, clear only that agent."""
        if agent_id:
            f = self._agent_file(agent_id)
            if f.exists():
                f.unlink()
            self._counts.pop(agent_id, None)
        else:
            for f in self._data_dir.glob("*.jsonl"):
                f.unlink()
            self._counts.clear()

    def _write_record(self, record: ObservationRecord) -> None:
        obs_file = self._agent_file(record.agent_id)
        try:
            with open(obs_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record.to_dict(), default=str) + "\n")
        except OSError as exc:
            logger.error("Failed to write observation: %s", exc)

    def _agent_file(self, agent_id: str) -> Path:
        # Sanitize agent_id for use as filename
        safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in agent_id)
        return self._data_dir / f"{safe_id}.jsonl"
