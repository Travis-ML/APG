"""Behavioral profiler for observe mode.

Aggregates raw observation records into a structured per-agent profile
that the policy generator can consume. No model inference. Pure aggregation.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from apg.observe.collector import ObservationRecord


@dataclass
class AgentProfile:
    """Aggregated behavioral profile for a single agent."""

    agent_id: str
    total_calls: int = 0
    environments: set[str] = field(default_factory=set)

    # Counts per action type
    action_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Resource paths grouped by action type
    resource_paths: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    # Tool names grouped by action type
    tool_names: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    # Categories observed
    categories: set[str] = field(default_factory=set)

    # Risk level distribution
    risk_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Max risk level observed
    max_risk: str = "low"

    # Observation window
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "total_calls": self.total_calls,
            "environments": sorted(self.environments),
            "observation_window": {
                "first_seen": self.first_seen,
                "last_seen": self.last_seen,
            },
            "action_types": {
                action: {
                    "count": count,
                    "pct": round(count / self.total_calls * 100, 1) if self.total_calls else 0,
                }
                for action, count in sorted(self.action_counts.items())
            },
            "resource_paths": {
                action: sorted(paths) for action, paths in sorted(self.resource_paths.items())
            },
            "tool_names": {
                action: sorted(names) for action, names in sorted(self.tool_names.items())
            },
            "categories": sorted(self.categories),
            "risk_distribution": dict(self.risk_counts),
            "max_risk": self.max_risk,
        }


_RISK_ORDER = ["low", "medium", "high", "critical"]


class ProfileBuilder:
    """Builds an AgentProfile from a list of ObservationRecords."""

    def build(self, agent_id: str, records: list[ObservationRecord]) -> AgentProfile:
        """Aggregate observation records into a behavioral profile."""
        profile = AgentProfile(agent_id=agent_id)

        if not records:
            return profile

        profile.total_calls = len(records)
        profile.first_seen = records[0].timestamp
        profile.last_seen = records[-1].timestamp

        max_risk_idx = 0

        for record in records:
            profile.environments.add(record.environment)
            profile.action_counts[record.action_type] += 1
            profile.resource_paths[record.action_type].add(record.resource_path)
            profile.tool_names[record.action_type].add(record.tool_name)
            profile.categories.add(record.category)
            profile.risk_counts[record.risk_level] += 1

            risk_idx = _RISK_ORDER.index(record.risk_level) if record.risk_level in _RISK_ORDER else 1
            if risk_idx > max_risk_idx:
                max_risk_idx = risk_idx

        profile.max_risk = _RISK_ORDER[max_risk_idx]
        return profile
