"""Deterministic risk classification based on tool arguments.

No NLP or model inference. Pure regex/glob matching against known dangerous patterns.
"""

from __future__ import annotations

import re
from typing import Any

from apg.models import ActionType, RiskLevel


# Sensitive file patterns that elevate risk regardless of action type
_SENSITIVE_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\.env$", re.IGNORECASE),
    re.compile(r"\.pem$", re.IGNORECASE),
    re.compile(r"\.key$", re.IGNORECASE),
    re.compile(r"\.secret$", re.IGNORECASE),
    re.compile(r"(^|/)\.ssh/", re.IGNORECASE),
    re.compile(r"(^|/)\.aws/", re.IGNORECASE),
    re.compile(r"(^|/)\.kube/", re.IGNORECASE),
    re.compile(r"/etc/shadow$"),
    re.compile(r"/etc/passwd$"),
    re.compile(r"id_rsa", re.IGNORECASE),
]

# Base risk for each action type before argument inspection
_BASE_RISK: dict[ActionType, RiskLevel] = {
    ActionType.READ: RiskLevel.LOW,
    ActionType.LIST: RiskLevel.LOW,
    ActionType.WRITE: RiskLevel.MEDIUM,
    ActionType.EXECUTE: RiskLevel.MEDIUM,
    ActionType.DELETE: RiskLevel.HIGH,
    ActionType.UNKNOWN: RiskLevel.MEDIUM,
}


class RiskClassifier:
    """Classifies risk level for a normalized tool call.

    Risk is computed from three sources, taking the highest:
    1. Base risk from the action type
    2. Escalation rules from the tool mapping config
    3. Sensitive path pattern matching
    """

    def __init__(self, escalation_rules: list[dict[str, str]] | None = None):
        self._escalation_rules: list[tuple[re.Pattern[str], RiskLevel]] = []
        for rule in escalation_rules or []:
            try:
                pattern = re.compile(rule["pattern"], re.IGNORECASE)
                level = RiskLevel(rule["risk"])
                self._escalation_rules.append((pattern, level))
            except (re.error, ValueError, KeyError):
                continue  # skip malformed rules

    def classify(
        self,
        action_type: ActionType,
        resource_path: str,
        arguments: dict[str, Any] | None = None,
    ) -> RiskLevel:
        """Determine risk level. Returns the highest applicable level."""
        risk = _BASE_RISK.get(action_type, RiskLevel.MEDIUM)

        # Check escalation rules against the resource path
        for pattern, level in self._escalation_rules:
            if pattern.search(resource_path):
                risk = _max_risk(risk, level)

        # Check sensitive path patterns
        if _matches_sensitive_path(resource_path):
            risk = _max_risk(risk, RiskLevel.HIGH)

        # Environment-based escalation is handled at the normalizer level,
        # not here. This keeps the risk classifier purely about the action
        # and its arguments.

        return risk


def _matches_sensitive_path(path: str) -> bool:
    """Check if a resource path matches any known sensitive pattern."""
    for pattern in _SENSITIVE_PATH_PATTERNS:
        if pattern.search(path):
            return True
    return False


def _max_risk(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    """Return the higher of two risk levels."""
    order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    return order[max(order.index(a), order.index(b))]
