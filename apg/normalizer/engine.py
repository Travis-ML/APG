"""Semantic normalizer for MCP tool calls.

Takes a raw tool name and arguments, maps them to a canonical
(action_type, resource_path, risk_level) tuple using the YAML-driven
tool mappings. No NLP, no model inference. Pure lookup + regex.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from apg.models import (
    ActionType,
    AgentIdentity,
    CheckRequest,
    NormalizedRequest,
    RiskLevel,
)
from apg.normalizer.risk import RiskClassifier

logger = logging.getLogger(__name__)


class ToolMapping:
    """Single tool mapping loaded from config."""

    def __init__(self, raw: dict[str, Any]):
        self.action_type = ActionType(raw.get("action_type", "unknown"))
        self.resource_field: str | None = raw.get("resource_field")
        self.resource_prefix: str = raw.get("resource_prefix", "")
        self.category: str = raw.get("category", "unknown")
        self.risk_escalation: list[dict[str, str]] = raw.get("risk_escalation", [])


class SemanticNormalizer:
    """Maps MCP tool calls to normalized requests using YAML-configured mappings.

    The normalizer is the core of APG's intent classification. It sits between
    the raw ExtAuthz request and the Cedar evaluation engine, converting
    protocol-specific tool calls into a universal format that Cedar can reason about.
    """

    def __init__(self, mappings_file: str | Path | None = None):
        self._mappings: dict[str, ToolMapping] = {}
        self._default_mapping = ToolMapping({
            "action_type": "unknown",
            "resource_field": None,
            "resource_prefix": "unknown:",
            "category": "unknown",
        })
        if mappings_file:
            self.load_mappings(mappings_file)

    def load_mappings(self, path: str | Path) -> None:
        """Load tool mappings from a YAML file."""
        path = Path(path)
        if not path.exists():
            logger.warning("Tool mappings file not found: %s. Using defaults.", path)
            return

        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        mappings = raw.get("mappings", {})

        for tool_name, mapping_data in mappings.items():
            self._mappings[tool_name] = ToolMapping(mapping_data)

        default_raw = raw.get("default", {})
        if default_raw:
            self._default_mapping = ToolMapping(default_raw)

        logger.info("Loaded %d tool mappings from %s", len(self._mappings), path)

    def normalize(self, agent: AgentIdentity, request: CheckRequest) -> NormalizedRequest:
        """Normalize a raw check request into a canonical form.

        Steps:
        1. Look up tool mapping by name (exact match)
        2. Extract resource path from the appropriate argument field
        3. Classify risk using the risk classifier
        4. Return the fully normalized request
        """
        tool_name = request.tool_name
        mapping = self._mappings.get(tool_name, self._default_mapping)

        if mapping.action_type == ActionType.UNKNOWN and tool_name:
            logger.warning(
                "No mapping found for tool '%s'. Classified as unknown (risk: medium). "
                "Add this tool to tool_mappings.yaml to classify it properly.",
                tool_name,
            )

        # Extract resource path from the argument field specified in the mapping
        resource_path = self._extract_resource(mapping, request.tool_arguments)

        # Classify risk
        classifier = RiskClassifier(escalation_rules=mapping.risk_escalation)
        risk_level = classifier.classify(
            action_type=mapping.action_type,
            resource_path=resource_path,
            arguments=request.tool_arguments,
        )

        # Elevate risk in production
        if agent.environment == "prod" and risk_level == RiskLevel.LOW:
            risk_level = RiskLevel.MEDIUM

        return NormalizedRequest(
            agent=agent,
            tool_name=tool_name,
            action_type=mapping.action_type,
            resource_path=resource_path,
            risk_level=risk_level,
            category=mapping.category,
            arguments=request.tool_arguments,
            session_id=request.session_id,
            environment=agent.environment,
        )

    def _extract_resource(self, mapping: ToolMapping, arguments: dict[str, Any]) -> str:
        """Extract and prefix the resource path from tool arguments."""
        if not mapping.resource_field:
            return f"{mapping.resource_prefix}*"

        raw_value = arguments.get(mapping.resource_field, "*")
        if not isinstance(raw_value, str):
            raw_value = str(raw_value)

        # Apply prefix if the value doesn't already have it
        if mapping.resource_prefix and not raw_value.startswith(mapping.resource_prefix):
            return f"{mapping.resource_prefix}{raw_value}"
        return raw_value

    def has_mapping(self, tool_name: str) -> bool:
        """Check if a tool has an explicit mapping."""
        return tool_name in self._mappings

    @property
    def known_tools(self) -> list[str]:
        """Return list of tools with explicit mappings."""
        return list(self._mappings.keys())
