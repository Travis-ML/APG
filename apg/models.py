"""Core data models for APG request/response pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ActionType(str, Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    LIST = "list"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GatewayMode(str, Enum):
    ENFORCE = "enforce"
    AUDIT = "audit"
    OBSERVE = "observe"


class DecisionResult(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class AgentIdentity:
    """Resolved identity of the calling agent."""

    agent_id: str
    owner: str = ""
    team: str = ""
    runtime: str = ""
    environment: str = "dev"
    raw_claims: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NormalizedRequest:
    """Output of the semantic normalizer. Protocol-agnostic representation of a tool call."""

    agent: AgentIdentity
    tool_name: str
    action_type: ActionType
    resource_path: str
    risk_level: RiskLevel
    category: str  # filesystem | shell | browser | api | data | unknown
    arguments: dict[str, Any] = field(default_factory=dict)
    session_id: str = ""
    environment: str = "dev"


@dataclass
class PolicyDecision:
    """Result of Cedar policy evaluation."""

    result: DecisionResult
    reason: str
    policies_evaluated: int = 0

    def is_allowed(self) -> bool:
        return self.result == DecisionResult.ALLOW


@dataclass(frozen=True)
class CheckRequest:
    """Inbound request from AgentGateway ExtAuthz.

    Carries the raw data extracted from the HTTP headers and body
    that AgentGateway forwards to the external authorization service.
    """

    # Identity (from JWT or headers)
    agent_id: str
    jwt_claims: dict[str, Any] = field(default_factory=dict)

    # MCP tool call (from request body / metadata)
    tool_name: str = ""
    tool_arguments: dict[str, Any] = field(default_factory=dict)

    # Context
    environment: str = "dev"
    session_id: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class CheckResponse:
    """Response sent back to AgentGateway."""

    allowed: bool
    status_code: int = 200
    denied_reason: str = ""
    headers_to_add: dict[str, str] = field(default_factory=dict)
