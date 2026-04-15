"""ExtAuthz HTTP service for AgentGateway integration.

AgentGateway forwards requests to this service for authorization decisions.
The service runs the full APG pipeline: identity resolution, semantic
normalization, Cedar evaluation, audit logging, and optional observation.

HTTP ExtAuthz protocol:
- AgentGateway sends the original request headers (and optionally body/metadata)
- 200 response = allow
- 403 response = deny
- Response headers can be forwarded back to the upstream

AgentGateway config to point at this service:
    extAuthz:
      host: localhost:9001
      protocol:
        http:
          requestTimeout: "5s"
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Request, Response

from apg.audit.logger import AuditLogger
from apg.config import APGConfig
from apg.identity.resolver import IdentityResolutionError, IdentityResolver
from apg.models import (
    CheckRequest,
    DecisionResult,
    GatewayMode,
    NormalizedRequest,
    PolicyDecision,
)
from apg.normalizer.engine import SemanticNormalizer
from apg.observe.collector import ObservationCollector
from apg.policy.engine import CedarEngine

logger = logging.getLogger(__name__)

router = APIRouter()


class AuthzService:
    """Core authorization service implementing the APG pipeline.

    Pipeline stages:
    1. Parse inbound request (headers, body, JWT metadata)
    2. Resolve agent identity
    3. Normalize tool call to canonical action/resource/risk
    4. Evaluate Cedar policies
    5. Log decision to audit trail
    6. Optionally collect observation (observe mode)
    7. Return allow/deny to AgentGateway
    """

    def __init__(
        self,
        config: APGConfig,
        identity_resolver: IdentityResolver,
        normalizer: SemanticNormalizer,
        cedar_engine: CedarEngine,
        audit_logger: AuditLogger,
        observer: ObservationCollector | None = None,
    ):
        self._config = config
        self._identity = identity_resolver
        self._normalizer = normalizer
        self._cedar = cedar_engine
        self._audit = audit_logger
        self._observer = observer

    def check(self, check_request: CheckRequest) -> tuple[PolicyDecision, NormalizedRequest]:
        """Run the full authorization pipeline.

        Returns (decision, normalized_request) for the caller to format
        the HTTP response appropriately.
        """
        # Stage 1: Resolve identity
        try:
            agent = self._identity.resolve(check_request)
        except IdentityResolutionError as exc:
            logger.warning("Identity resolution failed: %s", exc)
            # Fail closed on identity errors
            dummy = self._normalizer.normalize(
                agent=self._identity._resolve_passthrough(check_request),
                request=check_request,
            )
            decision = PolicyDecision(
                result=DecisionResult.DENY,
                reason=f"identity:resolution-failed ({exc})",
            )
            self._audit.record(dummy, decision, mode=self._config.mode.value)
            return decision, dummy

        # Stage 2: Normalize
        normalized = self._normalizer.normalize(agent, check_request)

        # Stage 3: Evaluate Cedar
        decision = self._cedar.evaluate(normalized)

        # Stage 4: Mode-specific behavior
        mode = self._config.mode

        if mode == GatewayMode.OBSERVE:
            # Observe: collect the observation, always allow
            if self._observer:
                self._observer.collect(normalized, decision)
            # Override to allow (observe never blocks)
            effective_decision = PolicyDecision(
                result=DecisionResult.ALLOW,
                reason=f"observe:passthrough (would_{decision.result.value})",
            )
            self._audit.record(normalized, effective_decision, mode="observe")
            return effective_decision, normalized

        if mode == GatewayMode.AUDIT:
            # Audit: log the real decision but always allow
            self._audit.record(normalized, decision, mode="audit")
            effective_decision = PolicyDecision(
                result=DecisionResult.ALLOW,
                reason=f"audit:passthrough (would_{decision.result.value})",
            )
            return effective_decision, normalized

        # Enforce: the decision stands
        self._audit.record(normalized, decision, mode="enforce")
        return decision, normalized


# Module-level service instance, set during app startup
_service: AuthzService | None = None


def set_service(service: AuthzService) -> None:
    global _service
    _service = service


def get_service() -> AuthzService:
    if _service is None:
        raise RuntimeError("AuthzService not initialized. Call set_service() during app startup.")
    return _service


@router.post("/check")
async def check_authorization(request: Request) -> Response:
    """ExtAuthz HTTP check endpoint.

    AgentGateway sends the request context here. APG evaluates it
    and returns 200 (allow) or 403 (deny).

    The request body should contain:
    {
        "agent_id": "...",
        "jwt_claims": {...},
        "tool_name": "read_file",
        "tool_arguments": {"path": "src/main.py"},
        "environment": "dev",
        "session_id": "..."
    }

    AgentGateway can also forward this context via headers and metadata
    using CEL expressions in the extAuthz config.
    """
    service = get_service()

    # Parse request body
    try:
        body = await request.json()
    except Exception:
        body = {}

    # Build CheckRequest from body and headers
    headers = dict(request.headers)

    check_req = CheckRequest(
        agent_id=body.get("agent_id", headers.get("x-agent-id", "")),
        jwt_claims=body.get("jwt_claims", {}),
        tool_name=body.get("tool_name", headers.get("x-mcp-tool-name", "")),
        tool_arguments=body.get("tool_arguments", {}),
        environment=body.get("environment", headers.get("x-environment", "dev")),
        session_id=body.get("session_id", headers.get("x-session-id", "")),
        request_headers=headers,
    )

    decision, normalized = service.check(check_req)

    # Build response headers for AgentGateway to forward
    response_headers = {
        "x-apg-decision": decision.result.value,
        "x-apg-reason": decision.reason,
        "x-apg-action-type": normalized.action_type.value,
        "x-apg-risk-level": normalized.risk_level.value,
    }

    if decision.is_allowed():
        return Response(
            status_code=200,
            content=json.dumps({"allowed": True, "reason": decision.reason}),
            media_type="application/json",
            headers=response_headers,
        )
    else:
        return Response(
            status_code=403,
            content=json.dumps({
                "allowed": False,
                "reason": decision.reason,
                "agent_id": normalized.agent.agent_id,
                "action_type": normalized.action_type.value,
                "resource_path": normalized.resource_path,
            }),
            media_type="application/json",
            headers=response_headers,
        )


@router.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "service": "apg"}
