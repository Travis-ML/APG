"""Cedar policy evaluation engine.

Wraps cedarpy to evaluate NormalizedRequests against loaded policies.
Fail-closed: any evaluation error results in DENY.
"""

from __future__ import annotations

import logging
import sys

import cedarpy

from apg.models import DecisionResult, NormalizedRequest, PolicyDecision

logger = logging.getLogger(__name__)


class CedarEngine:
    """Evaluates normalized requests against Cedar policies.

    The engine builds a Cedar authorization request from the NormalizedRequest,
    mapping the APG data model to Cedar's principal/action/resource/context model:

    - principal: Agent::"<agent_id>"
    - action:    Action::"toolCall"
    - resource:  Tool::"<category>"   (filesystem, shell, browser, etc.)
    - context:   flattened dict with action_type, resource_path, risk_level, etc.
    """

    def __init__(self, policies: str):
        self._policies = policies

    def update_policies(self, policies: str) -> None:
        """Hot-swap policies without restart."""
        self._policies = policies
        logger.info("Cedar policies updated (%d chars)", len(policies))

    def evaluate(self, request: NormalizedRequest) -> PolicyDecision:
        """Evaluate a normalized request against Cedar policies.

        Returns ALLOW only if Cedar returns an explicit permit.
        Returns DENY for: explicit forbid, no matching permit, or evaluation error.
        """
        principal = f'Agent::"{request.agent.agent_id}"'
        action = 'Action::"toolCall"'
        resource = f'Tool::"{request.category}"'

        context = {
            "action_type": request.action_type.value,
            "resource_path": request.resource_path,
            "risk_level": request.risk_level.value,
            "environment": request.environment,
            "tool_name": request.tool_name,
            "category": request.category,
            "session_id": request.session_id,
            "agent_id": request.agent.agent_id,
            "owner": request.agent.owner,
            "team": request.agent.team,
            "runtime": request.agent.runtime,
        }

        try:
            result = cedarpy.is_authorized(
                request={
                    "principal": principal,
                    "action": action,
                    "resource": resource,
                    "context": context,
                },
                policies=self._policies,
                entities=[],
            )
            allowed = result.decision == cedarpy.Decision.Allow
        except Exception as exc:
            # Fail closed. Log the error but never fail open.
            logger.error("Cedar evaluation error: %s", exc)
            return PolicyDecision(
                result=DecisionResult.DENY,
                reason=f"cedar:evaluation-error ({exc})",
            )

        if allowed:
            return PolicyDecision(
                result=DecisionResult.ALLOW,
                reason="cedar:permit",
            )

        return PolicyDecision(
            result=DecisionResult.DENY,
            reason="cedar:no-matching-permit",
        )
