"""Identity resolution from JWT claims or request headers."""

from __future__ import annotations

import logging
from typing import Any

import jwt

from apg.models import AgentIdentity, CheckRequest

logger = logging.getLogger(__name__)


class IdentityResolutionError(Exception):
    """Raised when agent identity cannot be resolved."""


class IdentityResolver:
    """Resolves agent identity from JWT claims or request headers.

    AgentGateway forwards JWT claims in the ExtAuthz metadata or as
    request headers. This resolver extracts them into an AgentIdentity.
    """

    def __init__(
        self,
        method: str = "jwt",
        header_name: str = "X-Agent-Id",
        jwt_secret: str = "",
        jwt_algorithms: list[str] | None = None,
    ):
        self._method = method
        self._header_name = header_name
        self._jwt_secret = jwt_secret
        self._jwt_algorithms = jwt_algorithms or ["HS256", "RS256"]

    def resolve(self, request: CheckRequest) -> AgentIdentity:
        """Resolve agent identity from the inbound check request."""
        if self._method == "jwt":
            return self._resolve_jwt(request)
        if self._method == "header":
            return self._resolve_header(request)
        if self._method == "passthrough":
            return self._resolve_passthrough(request)
        raise IdentityResolutionError(f"Unknown identity method: {self._method}")

    def _resolve_jwt(self, request: CheckRequest) -> AgentIdentity:
        """Extract identity from JWT claims forwarded by AgentGateway.

        AgentGateway decodes the JWT and can forward claims as metadata
        in the ExtAuthz request. If pre-decoded claims are present in
        request.jwt_claims, use those directly. Otherwise fall back to
        the agent_id field.
        """
        claims = request.jwt_claims
        if not claims and not request.agent_id:
            raise IdentityResolutionError(
                "No JWT claims or agent_id found in request. "
                "Ensure AgentGateway is configured to forward JWT metadata."
            )

        return AgentIdentity(
            agent_id=claims.get("sub", claims.get("agent_id", request.agent_id)),
            owner=claims.get("owner", ""),
            team=claims.get("team", ""),
            runtime=claims.get("runtime", ""),
            environment=request.environment,
            raw_claims=claims,
        )

    def _resolve_header(self, request: CheckRequest) -> AgentIdentity:
        """Extract identity from a request header."""
        agent_id = request.request_headers.get(self._header_name, "")
        if not agent_id:
            agent_id = request.agent_id
        if not agent_id:
            raise IdentityResolutionError(
                f"No agent identity found in header '{self._header_name}' or request."
            )
        return AgentIdentity(
            agent_id=agent_id,
            environment=request.environment,
        )

    def _resolve_passthrough(self, request: CheckRequest) -> AgentIdentity:
        """Use whatever agent_id is on the request without validation."""
        return AgentIdentity(
            agent_id=request.agent_id or "anonymous",
            environment=request.environment,
            raw_claims=request.jwt_claims,
        )
