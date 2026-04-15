"""APG server entry point.

Wires together all components and starts the FastAPI application.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI

from apg.audit.logger import AuditLogger
from apg.config import APGConfig, load_config
from apg.extauthz.service import AuthzService, router as authz_router, set_service
from apg.identity.resolver import IdentityResolver
from apg.models import GatewayMode
from apg.normalizer.engine import SemanticNormalizer
from apg.observe.collector import ObservationCollector
from apg.policy.engine import CedarEngine
from apg.policy.loader import PolicyLoader, PolicyLoadError

logger = logging.getLogger(__name__)


def build_app(config: APGConfig | None = None, config_path: str | None = None) -> FastAPI:
    """Build and configure the FastAPI application."""
    if config is None:
        config = load_config(config_path or "config/apg.yaml")

    # Initialize components
    identity_resolver = IdentityResolver(
        method=config.identity_method,
        header_name=config.identity_header,
        jwt_secret=config.jwt_secret,
        jwt_algorithms=config.jwt_algorithms,
    )

    normalizer = SemanticNormalizer(mappings_file=config.mappings_file)

    # Load Cedar policies
    try:
        loader = PolicyLoader(config.policy_dir)
        policies = loader.load()
    except PolicyLoadError:
        logger.warning("No policy directory found at %s. Starting with empty policies.", config.policy_dir)
        policies = ""

    if not policies.strip():
        logger.warning(
            "No Cedar policies loaded. In enforce mode, all requests will be denied. "
            "Add .cedar files to %s or switch to observe mode.",
            config.policy_dir,
        )

    cedar_engine = CedarEngine(policies=policies)

    audit_logger = AuditLogger(
        log_file=config.audit.output,
        redact_keys=config.audit.redact_keys,
    )

    # Initialize observer if in observe mode
    observer: ObservationCollector | None = None
    if config.mode == GatewayMode.OBSERVE:
        observe_mode = config.observe.mode
        if observe_mode == "auto":
            observe_mode = "delta" if policies.strip() else "full"

        observer = ObservationCollector(
            data_dir=config.observe.data_dir,
            mode=observe_mode,
        )
        logger.warning(
            "\n%s\n  Observe mode active (%s). %s\n%s",
            "=" * 60,
            observe_mode,
            config.observe.disclaimer if hasattr(config.observe, 'disclaimer') else "",
            "=" * 60,
        )

    # Wire up the service
    service = AuthzService(
        config=config,
        identity_resolver=identity_resolver,
        normalizer=normalizer,
        cedar_engine=cedar_engine,
        audit_logger=audit_logger,
        observer=observer,
    )
    set_service(service)

    # Store references for management endpoints
    state: dict[str, Any] = {
        "config": config,
        "loader": loader if policies is not None else None,
        "cedar_engine": cedar_engine,
        "observer": observer,
        "normalizer": normalizer,
    }

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger.info(
            "APG starting on %s:%d in %s mode",
            config.host, config.port, config.mode.value,
        )
        yield
        logger.info("APG shutting down")

    app = FastAPI(
        title="Agent Policy Gateway",
        description="Cedar-based intent execution control for LLMs and agents",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.include_router(authz_router, prefix="/v1")
    app.state.apg = state

    # Management endpoints
    @app.get("/v1/status")
    async def status() -> dict[str, Any]:
        return {
            "mode": config.mode.value,
            "policies_loaded": bool(policies.strip()),
            "policy_dir": config.policy_dir,
            "observer_active": observer is not None,
            "observer_stats": observer.get_stats() if observer else None,
        }

    @app.post("/v1/policies/reload")
    async def reload_policies() -> dict[str, Any]:
        if state.get("loader"):
            changed, new_policies = state["loader"].reload_if_changed()
            if changed:
                state["cedar_engine"].update_policies(new_policies)
                return {"reloaded": True, "policy_length": len(new_policies)}
            return {"reloaded": False, "message": "No changes detected"}
        return {"reloaded": False, "message": "No policy loader configured"}

    return app


def run_server(config_path: str = "config/apg.yaml") -> None:
    """Run the APG server."""
    import uvicorn

    config = load_config(config_path)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    app = build_app(config=config)

    uvicorn.run(
        app,
        host=config.host,
        port=config.port,
        log_level="info",
    )
