"""Configuration loading and validation for APG."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from apg.models import GatewayMode


@dataclass
class ObserveGeneralizationConfig:
    file_collapse_threshold: int = 5
    max_wildcard_depth: int = 1
    extension_grouping: bool = True
    command_prefix_tokens: int = 1
    compound_command_prefixes: list[str] = field(default_factory=lambda: [
        "pip install", "npm install", "yarn add", "cargo build",
        "go build", "docker build", "python -m",
    ])
    never_wildcard: list[str] = field(default_factory=lambda: [
        "*.env", "*.key", "*.pem", "*.secret", "**/secrets/**",
    ])
    never_permit_commands: list[str] = field(default_factory=lambda: [
        "rm -rf", "sudo", "chmod", "chown", "curl * | sh", "curl * | bash",
    ])


@dataclass
class ObserveConfig:
    mode: str = "auto"  # full | delta | auto
    data_dir: str = "/var/apg/observe"
    auto_disable_after: str | None = None
    reminder_interval_hours: int = 24
    generalization: ObserveGeneralizationConfig = field(default_factory=ObserveGeneralizationConfig)


@dataclass
class AuditConfig:
    enabled: bool = True
    format: str = "jsonl"
    output: str = "/var/log/apg/audit.log"
    redact_keys: list[str] = field(default_factory=lambda: [
        "password", "token", "secret", "key", "credential", "api_key",
    ])


@dataclass
class APGConfig:
    host: str = "0.0.0.0"
    port: int = 9001
    mode: GatewayMode = GatewayMode.ENFORCE
    default: str = "deny"

    # Identity
    identity_method: str = "jwt"
    identity_header: str = "X-Agent-Id"
    jwt_secret: str = ""
    jwt_algorithms: list[str] = field(default_factory=lambda: ["HS256", "RS256"])

    # Cedar
    policy_dir: str = "/etc/apg/policies"
    schema_file: str = ""
    hot_reload: bool = True
    reload_interval_seconds: int = 30

    # Normalizer
    mappings_file: str = "config/tool_mappings.yaml"

    # Sub-configs
    observe: ObserveConfig = field(default_factory=ObserveConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)


def load_config(path: str | Path) -> APGConfig:
    """Load APG configuration from a YAML file."""
    path = Path(path)
    if not path.exists():
        return APGConfig()

    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    gw = raw.get("gateway", {})
    ident = raw.get("identity", {})
    cedar = raw.get("cedar", {})
    norm = raw.get("normalizer", {})
    obs_raw = raw.get("observe", {})
    aud_raw = raw.get("audit", {})

    # Build generalization config
    gen_raw = obs_raw.get("generalization", {})
    gen_config = ObserveGeneralizationConfig(
        file_collapse_threshold=gen_raw.get("file_collapse_threshold", 5),
        max_wildcard_depth=gen_raw.get("max_wildcard_depth", 1),
        extension_grouping=gen_raw.get("extension_grouping", True),
        command_prefix_tokens=gen_raw.get("command_prefix_tokens", 1),
        compound_command_prefixes=gen_raw.get("compound_command_prefixes",
                                              ObserveGeneralizationConfig().compound_command_prefixes),
        never_wildcard=gen_raw.get("never_wildcard", ObserveGeneralizationConfig().never_wildcard),
        never_permit_commands=gen_raw.get("never_permit_commands",
                                          ObserveGeneralizationConfig().never_permit_commands),
    )

    observe = ObserveConfig(
        mode=obs_raw.get("mode", "auto"),
        data_dir=obs_raw.get("data_dir", "/var/apg/observe"),
        auto_disable_after=obs_raw.get("auto_disable_after"),
        reminder_interval_hours=obs_raw.get("reminder_interval_hours", 24),
        generalization=gen_config,
    )

    audit = AuditConfig(
        enabled=aud_raw.get("enabled", True),
        format=aud_raw.get("format", "jsonl"),
        output=aud_raw.get("output", "/var/log/apg/audit.log"),
        redact_keys=aud_raw.get("redact_keys", AuditConfig().redact_keys),
    )

    # Resolve JWT secret from file if specified
    jwt_secret = ""
    jwt_secret_file = ident.get("jwt_secret_file", "")
    if jwt_secret_file and Path(jwt_secret_file).exists():
        jwt_secret = Path(jwt_secret_file).read_text(encoding="utf-8").strip()

    mode_str = gw.get("mode", "enforce")
    try:
        mode = GatewayMode(mode_str)
    except ValueError:
        mode = GatewayMode.ENFORCE

    return APGConfig(
        host=gw.get("host", "0.0.0.0"),
        port=gw.get("port", 9001),
        mode=mode,
        default=gw.get("default", "deny"),
        identity_method=ident.get("method", "jwt"),
        identity_header=ident.get("header", "X-Agent-Id"),
        jwt_secret=jwt_secret,
        jwt_algorithms=ident.get("jwt_algorithms", ["HS256", "RS256"]),
        policy_dir=cedar.get("policy_dir", "/etc/apg/policies"),
        schema_file=cedar.get("schema_file", ""),
        hot_reload=cedar.get("hot_reload", True),
        reload_interval_seconds=cedar.get("reload_interval_seconds", 30),
        mappings_file=norm.get("mappings_file", "config/tool_mappings.yaml"),
        observe=observe,
        audit=audit,
    )
