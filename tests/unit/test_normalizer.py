"""Tests for the semantic normalizer."""

import pytest
from pathlib import Path

from apg.models import ActionType, AgentIdentity, CheckRequest, RiskLevel
from apg.normalizer.engine import SemanticNormalizer


@pytest.fixture
def mappings_file(tmp_path: Path) -> Path:
    content = """
mappings:
  read_file:
    action_type: read
    resource_field: path
    resource_prefix: "file:"
    category: filesystem
  write_file:
    action_type: write
    resource_field: path
    resource_prefix: "file:"
    category: filesystem
  bash:
    action_type: execute
    resource_field: command
    resource_prefix: "shell:"
    category: shell
    risk_escalation:
      - pattern: "rm -rf"
        risk: critical
      - pattern: "sudo"
        risk: high
default:
  action_type: unknown
  resource_field: null
  resource_prefix: "unknown:"
  category: unknown
"""
    f = tmp_path / "mappings.yaml"
    f.write_text(content, encoding="utf-8")
    return f


@pytest.fixture
def normalizer(mappings_file: Path) -> SemanticNormalizer:
    return SemanticNormalizer(mappings_file=mappings_file)


@pytest.fixture
def agent() -> AgentIdentity:
    return AgentIdentity(agent_id="agent-001", environment="dev")


def test_read_file_normalized(normalizer: SemanticNormalizer, agent: AgentIdentity) -> None:
    req = CheckRequest(
        agent_id="agent-001",
        tool_name="read_file",
        tool_arguments={"path": "src/main.py"},
        environment="dev",
    )
    result = normalizer.normalize(agent, req)
    assert result.action_type == ActionType.READ
    assert result.resource_path == "file:src/main.py"
    assert result.category == "filesystem"
    assert result.risk_level == RiskLevel.LOW


def test_write_file_normalized(normalizer: SemanticNormalizer, agent: AgentIdentity) -> None:
    req = CheckRequest(
        agent_id="agent-001",
        tool_name="write_file",
        tool_arguments={"path": "output.txt"},
        environment="dev",
    )
    result = normalizer.normalize(agent, req)
    assert result.action_type == ActionType.WRITE
    assert result.resource_path == "file:output.txt"
    assert result.risk_level == RiskLevel.MEDIUM


def test_bash_normalized(normalizer: SemanticNormalizer, agent: AgentIdentity) -> None:
    req = CheckRequest(
        agent_id="agent-001",
        tool_name="bash",
        tool_arguments={"command": "pytest tests/"},
        environment="dev",
    )
    result = normalizer.normalize(agent, req)
    assert result.action_type == ActionType.EXECUTE
    assert result.resource_path == "shell:pytest tests/"
    assert result.category == "shell"


def test_bash_rm_rf_escalates_to_critical(normalizer: SemanticNormalizer, agent: AgentIdentity) -> None:
    req = CheckRequest(
        agent_id="agent-001",
        tool_name="bash",
        tool_arguments={"command": "rm -rf /tmp/stuff"},
        environment="dev",
    )
    result = normalizer.normalize(agent, req)
    assert result.risk_level == RiskLevel.CRITICAL


def test_bash_sudo_escalates_to_high(normalizer: SemanticNormalizer, agent: AgentIdentity) -> None:
    req = CheckRequest(
        agent_id="agent-001",
        tool_name="bash",
        tool_arguments={"command": "sudo apt install vim"},
        environment="dev",
    )
    result = normalizer.normalize(agent, req)
    assert result.risk_level == RiskLevel.HIGH


def test_unknown_tool_classified(normalizer: SemanticNormalizer, agent: AgentIdentity) -> None:
    req = CheckRequest(
        agent_id="agent-001",
        tool_name="future_tool",
        tool_arguments={"data": "something"},
        environment="dev",
    )
    result = normalizer.normalize(agent, req)
    assert result.action_type == ActionType.UNKNOWN
    assert result.category == "unknown"
    assert result.risk_level == RiskLevel.MEDIUM


def test_prod_environment_elevates_risk(normalizer: SemanticNormalizer) -> None:
    agent = AgentIdentity(agent_id="agent-001", environment="prod")
    req = CheckRequest(
        agent_id="agent-001",
        tool_name="read_file",
        tool_arguments={"path": "config.yaml"},
        environment="prod",
    )
    result = normalizer.normalize(agent, req)
    # read is normally LOW, but prod elevates to MEDIUM
    assert result.risk_level == RiskLevel.MEDIUM


def test_sensitive_path_elevates_risk(normalizer: SemanticNormalizer, agent: AgentIdentity) -> None:
    req = CheckRequest(
        agent_id="agent-001",
        tool_name="read_file",
        tool_arguments={"path": "/home/user/.ssh/id_rsa"},
        environment="dev",
    )
    result = normalizer.normalize(agent, req)
    assert result.risk_level == RiskLevel.HIGH


def test_has_mapping(normalizer: SemanticNormalizer) -> None:
    assert normalizer.has_mapping("read_file") is True
    assert normalizer.has_mapping("nonexistent") is False


def test_known_tools(normalizer: SemanticNormalizer) -> None:
    tools = normalizer.known_tools
    assert "read_file" in tools
    assert "write_file" in tools
    assert "bash" in tools
