"""End-to-end test for the observe pipeline: capture -> profile -> generalize -> generate Cedar."""

import pytest
from pathlib import Path

from apg.config import ObserveGeneralizationConfig
from apg.models import (
    ActionType,
    AgentIdentity,
    DecisionResult,
    NormalizedRequest,
    PolicyDecision,
    RiskLevel,
)
from apg.observe.collector import ObservationCollector
from apg.observe.profile import ProfileBuilder
from apg.observe.generator import PolicyGenerator


def _make_request(
    agent_id: str = "claude-dev-001",
    tool: str = "read_file",
    action: ActionType = ActionType.READ,
    resource: str = "file:src/main.py",
    risk: RiskLevel = RiskLevel.LOW,
    env: str = "dev",
    session: str = "sess_001",
) -> NormalizedRequest:
    return NormalizedRequest(
        agent=AgentIdentity(agent_id=agent_id, environment=env),
        tool_name=tool,
        action_type=action,
        resource_path=resource,
        risk_level=risk,
        category="filesystem" if tool != "bash" else "shell",
        session_id=session,
        environment=env,
    )


def _allow() -> PolicyDecision:
    return PolicyDecision(result=DecisionResult.ALLOW, reason="cedar:permit")


def _deny() -> PolicyDecision:
    return PolicyDecision(result=DecisionResult.DENY, reason="cedar:no-matching-permit")


class TestCollector:
    def test_full_mode_captures_all(self, tmp_path: Path) -> None:
        collector = ObservationCollector(data_dir=tmp_path, mode="full")
        req = _make_request()
        assert collector.collect(req, _allow()) is True
        assert collector.collect(req, _deny()) is True
        records = collector.get_observations("claude-dev-001")
        assert len(records) == 2

    def test_delta_mode_only_captures_denials(self, tmp_path: Path) -> None:
        collector = ObservationCollector(data_dir=tmp_path, mode="delta")
        req = _make_request()
        assert collector.collect(req, _allow()) is False
        assert collector.collect(req, _deny()) is True
        records = collector.get_observations("claude-dev-001")
        assert len(records) == 1
        assert records[0].would_deny is True

    def test_multiple_agents_tracked_separately(self, tmp_path: Path) -> None:
        collector = ObservationCollector(data_dir=tmp_path, mode="full")
        collector.collect(_make_request(agent_id="agent-a"), _allow())
        collector.collect(_make_request(agent_id="agent-b"), _deny())
        assert "agent-a" in collector.get_all_agent_ids()
        assert "agent-b" in collector.get_all_agent_ids()
        assert len(collector.get_observations("agent-a")) == 1
        assert len(collector.get_observations("agent-b")) == 1

    def test_stats(self, tmp_path: Path) -> None:
        collector = ObservationCollector(data_dir=tmp_path, mode="full")
        for _ in range(5):
            collector.collect(_make_request(), _allow())
        stats = collector.get_stats()
        assert stats["total_observations"] == 5
        assert stats["agents_observed"] == 1

    def test_clear_agent(self, tmp_path: Path) -> None:
        collector = ObservationCollector(data_dir=tmp_path, mode="full")
        collector.collect(_make_request(agent_id="agent-a"), _allow())
        collector.collect(_make_request(agent_id="agent-b"), _allow())
        collector.clear(agent_id="agent-a")
        assert collector.get_observations("agent-a") == []
        assert len(collector.get_observations("agent-b")) == 1

    def test_clear_all(self, tmp_path: Path) -> None:
        collector = ObservationCollector(data_dir=tmp_path, mode="full")
        collector.collect(_make_request(agent_id="agent-a"), _allow())
        collector.collect(_make_request(agent_id="agent-b"), _allow())
        collector.clear()
        assert collector.get_all_agent_ids() == []


class TestProfileBuilder:
    def test_builds_profile_from_observations(self, tmp_path: Path) -> None:
        collector = ObservationCollector(data_dir=tmp_path, mode="full")

        # Simulate realistic agent behavior
        reads = [
            "file:src/auth/login.py",
            "file:src/auth/signup.py",
            "file:src/auth/reset.py",
            "file:src/auth/oauth.py",
            "file:src/auth/middleware.py",
            "file:src/models/user.py",
            "file:src/models/session.py",
            "file:README.md",
        ]
        writes = [
            "file:src/auth/login.py",
            "file:src/auth/signup.py",
            "file:tests/test_auth.py",
        ]
        executes = [
            "shell:pytest tests/",
            "shell:pytest tests/test_auth.py",
            "shell:python -m pytest --cov",
            "shell:pip install requests",
        ]

        for path in reads:
            collector.collect(
                _make_request(resource=path, action=ActionType.READ, tool="read_file"),
                _allow(),
            )
        for path in writes:
            collector.collect(
                _make_request(resource=path, action=ActionType.WRITE, tool="write_file", risk=RiskLevel.MEDIUM),
                _allow(),
            )
        for cmd in executes:
            collector.collect(
                _make_request(resource=cmd, action=ActionType.EXECUTE, tool="bash", risk=RiskLevel.MEDIUM),
                _allow(),
            )

        records = collector.get_observations("claude-dev-001")
        builder = ProfileBuilder()
        profile = builder.build("claude-dev-001", records)

        assert profile.total_calls == len(reads) + len(writes) + len(executes)
        assert profile.action_counts["read"] == len(reads)
        assert profile.action_counts["write"] == len(writes)
        assert profile.action_counts["execute"] == len(executes)
        assert "dev" in profile.environments
        assert "delete" not in profile.action_counts

    def test_empty_records(self) -> None:
        builder = ProfileBuilder()
        profile = builder.build("empty-agent", [])
        assert profile.total_calls == 0


class TestFullObservePipeline:
    """End-to-end: collect observations -> build profile -> generate Cedar policy."""

    def test_generates_valid_cedar_from_observations(self, tmp_path: Path) -> None:
        collector = ObservationCollector(data_dir=tmp_path, mode="full")

        # Simulate a dev agent doing typical work
        observations = [
            ("read_file", ActionType.READ, "file:src/auth/login.py", RiskLevel.LOW),
            ("read_file", ActionType.READ, "file:src/auth/signup.py", RiskLevel.LOW),
            ("read_file", ActionType.READ, "file:src/auth/reset.py", RiskLevel.LOW),
            ("read_file", ActionType.READ, "file:src/auth/oauth.py", RiskLevel.LOW),
            ("read_file", ActionType.READ, "file:src/auth/middleware.py", RiskLevel.LOW),
            ("read_file", ActionType.READ, "file:src/models/user.py", RiskLevel.LOW),
            ("read_file", ActionType.READ, "file:README.md", RiskLevel.LOW),
            ("write_file", ActionType.WRITE, "file:src/auth/login.py", RiskLevel.MEDIUM),
            ("write_file", ActionType.WRITE, "file:src/auth/signup.py", RiskLevel.MEDIUM),
            ("write_file", ActionType.WRITE, "file:tests/test_auth.py", RiskLevel.MEDIUM),
            ("bash", ActionType.EXECUTE, "shell:pytest tests/", RiskLevel.MEDIUM),
            ("bash", ActionType.EXECUTE, "shell:pytest tests/test_auth.py", RiskLevel.MEDIUM),
            ("bash", ActionType.EXECUTE, "shell:pip install requests", RiskLevel.MEDIUM),
        ]

        for tool, action, resource, risk in observations:
            collector.collect(
                _make_request(tool=tool, action=action, resource=resource, risk=risk),
                _allow(),
            )

        # Build profile
        records = collector.get_observations("claude-dev-001")
        builder = ProfileBuilder()
        profile = builder.build("claude-dev-001", records)

        # Generate Cedar policy
        config = ObserveGeneralizationConfig(
            file_collapse_threshold=3,
            never_wildcard=["*.env", "*.key"],
            never_permit_commands=["rm -rf", "sudo"],
            compound_command_prefixes=["pip install", "python -m"],
        )
        generator = PolicyGenerator(config=config)
        policy_text = generator.generate(profile, delta=False)

        # Validate the generated policy contains expected elements
        assert "claude-dev-001" in policy_text
        assert "AUTO-GENERATED" in policy_text
        assert "permit(" in policy_text
        assert "forbid(" in policy_text
        assert "action_type" in policy_text
        assert "environment" in policy_text

        # Should have wildcarded src/auth (5 files >= threshold of 3)
        assert "src/auth" in policy_text

        # Should have recommended forbids for things never observed
        assert "prod" in policy_text  # forbid prod since never observed
        assert "delete" in policy_text  # forbid delete since never observed

        # Should contain execute rules with command prefixes
        assert "pytest" in policy_text
        assert "pip install" in policy_text

    def test_delta_mode_generates_additive_policy(self, tmp_path: Path) -> None:
        collector = ObservationCollector(data_dir=tmp_path, mode="delta")

        # Only denied calls get captured in delta mode
        collector.collect(
            _make_request(resource="file:src/new_module/helper.py", action=ActionType.READ),
            _deny(),
        )
        collector.collect(
            _make_request(resource="file:src/new_module/utils.py", action=ActionType.READ),
            _deny(),
        )

        records = collector.get_observations("claude-dev-001")
        builder = ProfileBuilder()
        profile = builder.build("claude-dev-001", records)

        config = ObserveGeneralizationConfig(file_collapse_threshold=5)
        generator = PolicyGenerator(config=config)
        policy_text = generator.generate(profile, delta=True)

        assert "DELTA POLICY" in policy_text
        assert "DENIED by current policy" in policy_text
        # 2 files < threshold, so listed individually
        assert "new_module/helper.py" in policy_text
        assert "new_module/utils.py" in policy_text

    def test_flagged_paths_not_auto_permitted(self, tmp_path: Path) -> None:
        collector = ObservationCollector(data_dir=tmp_path, mode="full")

        collector.collect(
            _make_request(resource="file:src/.env", action=ActionType.READ),
            _allow(),
        )

        records = collector.get_observations("claude-dev-001")
        builder = ProfileBuilder()
        profile = builder.build("claude-dev-001", records)

        config = ObserveGeneralizationConfig(never_wildcard=["*.env"])
        generator = PolicyGenerator(config=config)
        policy_text = generator.generate(profile)

        assert "FLAGGED" in policy_text
        assert "not auto-permitted" in policy_text

    def test_dangerous_commands_flagged(self, tmp_path: Path) -> None:
        collector = ObservationCollector(data_dir=tmp_path, mode="full")

        collector.collect(
            _make_request(
                tool="bash", action=ActionType.EXECUTE,
                resource="shell:rm -rf /tmp/junk", risk=RiskLevel.CRITICAL,
            ),
            _allow(),
        )
        collector.collect(
            _make_request(
                tool="bash", action=ActionType.EXECUTE,
                resource="shell:pytest tests/", risk=RiskLevel.MEDIUM,
            ),
            _allow(),
        )

        records = collector.get_observations("claude-dev-001")
        builder = ProfileBuilder()
        profile = builder.build("claude-dev-001", records)

        config = ObserveGeneralizationConfig(never_permit_commands=["rm -rf"])
        generator = PolicyGenerator(config=config)
        policy_text = generator.generate(profile)

        # rm -rf should be flagged, pytest should be permitted
        assert "FLAGGED" in policy_text
        assert "dangerous pattern" in policy_text.lower() or "never_permit" in policy_text.lower()

    def test_profile_to_dict_serializable(self, tmp_path: Path) -> None:
        collector = ObservationCollector(data_dir=tmp_path, mode="full")
        collector.collect(_make_request(), _allow())

        records = collector.get_observations("claude-dev-001")
        builder = ProfileBuilder()
        profile = builder.build("claude-dev-001", records)

        data = profile.to_dict()
        assert data["agent_id"] == "claude-dev-001"
        assert data["total_calls"] == 1
        assert "read" in data["action_types"]
        assert data["action_types"]["read"]["pct"] == 100.0
