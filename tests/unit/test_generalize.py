"""Tests for observe mode generalization."""

import pytest

from apg.config import ObserveGeneralizationConfig
from apg.observe.generalize import CommandGeneralizer, PathGeneralizer


@pytest.fixture
def config() -> ObserveGeneralizationConfig:
    return ObserveGeneralizationConfig(
        file_collapse_threshold=3,
        max_wildcard_depth=1,
        extension_grouping=True,
        command_prefix_tokens=1,
        compound_command_prefixes=["pip install", "python -m"],
        never_wildcard=["*.env", "*.key"],
        never_permit_commands=["rm -rf", "sudo"],
    )


class TestPathGeneralizer:
    def test_below_threshold_lists_individually(self, config: ObserveGeneralizationConfig) -> None:
        gen = PathGeneralizer(config)
        paths = ["file:src/auth/login.py", "file:src/auth/signup.py"]
        rules = gen.generalize(paths)
        # 2 files < threshold of 3, so listed individually
        assert len(rules) == 2
        assert all(not r.collapsed for r in rules)

    def test_at_threshold_collapses(self, config: ObserveGeneralizationConfig) -> None:
        gen = PathGeneralizer(config)
        paths = [
            "file:src/auth/login.py",
            "file:src/auth/signup.py",
            "file:src/auth/reset.py",
        ]
        rules = gen.generalize(paths)
        # 3 files >= threshold, collapsed to wildcard
        collapsed = [r for r in rules if r.collapsed]
        assert len(collapsed) >= 1
        assert any("*" in r.pattern for r in collapsed)

    def test_extension_grouping(self, config: ObserveGeneralizationConfig) -> None:
        gen = PathGeneralizer(config)
        paths = [
            "file:src/auth/login.py",
            "file:src/auth/signup.py",
            "file:src/auth/reset.py",
            "file:src/auth/notes.md",
        ]
        rules = gen.generalize(paths)
        # Should group .py files together, .md separately
        patterns = [r.pattern for r in rules]
        assert any(".py" in p for p in patterns)

    def test_protected_paths_never_wildcarded(self, config: ObserveGeneralizationConfig) -> None:
        gen = PathGeneralizer(config)
        paths = [
            "file:src/.env",
            "file:src/config.py",
            "file:src/main.py",
            "file:src/utils.py",
        ]
        rules = gen.generalize(paths)
        env_rules = [r for r in rules if ".env" in r.pattern]
        assert all(r.flagged for r in env_rules)

    def test_empty_input(self, config: ObserveGeneralizationConfig) -> None:
        gen = PathGeneralizer(config)
        rules = gen.generalize([])
        assert rules == []

    def test_mixed_directories(self, config: ObserveGeneralizationConfig) -> None:
        gen = PathGeneralizer(config)
        paths = [
            "file:src/auth/login.py",
            "file:src/auth/signup.py",
            "file:src/auth/reset.py",
            "file:src/models/user.py",
            "file:tests/test_auth.py",
        ]
        rules = gen.generalize(paths)
        # src/auth should collapse, src/models and tests should be individual
        assert len(rules) >= 3  # at least: auth/*, models/user.py, tests/test_auth.py


class TestCommandGeneralizer:
    def test_groups_by_prefix(self, config: ObserveGeneralizationConfig) -> None:
        gen = CommandGeneralizer(config)
        commands = [
            "shell:pytest tests/unit/",
            "shell:pytest tests/integration/",
            "shell:pytest --cov",
        ]
        rules = gen.generalize(commands)
        assert len(rules) == 1
        assert "pytest" in rules[0].pattern
        assert rules[0].source_count == 3

    def test_compound_prefix(self, config: ObserveGeneralizationConfig) -> None:
        gen = CommandGeneralizer(config)
        commands = [
            "shell:pip install requests",
            "shell:pip install flask",
        ]
        rules = gen.generalize(commands)
        assert len(rules) == 1
        assert "pip install" in rules[0].pattern

    def test_dangerous_commands_flagged(self, config: ObserveGeneralizationConfig) -> None:
        gen = CommandGeneralizer(config)
        commands = [
            "shell:pytest tests/",
            "shell:rm -rf /tmp/junk",
            "shell:sudo apt update",
        ]
        rules = gen.generalize(commands)
        flagged = [r for r in rules if r.flagged]
        assert len(flagged) == 2  # rm -rf and sudo

    def test_empty_input(self, config: ObserveGeneralizationConfig) -> None:
        gen = CommandGeneralizer(config)
        rules = gen.generalize([])
        assert rules == []

    def test_single_command(self, config: ObserveGeneralizationConfig) -> None:
        gen = CommandGeneralizer(config)
        rules = gen.generalize(["shell:node server.js"])
        assert len(rules) == 1
        assert not rules[0].collapsed  # single command, not collapsed
