"""Tests for MCP tool auto-discovery and classification."""

import json
import pytest
import yaml
from pathlib import Path

from apg.discover import (
    Confidence,
    ToolDiscovery,
    generate_mappings_yaml,
    load_tools_from_file,
)


# ---------------------------------------------------------------------------
# Fixtures: realistic MCP tool definitions
# ---------------------------------------------------------------------------

def _tool(
    name: str,
    description: str = "",
    annotations: dict | None = None,
    properties: dict | None = None,
    required: list | None = None,
) -> dict:
    """Helper to build a tool definition matching MCP tools/list format."""
    tool = {"name": name}
    if description:
        tool["description"] = description
    if annotations:
        tool["annotations"] = annotations
    if properties or required:
        schema: dict = {"type": "object"}
        if properties:
            schema["properties"] = properties
        if required:
            schema["required"] = required
        tool["inputSchema"] = schema
    return tool


# Reference filesystem server tools (from @modelcontextprotocol/server-filesystem)
FILESYSTEM_TOOLS = [
    _tool("read_text_file", "Read complete contents of a file as text",
          annotations={"readOnlyHint": True},
          properties={"path": {"type": "string"}}, required=["path"]),
    _tool("read_media_file", "Read an image or audio file",
          annotations={"readOnlyHint": True},
          properties={"path": {"type": "string"}}, required=["path"]),
    _tool("read_multiple_files", "Read multiple files simultaneously",
          annotations={"readOnlyHint": True},
          properties={"paths": {"type": "array"}}, required=["paths"]),
    _tool("write_file", "Create or overwrite a file",
          annotations={"readOnlyHint": False, "idempotentHint": True, "destructiveHint": False},
          properties={"path": {"type": "string"}, "content": {"type": "string"}},
          required=["path", "content"]),
    _tool("edit_file", "Make targeted edits using advanced diff",
          annotations={"readOnlyHint": False, "idempotentHint": False, "destructiveHint": False},
          properties={"path": {"type": "string"}, "edits": {"type": "array"}},
          required=["path", "edits"]),
    _tool("list_directory", "List files and directories at a path",
          annotations={"readOnlyHint": True},
          properties={"path": {"type": "string"}}, required=["path"]),
    _tool("directory_tree", "Recursive directory listing as tree",
          annotations={"readOnlyHint": True},
          properties={"path": {"type": "string"}}, required=["path"]),
    _tool("move_file", "Move or rename a file or directory",
          annotations={"readOnlyHint": False, "idempotentHint": False, "destructiveHint": True},
          properties={"source": {"type": "string"}, "destination": {"type": "string"}},
          required=["source", "destination"]),
    _tool("search_files", "Search for files matching a pattern",
          annotations={"readOnlyHint": True},
          properties={"path": {"type": "string"}, "pattern": {"type": "string"}},
          required=["path", "pattern"]),
    _tool("get_file_info", "Get metadata about a file or directory",
          annotations={"readOnlyHint": True},
          properties={"path": {"type": "string"}}, required=["path"]),
]


class TestTier1Annotations:
    """Tier 1: Classification from MCP ToolAnnotations."""

    def test_read_only_hint_classifies_as_read(self) -> None:
        discovery = ToolDiscovery()
        tools = [_tool("some_tool", annotations={"readOnlyHint": True})]
        results = discovery.discover_from_tools_list(tools)
        assert len(results) == 1
        assert results[0].action_type == "read"
        assert results[0].confidence == Confidence.HIGH

    def test_destructive_hint_classifies_as_delete(self) -> None:
        discovery = ToolDiscovery()
        tools = [_tool("some_tool", annotations={"destructiveHint": True})]
        results = discovery.discover_from_tools_list(tools)
        assert results[0].action_type == "delete"
        assert results[0].confidence == Confidence.HIGH

    def test_idempotent_not_readonly_classifies_as_write(self) -> None:
        discovery = ToolDiscovery()
        tools = [_tool("some_tool", annotations={
            "readOnlyHint": False, "idempotentHint": True, "destructiveHint": False,
        })]
        results = discovery.discover_from_tools_list(tools)
        assert results[0].action_type == "write"
        assert results[0].confidence == Confidence.HIGH

    def test_not_readonly_no_other_hints_classifies_as_write(self) -> None:
        discovery = ToolDiscovery()
        tools = [_tool("some_tool", annotations={"readOnlyHint": False})]
        results = discovery.discover_from_tools_list(tools)
        assert results[0].action_type == "write"
        assert results[0].confidence == Confidence.HIGH

    def test_empty_annotations_fall_through(self) -> None:
        discovery = ToolDiscovery()
        tools = [_tool("read_file", annotations={})]
        results = discovery.discover_from_tools_list(tools)
        # Should fall to tier 2 (name heuristic)
        assert results[0].confidence == Confidence.MEDIUM

    def test_destructive_gets_risk_escalation(self) -> None:
        discovery = ToolDiscovery()
        tools = [_tool("drop_table", annotations={"destructiveHint": True})]
        results = discovery.discover_from_tools_list(tools)
        assert any(r["risk"] == "high" for r in results[0].risk_escalation)


class TestTier2NameHeuristics:
    """Tier 2: Classification from tool name keywords."""

    def test_read_keyword(self) -> None:
        discovery = ToolDiscovery()
        for name in ["read_config", "get_status", "fetch_data", "list_items"]:
            results = discovery.discover_from_tools_list([_tool(name)])
            assert results[0].action_type == "read", f"Failed for {name}"
            assert results[0].confidence == Confidence.MEDIUM

    def test_write_keyword(self) -> None:
        discovery = ToolDiscovery()
        for name in ["create_file", "update_record", "edit_document", "save_data"]:
            results = discovery.discover_from_tools_list([_tool(name)])
            assert results[0].action_type == "write", f"Failed for {name}"

    def test_delete_keyword(self) -> None:
        discovery = ToolDiscovery()
        for name in ["delete_file", "remove_entry", "destroy_session", "purge_cache"]:
            results = discovery.discover_from_tools_list([_tool(name)])
            assert results[0].action_type == "delete", f"Failed for {name}"

    def test_execute_keyword(self) -> None:
        discovery = ToolDiscovery()
        for name in ["run_command", "execute_query", "bash", "shell_exec"]:
            results = discovery.discover_from_tools_list([_tool(name)])
            assert results[0].action_type == "execute", f"Failed for {name}"

    def test_camel_case_tokenization(self) -> None:
        discovery = ToolDiscovery()
        results = discovery.discover_from_tools_list([_tool("readTextFile")])
        assert results[0].action_type == "read"

    def test_kebab_case_tokenization(self) -> None:
        discovery = ToolDiscovery()
        results = discovery.discover_from_tools_list([_tool("delete-user-data")])
        assert results[0].action_type == "delete"

    def test_delete_takes_priority_over_read(self) -> None:
        """If name contains both read and delete keywords, delete wins (safer)."""
        discovery = ToolDiscovery()
        results = discovery.discover_from_tools_list([_tool("read_and_delete_logs")])
        assert results[0].action_type == "delete"

    def test_execute_takes_priority_over_read(self) -> None:
        discovery = ToolDiscovery()
        results = discovery.discover_from_tools_list([_tool("run_search_query")])
        assert results[0].action_type == "execute"


class TestTier3Fallback:
    """Tier 3: No signal, flagged for review."""

    def test_unknown_name_no_annotations(self) -> None:
        discovery = ToolDiscovery()
        results = discovery.discover_from_tools_list([_tool("frobulate")])
        assert results[0].confidence == Confidence.LOW
        assert results[0].needs_review is True

    def test_shell_schema_infers_execute(self) -> None:
        """Even without name/annotation signal, a 'command' field implies execute."""
        discovery = ToolDiscovery()
        tools = [_tool("frobulate", properties={"command": {"type": "string"}})]
        results = discovery.discover_from_tools_list(tools)
        assert results[0].action_type == "execute"
        assert results[0].category == "shell"


class TestSchemaAnalysis:
    """Input schema field analysis for resource_field and category."""

    def test_path_field_detected(self) -> None:
        discovery = ToolDiscovery()
        tools = [_tool("read_data", annotations={"readOnlyHint": True},
                        properties={"path": {"type": "string"}})]
        results = discovery.discover_from_tools_list(tools)
        assert results[0].resource_field == "path"
        assert results[0].resource_prefix == "file:"
        assert results[0].category == "filesystem"

    def test_command_field_detected(self) -> None:
        discovery = ToolDiscovery()
        tools = [_tool("run_script", properties={"command": {"type": "string"}})]
        results = discovery.discover_from_tools_list(tools)
        assert results[0].resource_field == "command"
        assert results[0].resource_prefix == "shell:"

    def test_url_field_detected(self) -> None:
        discovery = ToolDiscovery()
        tools = [_tool("fetch_page", properties={"url": {"type": "string"}})]
        results = discovery.discover_from_tools_list(tools)
        assert results[0].resource_field == "url"
        assert results[0].resource_prefix == "url:"

    def test_query_field_detected(self) -> None:
        discovery = ToolDiscovery()
        tools = [_tool("search_db", properties={"query": {"type": "string"}})]
        results = discovery.discover_from_tools_list(tools)
        assert results[0].resource_field == "query"
        assert results[0].category == "data"

    def test_no_schema_gives_null_resource(self) -> None:
        discovery = ToolDiscovery()
        tools = [_tool("do_thing", annotations={"readOnlyHint": True})]
        results = discovery.discover_from_tools_list(tools)
        assert results[0].resource_field is None


class TestExistingMappings:
    """Merge behavior with existing mappings."""

    def test_skips_already_mapped_tools(self) -> None:
        existing = {"read_file": {"action_type": "read"}}
        discovery = ToolDiscovery(existing_mappings=existing)
        tools = [_tool("read_file"), _tool("write_file")]
        results = discovery.discover_from_tools_list(tools)
        assert len(results) == 1
        assert results[0].tool_name == "write_file"


class TestReferenceFilesystemServer:
    """Test against actual MCP reference filesystem server tool definitions."""

    def test_all_filesystem_tools_classified(self) -> None:
        discovery = ToolDiscovery()
        results = discovery.discover_from_tools_list(FILESYSTEM_TOOLS)
        assert len(results) == len(FILESYSTEM_TOOLS)

        by_name = {r.tool_name: r for r in results}

        # Read tools
        for name in ["read_text_file", "read_media_file", "read_multiple_files",
                      "list_directory", "directory_tree", "search_files", "get_file_info"]:
            assert by_name[name].action_type == "read", f"{name} should be read"
            assert by_name[name].confidence == Confidence.HIGH, f"{name} should be high confidence"

        # Write tools
        assert by_name["write_file"].action_type == "write"
        assert by_name["write_file"].confidence == Confidence.HIGH
        assert by_name["edit_file"].action_type == "write"

        # Destructive tool
        assert by_name["move_file"].action_type == "delete"
        assert by_name["move_file"].confidence == Confidence.HIGH

    def test_filesystem_tools_have_path_resource(self) -> None:
        discovery = ToolDiscovery()
        results = discovery.discover_from_tools_list(FILESYSTEM_TOOLS)
        path_tools = [r for r in results if r.resource_field == "path"]
        # Most filesystem tools have a path field
        assert len(path_tools) >= 7


class TestYAMLGeneration:
    """Test the YAML output."""

    def test_generates_valid_yaml(self) -> None:
        discovery = ToolDiscovery()
        results = discovery.discover_from_tools_list(FILESYSTEM_TOOLS[:3])
        yaml_text = generate_mappings_yaml(results)

        parsed = yaml.safe_load(yaml_text)
        assert "mappings" in parsed
        assert "default" in parsed

    def test_includes_provenance_comments(self) -> None:
        discovery = ToolDiscovery()
        results = discovery.discover_from_tools_list(FILESYSTEM_TOOLS[:1])
        yaml_text = generate_mappings_yaml(results, include_comments=True)
        assert "Confidence:" in yaml_text
        assert "Reason:" in yaml_text

    def test_flags_review_items(self) -> None:
        discovery = ToolDiscovery()
        results = discovery.discover_from_tools_list([_tool("xyzzy_widget")])
        yaml_text = generate_mappings_yaml(results)
        assert "NEEDS REVIEW" in yaml_text

    def test_summary_counts(self) -> None:
        discovery = ToolDiscovery()
        results = discovery.discover_from_tools_list(FILESYSTEM_TOOLS)
        yaml_text = generate_mappings_yaml(results)
        assert "high confidence" in yaml_text


class TestFileLoading:
    """Test loading tools from JSON files."""

    def test_load_tools_array(self, tmp_path: Path) -> None:
        tools = [{"name": "read_file"}, {"name": "write_file"}]
        f = tmp_path / "tools.json"
        f.write_text(json.dumps(tools))
        loaded = load_tools_from_file(f)
        assert len(loaded) == 2

    def test_load_tools_list_response(self, tmp_path: Path) -> None:
        response = {"tools": [{"name": "read_file"}, {"name": "bash"}]}
        f = tmp_path / "tools.json"
        f.write_text(json.dumps(response))
        loaded = load_tools_from_file(f)
        assert len(loaded) == 2

    def test_load_invalid_format_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.json"
        f.write_text(json.dumps({"not_tools": []}))
        with pytest.raises(ValueError, match="Unrecognized format"):
            load_tools_from_file(f)
