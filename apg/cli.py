"""APG CLI - management commands for the Agent Policy Gateway."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import yaml

from apg.config import load_config


@click.group()
@click.option(
    "--config", "config_path",
    default="config/apg.yaml",
    envvar="APG_CONFIG",
    help="Path to APG configuration file.",
)
@click.pass_context
def cli(ctx: click.Context, config_path: str) -> None:
    """apg - Agent Policy Gateway management CLI."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path
    ctx.obj["config"] = load_config(config_path)


@cli.command()
@click.pass_context
def serve(ctx: click.Context) -> None:
    """Start the APG server."""
    from apg.server import run_server
    run_server(config_path=ctx.obj["config_path"])


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show current APG configuration and status."""
    config = ctx.obj["config"]
    click.echo(f"Mode:          {config.mode.value}")
    click.echo(f"Listen:        {config.host}:{config.port}")
    click.echo(f"Policy dir:    {config.policy_dir}")
    click.echo(f"Identity:      {config.identity_method}")
    click.echo(f"Audit output:  {config.audit.output}")
    click.echo(f"Mappings file: {config.mappings_file}")

    if config.mode.value == "observe":
        click.echo(f"\nObserve mode:  {config.observe.mode}")
        click.echo(f"Observe data:  {config.observe.data_dir}")
        click.echo(f"Collapse threshold: {config.observe.generalization.file_collapse_threshold}")


@cli.group()
def mode() -> None:
    """Switch APG operating mode."""


@mode.command("enforce")
@click.pass_context
def mode_enforce(ctx: click.Context) -> None:
    """Switch to enforce mode (deny unauthorized requests)."""
    _set_mode(ctx.obj["config_path"], "enforce")
    click.echo("Mode set to ENFORCE. Restart the server for changes to take effect.")


@mode.command("audit")
@click.pass_context
def mode_audit(ctx: click.Context) -> None:
    """Switch to audit mode (log decisions, always allow)."""
    _set_mode(ctx.obj["config_path"], "audit")
    click.echo("Mode set to AUDIT. Restart the server for changes to take effect.")


@mode.command("observe")
@click.pass_context
def mode_observe(ctx: click.Context) -> None:
    """Switch to observe mode (capture behavior for policy generation)."""
    config = ctx.obj["config"]
    click.echo("")
    click.echo("=" * 60)
    click.echo("  OBSERVE MODE")
    click.echo("=" * 60)
    click.echo(f"  {config.observe.disclaimer if hasattr(config.observe, 'disclaimer') else ''}")
    click.echo("=" * 60)
    click.echo("")

    if not click.confirm("Enable observe mode?"):
        click.echo("Cancelled.")
        return

    _set_mode(ctx.obj["config_path"], "observe")
    click.echo("Mode set to OBSERVE. Restart the server for changes to take effect.")


def _set_mode(config_path: str, mode: str) -> None:
    """Update the mode in the config file."""
    path = Path(config_path)
    if not path.exists():
        click.echo(f"Config file not found: {path}", err=True)
        raise SystemExit(1)

    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw.setdefault("gateway", {})["mode"] = mode
    path.write_text(yaml.dump(raw, default_flow_style=False), encoding="utf-8")


@cli.group()
def observe() -> None:
    """Observe mode management commands."""


@observe.command("stats")
@click.pass_context
def observe_stats(ctx: click.Context) -> None:
    """Show observation collection statistics."""
    config = ctx.obj["config"]
    data_dir = Path(config.observe.data_dir)

    if not data_dir.exists():
        click.echo("No observation data found.")
        return

    agent_files = list(data_dir.glob("*.jsonl"))
    if not agent_files:
        click.echo("No observations collected yet.")
        return

    click.echo(f"Observation data directory: {data_dir}")
    click.echo(f"Agents observed: {len(agent_files)}")
    click.echo("")

    for f in sorted(agent_files):
        line_count = sum(1 for _ in f.open())
        click.echo(f"  {f.stem}: {line_count} observations")


@observe.command("generate")
@click.option("--agent", "agent_id", default=None, help="Generate for a specific agent only.")
@click.option("--output-dir", default=None, help="Output directory for generated policies.")
@click.pass_context
def observe_generate(ctx: click.Context, agent_id: str | None, output_dir: str | None) -> None:
    """Generate Cedar policies from collected observations."""
    from apg.observe.collector import ObservationCollector
    from apg.observe.profile import ProfileBuilder
    from apg.observe.generator import PolicyGenerator

    config = ctx.obj["config"]
    data_dir = Path(config.observe.data_dir)

    if not data_dir.exists():
        click.echo("No observation data found. Run in observe mode first.", err=True)
        raise SystemExit(1)

    # Determine output directory
    out_dir = Path(output_dir) if output_dir else Path(config.policy_dir) / "staged"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Check if we're in delta mode
    from apg.policy.loader import PolicyLoader
    loader = PolicyLoader(config.policy_dir)
    delta = loader.has_policies()

    collector = ObservationCollector(data_dir=data_dir)
    builder = ProfileBuilder()
    generator = PolicyGenerator(config=config.observe.generalization)

    agents = [agent_id] if agent_id else collector.get_all_agent_ids()

    if not agents:
        click.echo("No agents with observations found.", err=True)
        raise SystemExit(1)

    for aid in agents:
        records = collector.get_observations(aid)
        if not records:
            click.echo(f"  {aid}: no observations, skipping")
            continue

        profile = builder.build(aid, records)
        policy_text = generator.generate(profile, delta=delta)

        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in aid)
        out_file = out_dir / f"{safe_name}.cedar"
        out_file.write_text(policy_text, encoding="utf-8")

        click.echo(f"  {aid}: {profile.total_calls} calls -> {out_file}")

    click.echo(f"\nGenerated policies written to: {out_dir}")
    click.echo("Review the generated files, then run 'apg policy promote' to apply.")


@observe.command("clear")
@click.option("--agent", "agent_id", default=None, help="Clear observations for a specific agent only.")
@click.pass_context
def observe_clear(ctx: click.Context, agent_id: str | None) -> None:
    """Clear collected observation data."""
    config = ctx.obj["config"]
    data_dir = Path(config.observe.data_dir)

    if not data_dir.exists():
        click.echo("No observation data to clear.")
        return

    target = f"agent {agent_id}" if agent_id else "all agents"
    if not click.confirm(f"Clear observation data for {target}?"):
        click.echo("Cancelled.")
        return

    from apg.observe.collector import ObservationCollector
    collector = ObservationCollector(data_dir=data_dir)
    collector.clear(agent_id=agent_id)
    click.echo(f"Observation data cleared for {target}.")


@cli.group()
def policy() -> None:
    """Policy management commands."""


@policy.command("list")
@click.pass_context
def policy_list(ctx: click.Context) -> None:
    """List loaded policy files."""
    config = ctx.obj["config"]
    policy_dir = Path(config.policy_dir)

    if not policy_dir.exists():
        click.echo(f"Policy directory not found: {policy_dir}")
        return

    cedar_files = sorted(policy_dir.glob("*.cedar"))
    if not cedar_files:
        click.echo("No .cedar policy files found.")
        return

    click.echo(f"Policy directory: {policy_dir}")
    for f in cedar_files:
        size = f.stat().st_size
        click.echo(f"  {f.name} ({size} bytes)")


@policy.command("validate")
@click.argument("file", type=click.Path(exists=True, path_type=Path))
def policy_validate(file: Path) -> None:
    """Validate Cedar policy syntax."""
    import cedarpy

    try:
        policy_text = file.read_text(encoding="utf-8")
    except OSError as exc:
        click.echo(f"Cannot read file: {exc}", err=True)
        raise SystemExit(1)

    try:
        result = cedarpy.is_authorized(
            request={
                "principal": 'Agent::"_check"',
                "action": 'Action::"_check"',
                "resource": 'Tool::"_check"',
            },
            policies=policy_text,
            entities=[],
        )
        errors = result.diagnostics.errors
        if errors:
            click.echo(f"Invalid Cedar policy: {'; '.join(errors)}", err=True)
            raise SystemExit(1)
        click.echo(f"Policy syntax valid: {file}")
    except Exception as exc:
        click.echo(f"Validation error: {exc}", err=True)
        raise SystemExit(1)


@policy.command("promote")
@click.option("--staged-dir", default=None, help="Directory containing staged policies.")
@click.pass_context
def policy_promote(ctx: click.Context, staged_dir: str | None) -> None:
    """Promote staged policies to the active policy directory."""
    import shutil

    config = ctx.obj["config"]
    active_dir = Path(config.policy_dir)
    staged = Path(staged_dir) if staged_dir else active_dir / "staged"

    if not staged.exists():
        click.echo("No staged policies found.", err=True)
        raise SystemExit(1)

    cedar_files = list(staged.glob("*.cedar"))
    if not cedar_files:
        click.echo("No .cedar files in staged directory.", err=True)
        raise SystemExit(1)

    click.echo(f"Promoting {len(cedar_files)} policy file(s) from {staged} to {active_dir}:")
    for f in cedar_files:
        click.echo(f"  {f.name}")

    if not click.confirm("Proceed?"):
        click.echo("Cancelled.")
        return

    active_dir.mkdir(parents=True, exist_ok=True)
    for f in cedar_files:
        shutil.copy2(f, active_dir / f.name)

    click.echo(f"Promoted {len(cedar_files)} file(s). Policies will reload automatically if hot_reload is enabled.")


@policy.command("diff")
@click.option("--staged-dir", default=None, help="Directory containing staged policies.")
@click.pass_context
def policy_diff(ctx: click.Context, staged_dir: str | None) -> None:
    """Show differences between staged and active policies."""
    import difflib

    config = ctx.obj["config"]
    active_dir = Path(config.policy_dir)
    staged = Path(staged_dir) if staged_dir else active_dir / "staged"

    if not staged.exists():
        click.echo("No staged policies found.", err=True)
        raise SystemExit(1)

    for staged_file in sorted(staged.glob("*.cedar")):
        active_file = active_dir / staged_file.name

        staged_lines = staged_file.read_text(encoding="utf-8").splitlines(keepends=True)

        if active_file.exists():
            active_lines = active_file.read_text(encoding="utf-8").splitlines(keepends=True)
            diff = difflib.unified_diff(
                active_lines, staged_lines,
                fromfile=f"active/{staged_file.name}",
                tofile=f"staged/{staged_file.name}",
            )
            diff_text = "".join(diff)
            if diff_text:
                click.echo(diff_text)
            else:
                click.echo(f"{staged_file.name}: no differences")
        else:
            click.echo(f"\n--- /dev/null")
            click.echo(f"+++ staged/{staged_file.name}")
            click.echo(f"  (new file, {len(staged_lines)} lines)")


if __name__ == "__main__":
    cli()
