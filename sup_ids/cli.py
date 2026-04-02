"""
sup_ids/cli.py
==============
Click-based CLI entry point.

Commands
--------
    sup start            Start monitoring + forwarding
    sup start --dry-run  Detect only (no HEC POST)
    sup status           Show stats and last 10 alerts from JSONL backup
    sup config show      Print active merged config
    sup config init      Write default sup.toml
    sup test-hec         Verify Splunk HEC connectivity
    sup --version        Print version string

Pipeline wired here in order:
  INPUT (platform_reader) → PARSE (log_parser) →
  ROUTE+DETECT (brute_tracker) → ALERT (alert_engine) →
  FORWARD (splunk_forwarder)
"""

from __future__ import annotations

import json
import signal
import sys
from collections import Counter
from pathlib import Path

import click

from sup_ids import __version__
from sup_ids.config import SupConfig, load_config, TOML_TEMPLATE
from sup_ids.log_parser import parse_linux_line, parse_windows_event
from sup_ids.platform_reader import get_reader
from sup_ids.brute_tracker import BruteTracker
from sup_ids.alert_engine import AlertEngine
from sup_ids.splunk_forwarder import SplunkForwarder


# ===========================================================================
# Root CLI group
# ===========================================================================

@click.group()
@click.version_option(__version__, prog_name="sup")
def cli():
    """SUP — Systemic Undercover Predator

    \b
    Open-source cross-platform CLI Intrusion Detection System.
    Brute-Force Detection  •  Splunk SIEM Forwarding

    \b
    Quick start:
      sup config init                   # generate sup.toml
      sup start --dry-run --verbose     # test without Splunk
      sup start --hec-token MY_TOKEN    # full run with Splunk
    """


# ===========================================================================
# sup start
# ===========================================================================

@cli.command("start")
@click.option("--hec-url",    "hec_url",   default=None, metavar="URL",   help="Splunk HEC endpoint URL")
@click.option("--hec-token",  "hec_token", default=None, metavar="TOKEN", help="Splunk HEC Bearer token  [required without --dry-run]")
@click.option("--index",      default=None, metavar="NAME",  help="Target Splunk index  [default: sup_ids]")
@click.option("--threshold",  default=None, type=int, metavar="N",    help="Failed attempts before HIGH alert  [default: 5]")
@click.option("--window",     default=None, type=int, metavar="SECS", help="Sliding-window duration in seconds  [default: 60]")
@click.option("--log-file",   "log_file",  default=None, type=click.Path(), help="Override monitored log file path")
@click.option("--dry-run",    is_flag=True, default=False, help="Detect only — skip HEC forwarding")
@click.option("--config",     "config_path", default="sup.toml", type=click.Path(), show_default=True, help="Path to TOML config file")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Print parsed events in real time")
def cmd_start(
    hec_url, hec_token, index, threshold, window,
    log_file, dry_run, config_path, verbose,
):
    """Start monitoring log files and forwarding alerts to Splunk."""

    # ── Load and merge config ─────────────────────────────────────────
    cfg = load_config(
        path=Path(config_path),
        splunk_hec_url=hec_url,
        splunk_hec_token=hec_token,
        splunk_index=index,
        brute_threshold=threshold,
        brute_window=window,
        log_files=[log_file] if log_file else None,
        dry_run=dry_run,
        verbose=verbose,
    )

    errors = cfg.validate()
    if errors:
        for e in errors:
            click.echo(f"[CONFIG ERROR] {e}", err=True)
        sys.exit(1)

    if not dry_run and not cfg.splunk_hec_token:
        click.echo(
            "[WARN] No HEC token set. Running in implicit dry-run mode.\n"
            "       Pass --hec-token TOKEN or set splunk_hec_token in sup.toml\n"
            "       to forward alerts to Splunk.",
            err=True,
        )
        cfg.dry_run = True

    # ── Banner ────────────────────────────────────────────────────────
    click.echo(
        f"\n  ╔══════════════════════════════════════════════════╗\n"
        f"  ║   SUP — Systemic Undercover Predator  v{__version__:<9} ║\n"
        f"  ╚══════════════════════════════════════════════════╝\n"
        f"  Platform  : {sys.platform}\n"
        f"  Threshold : {cfg.brute_threshold} failures / {cfg.brute_window}s window\n"
        f"  Log files : {cfg.log_files}\n"
        f"  Output    : {cfg.output_dir}\n"
        f"  Dry-run   : {cfg.dry_run}\n"
        f"  Splunk    : {cfg.splunk_hec_url}  index={cfg.splunk_index}\n"
    )

    # ── Initialise modules ────────────────────────────────────────────
    reader    = get_reader(cfg, verbose=verbose)
    tracker   = BruteTracker(cfg)
    engine    = AlertEngine(cfg)
    forwarder = SplunkForwarder(
        hec_url=cfg.splunk_hec_url,
        hec_token=cfg.splunk_hec_token,
        index=cfg.splunk_index,
        verify_ssl=cfg.splunk_verify_ssl,
        dry_run=cfg.dry_run,
        verbose=verbose,
    )

    # ── Graceful shutdown handler ─────────────────────────────────────
    events_parsed = 0
    alerts_fired  = 0

    def _shutdown(signum, frame):
        nonlocal events_parsed, alerts_fired
        click.echo(
            f"\n\n[SUP] Shutting down …\n"
            f"  Events parsed : {events_parsed}\n"
            f"  Alerts fired  : {alerts_fired}\n"
        )
        reader.stop()

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    click.echo("[SUP] Monitoring started.  Press Ctrl+C to stop.\n")

    # ── Main pipeline loop ────────────────────────────────────────────
    try:
        for raw_entry in reader.stream():
            if reader.stopped:
                break

            # PHASE 2 — PARSE
            if isinstance(raw_entry, dict):
                event = parse_windows_event(raw_entry)  # Windows path
            else:
                event = parse_linux_line(raw_entry)     # Linux path

            if event is None:
                continue

            events_parsed += 1

            if verbose:
                click.echo(
                    f"  [PARSE]  {event['event_type']:<20}  "
                    f"ip={event['src_ip']!r:<18}  "
                    f"user={event['username']!r}"
                )

            # PHASE 3+4 — ROUTE + DETECT
            trigger = tracker.process(event)
            if trigger is None:
                continue

            # PHASE 5 — ALERT
            alert = engine.build(trigger)
            if alert is None:
                continue    # deduplicated

            alerts_fired += 1
            click.echo(engine.format_console(alert))

            # PHASE 6 — FORWARD
            forwarder.send(alert)

    finally:
        forwarder.close()

    click.echo(
        f"\n[SUP] Stopped.\n"
        f"  Events parsed : {events_parsed}\n"
        f"  Alerts fired  : {alerts_fired}\n"
    )


# ===========================================================================
# sup status
# ===========================================================================

@cli.command("status")
@click.option("--config", "config_path", default="sup.toml", type=click.Path())
def cmd_status(config_path):
    """Show detection statistics and the last 10 alerts."""
    cfg    = load_config(path=Path(config_path))
    engine = AlertEngine(cfg)
    alerts = engine.recent_alerts(n=10)

    click.echo(f"\n  SUP v{__version__} — Status\n")

    if not alerts:
        click.echo("  No alerts found in backup.\n")
        return

    # Severity counts
    counts = Counter(a.get("severity", "?") for a in alerts)
    click.echo(f"  Alerts (last {len(alerts)} from backup):")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if counts.get(sev):
            click.echo(f"    {sev:<10} {counts[sev]}")

    click.echo()
    for a in alerts:
        click.echo(
            f"  [{a.get('severity','?'):8s}] "
            f"{a.get('timestamp','?')}  "
            f"{a.get('alert_type','?'):30s}  "
            f"ip={a.get('src_ip','n/a')}"
        )
    click.echo()


# ===========================================================================
# sup config
# ===========================================================================

@cli.group("config")
def cmd_config():
    """Manage SUP configuration."""


@cmd_config.command("show")
@click.option("--config", "config_path", default="sup.toml", type=click.Path())
def config_show(config_path):
    """Print the active configuration (file + CLI overrides merged)."""
    cfg = load_config(path=Path(config_path))
    click.echo("\n" + cfg.display() + "\n")


@cmd_config.command("init")
@click.option("--output", "-o", default="sup.toml", type=click.Path(), show_default=True)
def config_init(output):
    """Generate a default sup.toml config file."""
    dest = Path(output)
    if dest.exists():
        if not click.confirm(f"'{dest}' already exists. Overwrite?"):
            click.echo("Aborted.")
            return
    dest.write_text(TOML_TEMPLATE, encoding="utf-8")
    click.echo(f"[OK] Config written to '{dest}'")
    click.echo("     Edit the file and set splunk_hec_token before running 'sup start'.")


# ===========================================================================
# sup test-hec
# ===========================================================================

@cli.command("test-hec")
@click.option("--hec-url",   "hec_url",   default=None)
@click.option("--hec-token", "hec_token", default=None, required=False)
@click.option("--index",     default=None)
@click.option("--config", "config_path",  default="sup.toml", type=click.Path())
def cmd_test_hec(hec_url, hec_token, index, config_path):
    """Send a test event to Splunk HEC and confirm connectivity."""
    cfg = load_config(
        path=Path(config_path),
        splunk_hec_url=hec_url,
        splunk_hec_token=hec_token,
        splunk_index=index,
    )
    if not cfg.splunk_hec_token:
        click.echo(
            "[ERROR] HEC token is required.\n"
            "  Pass --hec-token TOKEN  or set splunk_hec_token in sup.toml",
            err=True,
        )
        sys.exit(1)

    with SplunkForwarder(
        hec_url=cfg.splunk_hec_url,
        hec_token=cfg.splunk_hec_token,
        index=cfg.splunk_index,
        verify_ssl=cfg.splunk_verify_ssl,
        verbose=True,
    ) as fwd:
        ok = fwd.test_connection()

    sys.exit(0 if ok else 1)


# ===========================================================================
# Entry point
# ===========================================================================

def main():
    cli()


if __name__ == "__main__":
    main()