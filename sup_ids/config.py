"""
sup_ids/config.py
=================
Configuration loader for SUP IDS.

Merge priority (highest → lowest):
  1. CLI flags
  2. sup.toml config file
  3. Built-in defaults

Usage:
    from sup_ids.config import load_config
    cfg = load_config(path="sup.toml", threshold=10)
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# TOML library — Python 3.11+ ships tomllib; older versions need tomli
# ---------------------------------------------------------------------------
try:
    import tomllib                  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib     # pip install tomli
    except ImportError:
        tomllib = None


# ---------------------------------------------------------------------------
# Platform helpers
# ---------------------------------------------------------------------------

def _default_output_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")
        return Path(base) / "sup"
    return Path("/var/log/sup")


def _auto_log_files() -> list[str]:
    """Return existing auth log paths for the current OS."""
    if sys.platform == "win32":
        return []  # Windows uses Event Log API — no file paths needed
    candidates = [
        "/var/log/auth.log",   # Debian / Ubuntu
        "/var/log/secure",     # RHEL / CentOS / Fedora
        "/var/log/syslog",     # Generic fallback
    ]
    found = [p for p in candidates if Path(p).exists()]
    return found if found else [candidates[0]]  # Always at least one entry


# ---------------------------------------------------------------------------
# SupConfig dataclass
# ---------------------------------------------------------------------------

@dataclass
class SupConfig:
    # ── Detection ────────────────────────────────────────────────────────────
    brute_threshold: int   = 5       # failed attempts before HIGH alert
    brute_window:    int   = 60      # sliding-window duration in seconds
    poll_interval:   float = 0.5     # log file polling frequency in seconds
    tail_mode:       bool  = True    # True = start from EOF

    # ── Splunk / HEC ─────────────────────────────────────────────────────────
    splunk_hec_url:   str  = "http://localhost:8088"
    splunk_hec_token: str  = ""
    splunk_index:     str  = "sup_ids"
    splunk_verify_ssl: bool = False

    # ── I/O ──────────────────────────────────────────────────────────────────
    log_files:  list  = field(default_factory=_auto_log_files)
    output_dir: Path  = field(default_factory=_default_output_dir)

    # ── Runtime ───────────────────────────────────────────────────────────────
    dry_run: bool = False
    verbose: bool = False

    # -------------------------------------------------------------------------
    def merge_toml(self, path: Path) -> None:
        """Load and overlay settings from a TOML file."""
        if tomllib is None:
            print(
                "[WARN] No TOML parser found. "
                "Run: pip install tomli  (Python < 3.11)",
                file=sys.stderr,
            )
            return
        if not path.exists():
            return

        with path.open("rb") as fh:
            data: dict = tomllib.load(fh)

        # Map TOML keys to dataclass fields
        scalar_keys = [
            "brute_threshold", "brute_window", "poll_interval", "tail_mode",
            "splunk_hec_url", "splunk_hec_token", "splunk_index",
            "splunk_verify_ssl", "dry_run", "verbose",
        ]
        for key in scalar_keys:
            if key in data:
                setattr(self, key, data[key])

        if "log_files" in data:
            self.log_files = data["log_files"]

        if "output_dir" in data:
            self.output_dir = Path(data["output_dir"])

    # -------------------------------------------------------------------------
    def merge_cli(self, **kwargs) -> None:
        """Overlay settings from CLI flags (None values are skipped)."""
        for key, val in kwargs.items():
            if val is None:
                continue
            if not hasattr(self, key):
                continue
            if key == "output_dir" and isinstance(val, str):
                val = Path(val)
            setattr(self, key, val)

    # -------------------------------------------------------------------------
    def validate(self) -> list[str]:
        """Return a list of validation error strings (empty list = valid)."""
        errors: list[str] = []
        if self.brute_threshold < 1:
            errors.append("brute_threshold must be >= 1")
        if self.brute_window < 1:
            errors.append("brute_window must be >= 1 second")
        if self.poll_interval <= 0:
            errors.append("poll_interval must be > 0")
        if not isinstance(self.log_files, list):
            errors.append("log_files must be a list of paths")
        return errors

    # -------------------------------------------------------------------------
    def display(self) -> str:
        """Return a human-readable config table string."""
        lines = [
            "┌─ SUP Active Configuration ─────────────────────────────────┐",
        ]
        for f in fields(self):
            val = getattr(self, f.name)
            lines.append(f"│  {f.name:<24} {str(val)}")
        lines.append("└────────────────────────────────────────────────────────────┘")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# TOML template  (written by `sup config init`)
# ---------------------------------------------------------------------------

TOML_TEMPLATE = """\
# sup.toml — SUP IDS Configuration
# Generated by: sup config init
# Merge priority: CLI flags > this file > built-in defaults
# Rename to sup.toml and edit before running.

# ── Detection ────────────────────────────────────────────────
brute_threshold = 5       # failed attempts before HIGH alert fires
brute_window    = 60      # sliding-window duration in seconds
poll_interval   = 0.5     # log file polling frequency in seconds
tail_mode       = true    # true = tail from EOF; false = read full history

# ── Splunk HEC ───────────────────────────────────────────────
splunk_hec_url   = "http://localhost:8088"
splunk_hec_token = ""          # REQUIRED — paste your HEC token here
splunk_index     = "sup_ids"
splunk_verify_ssl = false      # set true in production with valid TLS cert

# ── Log Files (optional override) ───────────────────────────
# By default SUP auto-detects platform log paths.
# Uncomment to override:
# log_files = [
#   "/var/log/auth.log",
#   "/var/log/secure",
# ]

# ── Output Directory ─────────────────────────────────────────
# Linux default : /var/log/sup/
# Windows default: %APPDATA%\\sup\\
# output_dir = "/var/log/sup"
"""


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------

def load_config(
    path: Optional[Path] = None,
    **cli_overrides,
) -> SupConfig:
    """
    Build a SupConfig by applying (in order):
      1. Built-in defaults
      2. TOML file at *path* (default: sup.toml in CWD)
      3. Any provided *cli_overrides*

    Returns a fully-merged SupConfig instance.
    """
    cfg = SupConfig()
    cfg.merge_toml(path or Path("sup.toml"))
    cfg.merge_cli(**cli_overrides)
    return cfg