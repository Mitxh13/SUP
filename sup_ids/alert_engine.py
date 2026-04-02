"""
sup_ids/alert_engine.py
=======================
PHASE 5 — ALERT

Builds fixed-schema JSON alert payloads from trigger dicts produced by
BruteTracker. Every alert is written to the local JSONL backup file
regardless of whether Splunk forwarding succeeds.

Alert JSON schema (all 11 fields always present)
-------------------------------------------------
  alert_type    : str   — e.g. "BRUTE_FORCE_SSH"
  severity      : str   — CRITICAL | HIGH | MEDIUM | LOW
  src_ip        : str
  username      : str
  attempt_count : int
  hostname      : str   — system hostname
  platform      : str   — "linux" | "windows"
  source_log    : str   — log file path or "Security Event Log"
  event_hash    : str   — SHA-256 of (alert_type + ip + user + raw_ts)
  timestamp     : str   — ISO-8601 UTC
  message       : str   — human-readable summary

Public API
----------
    engine = AlertEngine(config)
    alert  = engine.build(trigger)          # returns dict or None (dedup)
    line   = engine.format_console(alert)   # coloured terminal line
"""

from __future__ import annotations

import hashlib
import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sup_ids.config import SupConfig

# ---------------------------------------------------------------------------
# Routing tables
# ---------------------------------------------------------------------------

_SEVERITY: dict[str, str] = {
    "ROOT_LOGIN":         "CRITICAL",
    "WIN_PRIVILEGE_USE":  "HIGH",
    "WIN_ACCOUNT_LOCK":   "MEDIUM",
    "SSH_FAILED":         "HIGH",
    "INVALID_USER":       "HIGH",
    "WIN_LOGON_FAILED":   "HIGH",
    "SUDO_FAILURE":       "MEDIUM",
    "PAM_FAILURE":        "LOW",
}

_ALERT_TYPE: dict[str, str] = {
    "ROOT_LOGIN":         "ROOT_LOGIN_DETECTED",
    "WIN_PRIVILEGE_USE":  "PRIVILEGE_ESCALATION",
    "WIN_ACCOUNT_LOCK":   "ACCOUNT_LOCKOUT",
    "SSH_FAILED":         "BRUTE_FORCE_SSH",
    "INVALID_USER":       "BRUTE_FORCE_SSH",
    "WIN_LOGON_FAILED":   "BRUTE_FORCE_WINDOWS",
    "SUDO_FAILURE":       "SUDO_ESCALATION_ATTEMPT",
    "PAM_FAILURE":        "PAM_AUTH_FAILURE",
}

_HOSTNAME = socket.gethostname()

# ANSI colour codes for terminal output
_COLOURS: dict[str, str] = {
    "CRITICAL": "\033[1;31m",   # bold red
    "HIGH":     "\033[31m",     # red
    "MEDIUM":   "\033[33m",     # yellow
    "LOW":      "\033[36m",     # cyan
}
_RESET = "\033[0m"


# ---------------------------------------------------------------------------
# AlertEngine
# ---------------------------------------------------------------------------

class AlertEngine:
    """
    Builds and persists alert payloads.

    Parameters
    ----------
    config : SupConfig
    """

    # In-memory deduplication ceiling — cleared when exceeded
    _HASH_LIMIT = 100_000

    def __init__(self, config: SupConfig):
        self.config         = config
        self._seen_hashes:  set[str] = set()
        self._backup_path:  Optional[Path] = None
        self._setup_backup()

    # ------------------------------------------------------------------
    def _setup_backup(self) -> None:
        """Create the output directory and set the JSONL backup path."""
        out = Path(self.config.output_dir)
        try:
            out.mkdir(parents=True, exist_ok=True)
            self._backup_path = out / "alerts.jsonl"
        except PermissionError:
            fallback = Path.home() / ".sup" / "alerts.jsonl"
            fallback.parent.mkdir(parents=True, exist_ok=True)
            self._backup_path = fallback
            print(
                f"[WARN] Cannot write to {out}; falling back to {fallback}",
                file=sys.stderr,
            )

    # ------------------------------------------------------------------
    def build(self, trigger: dict) -> Optional[dict]:
        """
        Convert a trigger dict (from BruteTracker) into a full alert payload.

        Returns None if this event was already alerted (in-memory dedup).

        Parameters
        ----------
        trigger : dict
            Must contain at minimum: event_type, src_ip, username,
            timestamp, platform, raw, attempt_count, trigger.

        Returns
        -------
        dict | None
        """
        etype    = trigger.get("event_type", "UNKNOWN")
        src_ip   = trigger.get("src_ip",   "")
        username = trigger.get("username", "")
        count    = int(trigger.get("attempt_count", 1))
        platform = trigger.get("platform", sys.platform)
        ts_raw   = trigger.get("timestamp", "")

        alert_type = _ALERT_TYPE.get(etype, f"UNKNOWN_{etype}")
        severity   = _SEVERITY.get(etype, "LOW")

        # ── Source log label ──────────────────────────────────────────
        if platform == "windows":
            source_log = "Security Event Log"
        elif self.config.log_files:
            source_log = self.config.log_files[0]
        else:
            source_log = "/var/log/auth.log"

        # ── UTC timestamp ─────────────────────────────────────────────
        utc_now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # ── SHA-256 event hash (deduplication key) ───────────────────
        hash_input = f"{alert_type}:{src_ip}:{username}:{ts_raw}"
        event_hash = hashlib.sha256(hash_input.encode()).hexdigest()

        if event_hash in self._seen_hashes:
            return None     # duplicate suppressed
        self._seen_hashes.add(event_hash)

        # Prevent unbounded memory growth in long-running sessions
        if len(self._seen_hashes) > self._HASH_LIMIT:
            self._seen_hashes.clear()

        # ── Human-readable message ────────────────────────────────────
        if trigger.get("trigger") == "THRESHOLD":
            message = (
                f"Brute-force threshold exceeded: {count} attempts "
                f"in {self.config.brute_window}s from {src_ip or 'unknown'}"
            )
        elif etype == "ROOT_LOGIN":
            message = f"Root / Administrator login detected from {src_ip or 'unknown'}"
        elif etype in ("SUDO_FAILURE", "WIN_PRIVILEGE_USE"):
            message = f"Privilege escalation attempt by user {username!r}"
        elif etype == "WIN_ACCOUNT_LOCK":
            message = f"Account {username!r} locked out"
        else:
            message = f"{alert_type} detected from {src_ip or 'unknown'}"

        # ── Assemble payload ──────────────────────────────────────────
        alert: dict = {
            "alert_type":    alert_type,
            "severity":      severity,
            "src_ip":        src_ip,
            "username":      username,
            "attempt_count": count,
            "hostname":      _HOSTNAME,
            "platform":      platform,
            "source_log":    source_log,
            "event_hash":    event_hash,
            "timestamp":     utc_now,
            "message":       message,
        }

        self._write_backup(alert)
        return alert

    # ------------------------------------------------------------------
    def _write_backup(self, alert: dict) -> None:
        """Append the alert to the local JSONL backup file."""
        if not self._backup_path:
            return
        try:
            with self._backup_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(alert) + "\n")
        except OSError as exc:
            print(f"[WARN] JSONL backup write failed: {exc}", file=sys.stderr)

    # ------------------------------------------------------------------
    def format_console(self, alert: dict) -> str:
        """Return a coloured, human-readable one-line alert string."""
        sev    = alert.get("severity", "LOW")
        colour = _COLOURS.get(sev, "")
        return (
            f"{colour}[{sev:8s}]{_RESET}  "
            f"{alert['timestamp']}  "
            f"{alert['alert_type']:30s}  "
            f"ip={alert['src_ip'] or 'n/a':<18}  "
            f"user={alert['username'] or 'n/a'}"
        )

    # ------------------------------------------------------------------
    def recent_alerts(self, n: int = 10) -> list[dict]:
        """
        Read the last *n* alerts from the JSONL backup file.
        Returns an empty list if the file does not exist or is unreadable.
        """
        if not self._backup_path or not self._backup_path.exists():
            return []
        try:
            lines = self._backup_path.read_text(encoding="utf-8").strip().splitlines()
            alerts = []
            for raw in lines[-n:]:
                try:
                    alerts.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue
            return alerts
        except OSError:
            return []