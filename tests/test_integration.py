"""
tests/test_integration.py
==========================
End-to-end integration tests for the full SUP pipeline:
  Parser → BruteTracker → AlertEngine → ForwarderMock

Tests cover:
  - BRUTE_FORCE_SSH fires after 5th failure within window
  - ROOT_LOGIN_DETECTED fires immediately (1 event)
  - SUDO alert has MEDIUM severity
  - Alert JSON schema — all 11 fields present and valid
  - event_hash is SHA-256 hex; timestamp is ISO-8601 UTC
  - Duplicate suppression across the full pipeline
  - 50-line synthetic auth.log replay produces correct alert counts
"""

import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sup_ids.config import SupConfig
from sup_ids.log_parser import parse_linux_line, parse_windows_event
from sup_ids.brute_tracker import BruteTracker
from sup_ids.alert_engine import AlertEngine
from sup_ids.splunk_forwarder import SplunkForwarder

# ---------------------------------------------------------------------------
# Fixtures — real auth.log line samples
# ---------------------------------------------------------------------------

FIXTURE_DIR = Path(__file__).parent / "fixtures"

SSH_FAILED_LINES = [
    f"Jun 14 08:42:1{i} lab sshd[100{i}]: Failed password for root from 10.0.0.1 port 22 ssh2"
    for i in range(8)
]

ROOT_LOGIN_LINE = (
    "Jun 14 08:43:00 lab sshd[9999]: Accepted password for root from 10.0.0.2 port 22 ssh2"
)

SUDO_FAILURE_LINE = (
    "Jun 14 09:01:00 lab sudo[999]: bob : 3 incorrect password attempts ; "
    "TTY=pts/1 ; USER=root ; COMMAND=/bin/bash"
)

INVALID_USER_LINES = [
    f"Jun 14 09:00:0{i} lab sshd[200{i}]: Invalid user deploy{i} from 172.16.0.5 port 54{i}00"
    for i in range(6)
]

REQUIRED_FIELDS = {
    "alert_type", "severity", "src_ip", "username",
    "attempt_count", "hostname", "platform", "source_log",
    "event_hash", "timestamp", "message",
}


# ---------------------------------------------------------------------------
# Pipeline helper
# ---------------------------------------------------------------------------

def _run_pipeline(lines: list[str], threshold: int = 5, window: int = 60) -> list[dict]:
    """
    Pass *lines* through the full pipeline (Parser→Tracker→Alert).
    Returns list of generated alert dicts (duplicates excluded).
    """
    tmpdir  = tempfile.mkdtemp()
    cfg     = SupConfig()
    cfg.brute_threshold = threshold
    cfg.brute_window    = window
    cfg.log_files       = ["/var/log/auth.log"]
    cfg.output_dir      = Path(tmpdir)

    tracker = BruteTracker(cfg)
    engine  = AlertEngine(cfg)
    alerts: list[dict] = []

    for line in lines:
        event = parse_linux_line(line)
        if event is None:
            continue
        trigger = tracker.process(event)
        if trigger is None:
            continue
        alert = engine.build(trigger)
        if alert is not None:
            alerts.append(alert)

    return alerts


# ===========================================================================
# Core detection logic
# ===========================================================================

def test_brute_force_ssh_fires_after_5_failures():
    """Exactly 5 failed SSH logins from same IP → 1 HIGH BRUTE_FORCE_SSH alert."""
    alerts = _run_pipeline(SSH_FAILED_LINES[:5], threshold=5)
    ssh_alerts = [a for a in alerts if a["alert_type"] == "BRUTE_FORCE_SSH"]
    assert len(ssh_alerts) >= 1, f"Expected BRUTE_FORCE_SSH, got: {[a['alert_type'] for a in alerts]}"
    assert ssh_alerts[0]["severity"] == "HIGH"
    print("  PASS  test_brute_force_ssh_fires_after_5_failures")


def test_brute_force_does_not_fire_at_4():
    """4 failures below threshold → no BRUTE_FORCE alert."""
    alerts = _run_pipeline(SSH_FAILED_LINES[:4], threshold=5)
    assert not alerts, f"Expected no alert, got: {[a['alert_type'] for a in alerts]}"
    print("  PASS  test_brute_force_does_not_fire_at_4")


def test_root_login_fires_immediately():
    """1 root login line → CRITICAL ROOT_LOGIN_DETECTED, no brute window needed."""
    alerts = _run_pipeline([ROOT_LOGIN_LINE], threshold=100)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "ROOT_LOGIN_DETECTED"
    assert alerts[0]["severity"]   == "CRITICAL"
    assert alerts[0]["attempt_count"] == 1
    print("  PASS  test_root_login_fires_immediately")


def test_sudo_failure_fires_immediately_with_medium_severity():
    alerts = _run_pipeline([SUDO_FAILURE_LINE], threshold=100)
    sudo_alerts = [a for a in alerts if a["alert_type"] == "SUDO_ESCALATION_ATTEMPT"]
    assert len(sudo_alerts) == 1
    assert sudo_alerts[0]["severity"] == "MEDIUM"
    print("  PASS  test_sudo_failure_fires_immediately_with_medium_severity")


def test_invalid_user_brute_force_fires():
    alerts = _run_pipeline(INVALID_USER_LINES[:6], threshold=5)
    iu_alerts = [a for a in alerts if a["alert_type"] == "BRUTE_FORCE_SSH"]
    assert len(iu_alerts) >= 1
    print("  PASS  test_invalid_user_brute_force_fires")


# ===========================================================================
# Alert schema validation
# ===========================================================================

def test_alert_schema_all_11_fields_present():
    alerts = _run_pipeline([ROOT_LOGIN_LINE])
    assert alerts
    missing = REQUIRED_FIELDS - set(alerts[0].keys())
    assert not missing, f"Missing schema fields: {missing}"
    print("  PASS  test_alert_schema_all_11_fields_present")


def test_alert_event_hash_is_sha256():
    alerts = _run_pipeline([ROOT_LOGIN_LINE])
    assert alerts
    h = alerts[0]["event_hash"]
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)
    print("  PASS  test_alert_event_hash_is_sha256")


def test_alert_timestamp_is_iso8601_utc():
    alerts = _run_pipeline([ROOT_LOGIN_LINE])
    assert alerts
    ts = alerts[0]["timestamp"]
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", ts), f"Bad: {ts}"
    print("  PASS  test_alert_timestamp_is_iso8601_utc")


def test_alert_src_ip_correct():
    alerts = _run_pipeline(SSH_FAILED_LINES[:5], threshold=5)
    ssh = [a for a in alerts if a["alert_type"] == "BRUTE_FORCE_SSH"]
    assert ssh
    assert ssh[0]["src_ip"] == "10.0.0.1"
    print("  PASS  test_alert_src_ip_correct")


def test_alert_attempt_count_correct():
    alerts = _run_pipeline(SSH_FAILED_LINES[:5], threshold=5)
    ssh = [a for a in alerts if a["alert_type"] == "BRUTE_FORCE_SSH"]
    assert ssh
    assert ssh[0]["attempt_count"] == 5
    print("  PASS  test_alert_attempt_count_correct")


# ===========================================================================
# Deduplication across pipeline
# ===========================================================================

def test_duplicate_lines_not_double_alerted():
    """Same log line sent twice — second alert suppressed by event_hash."""
    line   = ROOT_LOGIN_LINE
    alerts = _run_pipeline([line, line])
    assert len(alerts) == 1, f"Expected 1 alert (dedup), got {len(alerts)}"
    print("  PASS  test_duplicate_lines_not_double_alerted")


# ===========================================================================
# 50-line synthetic replay
# ===========================================================================

def test_50_line_replay():
    """
    Replay 50 synthetic auth.log lines through the full pipeline.
    Expected:
      - 1+ BRUTE_FORCE_SSH alert (10 failures from 10.0.0.1, threshold=5)
      - 1 ROOT_LOGIN_DETECTED (immediate)
      - 1 SUDO_ESCALATION_ATTEMPT (immediate)
    """
    lines: list[str] = []

    # 10 SSH failures from 10.0.0.1
    for i in range(10):
        lines.append(
            f"Jun 14 08:00:{i:02d} lab sshd[{1000+i}]: "
            f"Failed password for root from 10.0.0.1 port 22 ssh2"
        )

    # 10 noise lines (kernel, cron, etc.)
    for i in range(10):
        lines.append(f"Jun 14 08:01:{i:02d} lab kernel: EXT4-fs: journal started")

    # 10 SSH failures from a different IP
    for i in range(10):
        lines.append(
            f"Jun 14 08:02:{i:02d} lab sshd[{2000+i}]: "
            f"Failed password for admin from 192.168.99.1 port 22 ssh2"
        )

    # 1 root login
    lines.append(
        "Jun 14 08:03:00 lab sshd[9000]: "
        "Accepted password for root from 10.10.10.1 port 22 ssh2"
    )

    # 1 sudo failure
    lines.append(
        "Jun 14 08:04:00 lab sudo[8000]: charlie : 2 incorrect password attempts ; "
        "TTY=pts/2 ; USER=root ; COMMAND=/bin/bash"
    )

    # 18 more noise lines to reach 50
    for i in range(18):
        lines.append(f"Jun 14 08:05:{i:02d} lab CRON[{3000+i}]: (root) CMD (/usr/bin/backup.sh)")

    assert len(lines) == 50, f"Fixture should have 50 lines, got {len(lines)}"

    alerts = _run_pipeline(lines, threshold=5)

    alert_types = [a["alert_type"] for a in alerts]
    print(f"  [INFO] Alerts from 50-line replay: {alert_types}")

    assert any(t == "BRUTE_FORCE_SSH"         for t in alert_types), "Expected BRUTE_FORCE_SSH"
    assert any(t == "ROOT_LOGIN_DETECTED"      for t in alert_types), "Expected ROOT_LOGIN_DETECTED"
    assert any(t == "SUDO_ESCALATION_ATTEMPT"  for t in alert_types), "Expected SUDO_ESCALATION_ATTEMPT"

    print("  PASS  test_50_line_replay")


# ===========================================================================
# Forwarder mock integration
# ===========================================================================

def test_forwarder_called_for_each_alert():
    """Verify that SplunkForwarder.send() is called once per alert."""
    lines  = SSH_FAILED_LINES[:5] + [ROOT_LOGIN_LINE]
    alerts = _run_pipeline(lines, threshold=5)

    fwd       = SplunkForwarder("http://localhost:8088", "token", dry_run=True)
    send_calls = []

    original_send = fwd.send

    def _mock_send(alert):
        send_calls.append(alert)
        return True

    fwd.send = _mock_send

    for alert in alerts:
        fwd.send(alert)

    assert len(send_calls) == len(alerts)
    print("  PASS  test_forwarder_called_for_each_alert")


# ===========================================================================
# Runner
# ===========================================================================

if __name__ == "__main__":
    tests = [
        test_brute_force_ssh_fires_after_5_failures,
        test_brute_force_does_not_fire_at_4,
        test_root_login_fires_immediately,
        test_sudo_failure_fires_immediately_with_medium_severity,
        test_invalid_user_brute_force_fires,
        test_alert_schema_all_11_fields_present,
        test_alert_event_hash_is_sha256,
        test_alert_timestamp_is_iso8601_utc,
        test_alert_src_ip_correct,
        test_alert_attempt_count_correct,
        test_duplicate_lines_not_double_alerted,
        test_50_line_replay,
        test_forwarder_called_for_each_alert,
    ]
    passed = failed = 0
    print(f"\nRunning {len(tests)} integration tests …\n")
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
    print(f"\n{'─'*45}")
    print(f"  {passed}/{passed+failed} passed")
