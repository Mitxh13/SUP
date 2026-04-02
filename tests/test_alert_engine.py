"""
tests/test_alert_engine.py
===========================
Unit tests for sup_ids/alert_engine.py

Tests cover:
  - All 11 schema fields always present
  - Correct severity routing for each event type
  - Correct alert_type mapping
  - event_hash is valid SHA-256 hex
  - timestamp is ISO-8601 UTC format
  - Duplicate suppression (same hash → None)
  - JSONL backup written correctly
  - format_console returns a non-empty string
"""

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sup_ids.config import SupConfig
from sup_ids.alert_engine import AlertEngine

# ---------------------------------------------------------------------------
# Required schema fields
# ---------------------------------------------------------------------------
REQUIRED_FIELDS = {
    "alert_type", "severity", "src_ip", "username",
    "attempt_count", "hostname", "platform", "source_log",
    "event_hash", "timestamp", "message",
}


def _cfg(tmp_dir: str = None) -> SupConfig:
    cfg = SupConfig()
    cfg.brute_threshold = 5
    cfg.brute_window    = 60
    cfg.log_files       = ["/var/log/auth.log"]
    if tmp_dir:
        cfg.output_dir  = Path(tmp_dir)
    else:
        cfg.output_dir  = Path(tempfile.mkdtemp())
    return cfg


def _trigger(
    event_type: str = "SSH_FAILED",
    src_ip:     str = "1.2.3.4",
    username:   str = "root",
    trigger:    str = "THRESHOLD",
    count:      int = 5,
    platform:   str = "linux",
    ts:         str = "Jun 14 09:00:00",
) -> dict:
    return {
        "event_type":    event_type,
        "src_ip":        src_ip,
        "username":      username,
        "timestamp":     ts,
        "platform":      platform,
        "raw":           f"fake line for {event_type}",
        "attempt_count": count,
        "trigger":       trigger,
    }


# ===========================================================================
# Schema completeness
# ===========================================================================

def test_all_schema_fields_present():
    engine = AlertEngine(_cfg())
    alert  = engine.build(_trigger())
    assert alert is not None
    missing = REQUIRED_FIELDS - set(alert.keys())
    assert not missing, f"Missing fields: {missing}"
    print("  PASS  test_all_schema_fields_present")


def test_schema_fields_for_root_login():
    engine = AlertEngine(_cfg())
    alert  = engine.build(_trigger("ROOT_LOGIN", trigger="IMMEDIATE", count=1))
    assert alert is not None
    missing = REQUIRED_FIELDS - set(alert.keys())
    assert not missing, f"Missing fields: {missing}"
    print("  PASS  test_schema_fields_for_root_login")


# ===========================================================================
# Severity routing
# ===========================================================================

def test_root_login_is_critical():
    engine = AlertEngine(_cfg())
    alert  = engine.build(_trigger("ROOT_LOGIN", trigger="IMMEDIATE", count=1))
    assert alert["severity"] == "CRITICAL"
    print("  PASS  test_root_login_is_critical")


def test_ssh_failed_is_high():
    engine = AlertEngine(_cfg())
    alert  = engine.build(_trigger("SSH_FAILED"))
    assert alert["severity"] == "HIGH"
    print("  PASS  test_ssh_failed_is_high")


def test_invalid_user_is_high():
    engine = AlertEngine(_cfg())
    alert  = engine.build(_trigger("INVALID_USER", ts="Jun 14 10:00:00"))
    assert alert["severity"] == "HIGH"
    print("  PASS  test_invalid_user_is_high")


def test_win_logon_failed_is_high():
    engine = AlertEngine(_cfg())
    alert  = engine.build(_trigger("WIN_LOGON_FAILED", platform="windows", ts="Jun 14 11:00:00"))
    assert alert["severity"] == "HIGH"
    print("  PASS  test_win_logon_failed_is_high")


def test_sudo_failure_is_medium():
    engine = AlertEngine(_cfg())
    alert  = engine.build(_trigger("SUDO_FAILURE", trigger="IMMEDIATE", count=1, ts="Jun 14 12:00:00"))
    assert alert["severity"] == "MEDIUM"
    print("  PASS  test_sudo_failure_is_medium")


def test_pam_failure_is_low():
    engine = AlertEngine(_cfg())
    alert  = engine.build(_trigger("PAM_FAILURE", trigger="IMMEDIATE", count=1, ts="Jun 14 13:00:00"))
    assert alert["severity"] == "LOW"
    print("  PASS  test_pam_failure_is_low")


# ===========================================================================
# Alert type mapping
# ===========================================================================

def test_ssh_failed_maps_to_brute_force_ssh():
    engine = AlertEngine(_cfg())
    alert  = engine.build(_trigger("SSH_FAILED"))
    assert alert["alert_type"] == "BRUTE_FORCE_SSH"
    print("  PASS  test_ssh_failed_maps_to_brute_force_ssh")


def test_root_login_maps_to_root_login_detected():
    engine = AlertEngine(_cfg())
    alert  = engine.build(_trigger("ROOT_LOGIN", trigger="IMMEDIATE", count=1))
    assert alert["alert_type"] == "ROOT_LOGIN_DETECTED"
    print("  PASS  test_root_login_maps_to_root_login_detected")


def test_sudo_failure_maps_correctly():
    engine = AlertEngine(_cfg())
    alert  = engine.build(_trigger("SUDO_FAILURE", trigger="IMMEDIATE", count=1, ts="Jun 14 14:00:00"))
    assert alert["alert_type"] == "SUDO_ESCALATION_ATTEMPT"
    print("  PASS  test_sudo_failure_maps_correctly")


# ===========================================================================
# event_hash and timestamp
# ===========================================================================

def test_event_hash_is_sha256_hex():
    engine = AlertEngine(_cfg())
    alert  = engine.build(_trigger())
    h      = alert["event_hash"]
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)
    print("  PASS  test_event_hash_is_sha256_hex")


def test_timestamp_is_iso8601_utc():
    import re
    engine = AlertEngine(_cfg())
    alert  = engine.build(_trigger())
    ts     = alert["timestamp"]
    # Must match YYYY-MM-DDTHH:MM:SSZ
    pattern = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
    assert re.match(pattern, ts), f"Bad timestamp: {ts!r}"
    print("  PASS  test_timestamp_is_iso8601_utc")


def test_attempt_count_preserved():
    engine = AlertEngine(_cfg())
    alert  = engine.build(_trigger(count=7))
    assert alert["attempt_count"] == 7
    print("  PASS  test_attempt_count_preserved")


# ===========================================================================
# Deduplication
# ===========================================================================

def test_duplicate_trigger_returns_none():
    engine   = AlertEngine(_cfg())
    trigger  = _trigger()
    alert1   = engine.build(trigger)
    alert2   = engine.build(trigger)     # identical → same hash
    assert alert1 is not None
    assert alert2 is None, "Duplicate alert should be suppressed"
    print("  PASS  test_duplicate_trigger_returns_none")


def test_different_ips_not_deduplicated():
    engine = AlertEngine(_cfg())
    a1 = engine.build(_trigger(src_ip="1.1.1.1"))
    a2 = engine.build(_trigger(src_ip="2.2.2.2"))
    assert a1 is not None
    assert a2 is not None
    print("  PASS  test_different_ips_not_deduplicated")


def test_different_timestamps_not_deduplicated():
    engine = AlertEngine(_cfg())
    a1 = engine.build(_trigger(ts="Jun 14 09:00:00"))
    a2 = engine.build(_trigger(ts="Jun 14 09:00:01"))   # different timestamp = different hash
    assert a1 is not None
    assert a2 is not None
    print("  PASS  test_different_timestamps_not_deduplicated")


# ===========================================================================
# JSONL backup
# ===========================================================================

def test_jsonl_backup_written():
    tmpdir = tempfile.mkdtemp()
    engine = AlertEngine(_cfg(tmp_dir=tmpdir))
    engine.build(_trigger())
    backup = Path(tmpdir) / "alerts.jsonl"
    assert backup.exists(), "JSONL backup file should be created"
    lines = backup.read_text().strip().splitlines()
    assert len(lines) == 1
    data  = json.loads(lines[0])
    assert "alert_type" in data
    print("  PASS  test_jsonl_backup_written")


def test_jsonl_backup_appends_multiple():
    tmpdir = tempfile.mkdtemp()
    engine = AlertEngine(_cfg(tmp_dir=tmpdir))
    engine.build(_trigger(ts="Jun 14 09:00:00"))
    engine.build(_trigger(ts="Jun 14 09:00:01"))
    engine.build(_trigger(ts="Jun 14 09:00:02"))
    backup = Path(tmpdir) / "alerts.jsonl"
    lines  = backup.read_text().strip().splitlines()
    assert len(lines) == 3, f"Expected 3 backup entries, got {len(lines)}"
    print("  PASS  test_jsonl_backup_appends_multiple")


def test_recent_alerts_reads_backup():
    tmpdir = tempfile.mkdtemp()
    engine = AlertEngine(_cfg(tmp_dir=tmpdir))
    for i in range(5):
        engine.build(_trigger(ts=f"Jun 14 09:00:0{i}"))
    recent = engine.recent_alerts(n=3)
    assert len(recent) == 3
    print("  PASS  test_recent_alerts_reads_backup")


# ===========================================================================
# Console formatting
# ===========================================================================

def test_format_console_non_empty():
    engine = AlertEngine(_cfg())
    alert  = engine.build(_trigger())
    line   = engine.format_console(alert)
    assert isinstance(line, str) and len(line) > 0
    print("  PASS  test_format_console_non_empty")


def test_format_console_contains_severity():
    engine = AlertEngine(_cfg())
    alert  = engine.build(_trigger())
    line   = engine.format_console(alert)
    assert "HIGH" in line
    print("  PASS  test_format_console_contains_severity")


# ===========================================================================
# Runner
# ===========================================================================

if __name__ == "__main__":
    tests = [
        test_all_schema_fields_present,
        test_schema_fields_for_root_login,
        test_root_login_is_critical,
        test_ssh_failed_is_high,
        test_invalid_user_is_high,
        test_win_logon_failed_is_high,
        test_sudo_failure_is_medium,
        test_pam_failure_is_low,
        test_ssh_failed_maps_to_brute_force_ssh,
        test_root_login_maps_to_root_login_detected,
        test_sudo_failure_maps_correctly,
        test_event_hash_is_sha256_hex,
        test_timestamp_is_iso8601_utc,
        test_attempt_count_preserved,
        test_duplicate_trigger_returns_none,
        test_different_ips_not_deduplicated,
        test_different_timestamps_not_deduplicated,
        test_jsonl_backup_written,
        test_jsonl_backup_appends_multiple,
        test_recent_alerts_reads_backup,
        test_format_console_non_empty,
        test_format_console_contains_severity,
    ]
    passed = failed = 0
    print(f"\nRunning {len(tests)} alert_engine tests …\n")
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
    print(f"\n{'─'*45}")
    print(f"  {passed}/{passed+failed} passed")
