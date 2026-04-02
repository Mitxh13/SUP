"""
tests/test_log_parser.py
========================
Unit tests for sup_ids/log_parser.py

Tests cover all 6 Linux regex patterns and the Windows event parser.
Sample log lines are taken from real auth.log / syslog output.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sup_ids.log_parser import (
    parse_linux_line,
    parse_windows_event,
    SSH_FAILED,
    INVALID_USER,
    ROOT_LOGIN,
    SUDO_FAILURE,
    PAM_FAILURE,
    WIN_LOGON_FAILED,
    WIN_LOGON_SUCCESS,
    WIN_PRIVILEGE_USE,
    WIN_ACCOUNT_LOCK,
)


# ===========================================================================
# Linux patterns
# ===========================================================================

# ── SSH_FAILED ───────────────────────────────────────────────────────────────

def test_ssh_failed_password_for_root():
    line = "Jun 14 08:42:11 lab sshd[1234]: Failed password for root from 192.168.1.47 port 22 ssh2"
    ev = parse_linux_line(line)
    assert ev is not None
    assert ev["event_type"] == SSH_FAILED
    assert ev["src_ip"]     == "192.168.1.47"
    assert ev["username"]   == "root"
    assert ev["platform"]   == "linux"
    assert ev["raw"]        == line
    print("  PASS  test_ssh_failed_password_for_root")


def test_ssh_failed_password_for_named_user():
    line = "Jun  5 12:00:01 server sshd[5678]: Failed password for alice from 10.0.0.5 port 43210 ssh2"
    ev = parse_linux_line(line)
    assert ev is not None
    assert ev["event_type"] == SSH_FAILED
    assert ev["src_ip"]     == "10.0.0.5"
    assert ev["username"]   == "alice"
    print("  PASS  test_ssh_failed_password_for_named_user")


def test_ssh_failed_invalid_user_prefix():
    line = "Jun 14 08:42:12 lab sshd[1234]: Failed password for invalid user admin from 10.0.0.99 port 54321 ssh2"
    ev = parse_linux_line(line)
    assert ev is not None
    assert ev["event_type"] == SSH_FAILED
    assert ev["src_ip"]     == "10.0.0.99"
    assert ev["username"]   == "admin"
    print("  PASS  test_ssh_failed_invalid_user_prefix")


# ── INVALID_USER ─────────────────────────────────────────────────────────────

def test_invalid_user_basic():
    line = "Jun 14 08:42:15 lab sshd[5678]: Invalid user webmaster from 172.16.0.1 port 22"
    ev = parse_linux_line(line)
    assert ev is not None
    assert ev["event_type"] == INVALID_USER
    assert ev["src_ip"]     == "172.16.0.1"
    assert ev["username"]   == "webmaster"
    print("  PASS  test_invalid_user_basic")


def test_invalid_user_long_username():
    line = "Jun 14 08:42:20 lab sshd[9000]: Invalid user deployment-service-account from 192.168.99.1 port 1234"
    ev = parse_linux_line(line)
    assert ev is not None
    assert ev["event_type"] == INVALID_USER
    assert ev["username"]   == "deployment-service-account"
    print("  PASS  test_invalid_user_long_username")


# ── ROOT_LOGIN ───────────────────────────────────────────────────────────────

def test_root_login_accepted_password():
    line = "Jun 14 08:43:00 lab sshd[9999]: Accepted password for root from 192.168.1.10 port 22 ssh2"
    ev = parse_linux_line(line)
    assert ev is not None
    assert ev["event_type"] == ROOT_LOGIN
    assert ev["username"]   == "root"
    assert ev["src_ip"]     == "192.168.1.10"
    print("  PASS  test_root_login_accepted_password")


def test_root_login_accepted_publickey():
    line = "Jun 14 09:00:00 lab sshd[1111]: Accepted publickey for root from 10.10.10.1 port 55000 ssh2"
    ev = parse_linux_line(line)
    assert ev is not None
    assert ev["event_type"] == ROOT_LOGIN
    print("  PASS  test_root_login_accepted_publickey")


def test_normal_user_login_not_matched_as_root():
    """Accepted login for a non-root user must NOT trigger ROOT_LOGIN."""
    line = "Jun 14 09:00:05 lab sshd[2222]: Accepted password for alice from 10.0.0.1 port 22 ssh2"
    ev = parse_linux_line(line)
    # Either None or some other event type — must not be ROOT_LOGIN
    if ev is not None:
        assert ev["event_type"] != ROOT_LOGIN
    print("  PASS  test_normal_user_login_not_matched_as_root")


# ── SUDO_FAILURE ─────────────────────────────────────────────────────────────

def test_sudo_incorrect_password():
    line = "Jun 14 09:01:00 lab sudo[999]: bob : 3 incorrect password attempts ; TTY=pts/1 ; USER=root ; COMMAND=/bin/bash"
    ev = parse_linux_line(line)
    assert ev is not None
    assert ev["event_type"] == SUDO_FAILURE
    assert ev["username"]   == "bob"
    print("  PASS  test_sudo_incorrect_password")


def test_sudo_not_in_sudoers():
    line = "Jun 14 09:02:00 lab sudo[1000]: alice : user NOT in sudoers ; TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/vim"
    ev = parse_linux_line(line)
    assert ev is not None
    assert ev["event_type"] == SUDO_FAILURE
    assert ev["username"]   == "alice"
    print("  PASS  test_sudo_not_in_sudoers")


# ── PAM_FAILURE ──────────────────────────────────────────────────────────────

def test_pam_auth_failure_with_rhost():
    line = "Jun 14 09:05:00 lab pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=172.16.0.5 user=testuser"
    ev = parse_linux_line(line)
    assert ev is not None
    assert ev["event_type"] == PAM_FAILURE
    assert ev["src_ip"]     == "172.16.0.5"
    print("  PASS  test_pam_auth_failure_with_rhost")


def test_pam_auth_failure_without_rhost():
    line = "Jun 14 09:06:00 lab pam_unix(login:auth): authentication failure; logname= uid=0 user=baduser"
    ev = parse_linux_line(line)
    assert ev is not None
    assert ev["event_type"] == PAM_FAILURE
    print("  PASS  test_pam_auth_failure_without_rhost")


# ── Non-matching / edge cases ────────────────────────────────────────────────

def test_kernel_line_returns_none():
    line = "Jun 14 09:10:00 lab kernel: Oops: general protection fault in somemodule+0x123"
    assert parse_linux_line(line) is None
    print("  PASS  test_kernel_line_returns_none")


def test_empty_string_returns_none():
    assert parse_linux_line("") is None
    print("  PASS  test_empty_string_returns_none")


def test_whitespace_only_returns_none():
    assert parse_linux_line("   \n  ") is None
    print("  PASS  test_whitespace_only_returns_none")


def test_cron_line_returns_none():
    line = "Jun 14 09:15:00 lab CRON[12345]: (root) CMD (/usr/bin/backup.sh)"
    assert parse_linux_line(line) is None
    print("  PASS  test_cron_line_returns_none")


def test_newline_stripped_from_raw():
    line = "Jun 14 08:42:11 lab sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2\n"
    ev = parse_linux_line(line)
    assert ev is not None
    assert not ev["raw"].endswith("\n")
    print("  PASS  test_newline_stripped_from_raw")


# ===========================================================================
# Windows Event Log parser
# ===========================================================================

def test_windows_4625_failed_logon():
    event = {
        "event_id":  4625,
        "src_ip":    "10.10.0.5",
        "username":  "Administrator",
        "timestamp": "2025-06-14 08:42:11",
        "raw":       "An account failed to log on.",
    }
    ev = parse_windows_event(event)
    assert ev is not None
    assert ev["event_type"] == WIN_LOGON_FAILED
    assert ev["src_ip"]     == "10.10.0.5"
    assert ev["username"]   == "Administrator"
    assert ev["platform"]   == "windows"
    print("  PASS  test_windows_4625_failed_logon")


def test_windows_4624_logon_success():
    event = {
        "event_id":  4624,
        "src_ip":    "192.168.0.10",
        "username":  "jdoe",
        "timestamp": "2025-06-14 09:00:00",
        "raw":       "",
    }
    ev = parse_windows_event(event)
    assert ev is not None
    assert ev["event_type"] == WIN_LOGON_SUCCESS
    print("  PASS  test_windows_4624_logon_success")


def test_windows_4672_privilege():
    event = {
        "event_id":  4672,
        "src_ip":    "",
        "username":  "SYSTEM",
        "timestamp": "2025-06-14 09:00:00",
        "raw":       "Special privileges assigned.",
    }
    ev = parse_windows_event(event)
    assert ev is not None
    assert ev["event_type"] == WIN_PRIVILEGE_USE
    print("  PASS  test_windows_4672_privilege")


def test_windows_4740_lockout():
    event = {
        "event_id":  4740,
        "src_ip":    "",
        "username":  "jsmith",
        "timestamp": "2025-06-14 10:00:00",
        "raw":       "A user account was locked out.",
    }
    ev = parse_windows_event(event)
    assert ev is not None
    assert ev["event_type"] == WIN_ACCOUNT_LOCK
    print("  PASS  test_windows_4740_lockout")


def test_windows_unknown_event_id_returns_none():
    event = {"event_id": 9999, "src_ip": "", "username": "", "timestamp": "", "raw": ""}
    assert parse_windows_event(event) is None
    print("  PASS  test_windows_unknown_event_id_returns_none")


def test_windows_loopback_ip_cleared():
    for bad_ip in ("127.0.0.1", "::1", "-", ""):
        event = {
            "event_id":  4625,
            "src_ip":    bad_ip,
            "username":  "bob",
            "timestamp": "2025-06-14 10:00:00",
            "raw":       "",
        }
        ev = parse_windows_event(event)
        assert ev is not None
        assert ev["src_ip"] == "", f"Expected empty src_ip for {bad_ip!r}, got {ev['src_ip']!r}"
    print("  PASS  test_windows_loopback_ip_cleared")


def test_windows_missing_event_id_returns_none():
    ev = parse_windows_event({})
    assert ev is None
    print("  PASS  test_windows_missing_event_id_returns_none")


# ===========================================================================
# Runner
# ===========================================================================

if __name__ == "__main__":
    tests = [
        test_ssh_failed_password_for_root,
        test_ssh_failed_password_for_named_user,
        test_ssh_failed_invalid_user_prefix,
        test_invalid_user_basic,
        test_invalid_user_long_username,
        test_root_login_accepted_password,
        test_root_login_accepted_publickey,
        test_normal_user_login_not_matched_as_root,
        test_sudo_incorrect_password,
        test_sudo_not_in_sudoers,
        test_pam_auth_failure_with_rhost,
        test_pam_auth_failure_without_rhost,
        test_kernel_line_returns_none,
        test_empty_string_returns_none,
        test_whitespace_only_returns_none,
        test_cron_line_returns_none,
        test_newline_stripped_from_raw,
        test_windows_4625_failed_logon,
        test_windows_4624_logon_success,
        test_windows_4672_privilege,
        test_windows_4740_lockout,
        test_windows_unknown_event_id_returns_none,
        test_windows_loopback_ip_cleared,
        test_windows_missing_event_id_returns_none,
    ]
    passed = failed = 0
    print(f"\nRunning {len(tests)} log_parser tests …\n")
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
    print(f"\n{'─'*45}")
    print(f"  {passed}/{passed+failed} passed")