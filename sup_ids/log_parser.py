"""
sup_ids/log_parser.py
=====================
PHASE 2 — PARSE

Regex engine that converts raw log lines (Linux) or Windows Event dicts
(Windows) into structured Event dicts consumed by downstream modules.

Supported log sources
---------------------
  Linux  : /var/log/auth.log, /var/log/secure, /var/log/syslog
  Windows: Security Event Log — Event IDs 4625, 4624, 4672, 4740

Event dict schema
-----------------
  {
      "event_type" : str,  # one of the EVENT_TYPES constants below
      "src_ip"     : str,  # attacker IP, or "" if not present
      "username"   : str,  # targeted account, or ""
      "timestamp"  : str,  # raw timestamp string from the log
      "platform"   : str,  # "linux" | "windows"
      "raw"        : str,  # original log line (for debugging)
  }

Non-matching lines return None and are silently dropped.
"""

from __future__ import annotations

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Event type constants
# ---------------------------------------------------------------------------
SSH_FAILED        = "SSH_FAILED"        # Failed SSH password attempt
INVALID_USER      = "INVALID_USER"      # SSH attempt for non-existent user
ROOT_LOGIN        = "ROOT_LOGIN"        # Successful root/admin login
SUDO_FAILURE      = "SUDO_FAILURE"      # sudo authentication failure
PAM_FAILURE       = "PAM_FAILURE"       # Generic PAM authentication failure
WIN_LOGON_FAILED  = "WIN_LOGON_FAILED"  # Windows 4625 failed logon
WIN_LOGON_SUCCESS = "WIN_LOGON_SUCCESS" # Windows 4624 successful logon
WIN_PRIVILEGE_USE = "WIN_PRIVILEGE_USE" # Windows 4672 special privilege
WIN_ACCOUNT_LOCK  = "WIN_ACCOUNT_LOCK"  # Windows 4740 account lockout


# ---------------------------------------------------------------------------
# Linux regex patterns
# ---------------------------------------------------------------------------

# Pattern: timestamp group reused by all Linux regexes
_TS = r"(?P<ts>\w{3}\s{1,2}\d{1,2}\s[\d:]{8})"

# sshd: "Failed password for root from 1.2.3.4 port 22 ssh2"
# sshd: "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
_RE_SSH_FAILED = re.compile(
    _TS
    + r".*sshd\[\d+\]:\s+Failed password for"
    + r"(?:\s+invalid user)?"
    + r"\s+(?P<user>\S+)"
    + r"\s+from\s+(?P<ip>[\d\.a-fA-F:]+)"
    + r"\s+port\s+\d+",
)

# sshd: "Invalid user webmaster from 10.0.0.1 port 44312"
_RE_INVALID_USER = re.compile(
    _TS
    + r".*sshd\[\d+\]:\s+Invalid user\s+(?P<user>\S+)"
    + r"\s+from\s+(?P<ip>[\d\.a-fA-F:]+)",
)

# sshd: "Accepted password for root from 192.168.1.10 port 22 ssh2"
# Catches successful root login — immediate CRITICAL alert
_RE_ROOT_LOGIN = re.compile(
    _TS
    + r".*sshd\[\d+\]:\s+Accepted\s+\w+\s+for\s+(?P<user>root)"
    + r"\s+from\s+(?P<ip>[\d\.a-fA-F:]+)",
)

# sudo: "bob : 3 incorrect password attempts ; TTY=pts/1 ; USER=root ; COMMAND=..."
# sudo: "alice : user NOT in sudoers ; TTY=pts/0 ; ..."
_RE_SUDO_FAILURE = re.compile(
    _TS
    + r".*sudo(?:\[\d+\])?:\s+(?P<user>\S+)\s+:"
    + r".*?(?:incorrect password attempts|NOT in sudoers)",
)

# pam_unix: "authentication failure; logname= uid=0 rhost=10.0.0.5 user=bob"
_RE_PAM_FAILURE = re.compile(
    _TS
    + r".*pam_\w+\(\S+\):\s+authentication failure"
    + r"(?:.*?rhost=(?P<ip>[\d\.a-fA-F:]+))?"
    + r"(?:.*?\s+user=(?P<user>\S+))?",
)

# Ordered list: ROOT_LOGIN must come before SSH_FAILED (both match accepted lines)
_LINUX_PATTERNS: list[tuple[re.Pattern, str]] = [
    (_RE_ROOT_LOGIN,    ROOT_LOGIN),
    (_RE_SSH_FAILED,    SSH_FAILED),
    (_RE_INVALID_USER,  INVALID_USER),
    (_RE_SUDO_FAILURE,  SUDO_FAILURE),
    (_RE_PAM_FAILURE,   PAM_FAILURE),
]

# ---------------------------------------------------------------------------
# Windows Event ID → event_type mapping
# ---------------------------------------------------------------------------
_WIN_EVENT_MAP: dict[int, str] = {
    4625: WIN_LOGON_FAILED,
    4624: WIN_LOGON_SUCCESS,
    4672: WIN_PRIVILEGE_USE,
    4740: WIN_ACCOUNT_LOCK,
}

# IPs that should be treated as "no external IP"
_LOCAL_IPS = {"-", "::1", "127.0.0.1", "0.0.0.0", ""}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_linux_line(line: str) -> Optional[dict]:
    """
    Match *line* against all Linux regex patterns.

    Returns an Event dict on the first match, or None if no pattern matches.
    Non-matching lines are silently dropped (caller can ignore None).

    Parameters
    ----------
    line : str
        A single raw log line (newline will be stripped automatically).

    Returns
    -------
    dict | None
        Structured Event dict, or None if the line is not a monitored event.
    """
    line = line.rstrip("\n\r")
    if not line.strip():
        return None

    for pattern, event_type in _LINUX_PATTERNS:
        m = pattern.search(line)
        if not m:
            continue

        gd = m.groupdict()
        return {
            "event_type": event_type,
            "src_ip":     (gd.get("ip") or "").strip(),
            "username":   (gd.get("user") or "").strip(),
            "timestamp":  (gd.get("ts") or "").strip(),
            "platform":   "linux",
            "raw":        line,
        }

    return None


def parse_windows_event(event: dict) -> Optional[dict]:
    """
    Parse a Windows Security Event Log record.

    The *event* dict is produced by platform_reader.WindowsReader and
    must contain at minimum: event_id, src_ip, username, timestamp, raw.

    Parameters
    ----------
    event : dict
        Raw Windows event dict from platform_reader.

    Returns
    -------
    dict | None
        Structured Event dict, or None if the event_id is not monitored.
    """
    try:
        eid = int(event.get("event_id", 0))
    except (TypeError, ValueError):
        return None

    etype = _WIN_EVENT_MAP.get(eid)
    if not etype:
        return None

    ip = str(event.get("src_ip") or "").strip()
    if ip in _LOCAL_IPS or ip.endswith("-\r\n"):
        ip = ""

    return {
        "event_type": etype,
        "src_ip":     ip,
        "username":   str(event.get("username") or "").strip(),
        "timestamp":  str(event.get("timestamp") or "").strip(),
        "platform":   "windows",
        "raw":        str(event.get("raw") or "")[:512],
    }


def parse_line(line: str) -> Optional[dict]:
    """
    Convenience dispatcher.
    Accepts a raw string (Linux) or JSON-like string — always routes to
    parse_linux_line for plain string input. Use parse_windows_event()
    directly for Windows event dicts.
    """
    return parse_linux_line(line)


# ---------------------------------------------------------------------------
# Standalone self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    samples = [
        # SSH failed
        "Jun 14 08:42:11 lab sshd[1234]: Failed password for root from 192.168.1.47 port 22 ssh2",
        # SSH failed invalid user
        "Jun 14 08:42:12 lab sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 54321 ssh2",
        # Invalid user (no "Failed password" prefix)
        "Jun 14 08:42:15 lab sshd[5678]: Invalid user webmaster from 172.16.0.1 port 22",
        # Root login (CRITICAL)
        "Jun 14 08:43:00 lab sshd[9999]: Accepted password for root from 192.168.1.10 port 22 ssh2",
        # Sudo failure
        "Jun 14 09:01:00 lab sudo[999]: bob : 3 incorrect password attempts ; TTY=pts/1 ; USER=root ; COMMAND=/bin/bash",
        # Sudo not in sudoers
        "Jun 14 09:02:00 lab sudo[1000]: alice : user NOT in sudoers ; TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/vim",
        # PAM failure
        "Jun 14 09:05:00 lab pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=172.16.0.5 user=testuser",
        # Non-matching line
        "Jun 14 09:10:00 lab kernel: Oops: general protection fault",
        # Empty line
        "",
    ]

    print(f"\n{'TYPE':<22} {'IP':<18} {'USER':<14} MATCH")
    print("─" * 70)
    for s in samples:
        result = parse_linux_line(s)
        if result:
            print(
                f"  {result['event_type']:<20} {result['src_ip']:<18} "
                f"{result['username']:<14} ✓"
            )
        else:
            preview = s[:55] + "…" if len(s) > 55 else s
            print(f"  {'(dropped)':<20} {'':18} {'':14} ✗  {preview!r}")