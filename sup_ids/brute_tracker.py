"""
sup_ids/brute_tracker.py
========================
PHASE 3 & 4 — ROUTE + DETECT

Thread-safe per-IP sliding-window brute-force tracker with cooldown guard.

How it works
------------
1. Each source IP gets its own deque of event timestamps.
2. On every call to record() the deque is pruned (entries older than
   `window` seconds are evicted) and the count is checked against
   `threshold`.
3. When threshold is reached an alert trigger is returned and a
   per-IP cooldown is started — further hits from the same IP are
   suppressed until the cooldown expires, preventing alert storms.
4. Certain event types (root login, sudo failure, privilege escalation)
   bypass the window entirely and fire immediately.

Public API
----------
    tracker = BruteTracker(config)
    trigger = tracker.process(event)   # returns dict | None
"""

from __future__ import annotations

import time
import threading
from collections import defaultdict, deque
from typing import Optional

from sup_ids.config import SupConfig

# ---------------------------------------------------------------------------
# Event routing tables
# ---------------------------------------------------------------------------

# Events that fire an alert immediately without going through the window
IMMEDIATE_EVENTS: frozenset[str] = frozenset({
    "ROOT_LOGIN",
    "SUDO_FAILURE",
    "WIN_PRIVILEGE_USE",
    "WIN_ACCOUNT_LOCK",
})

# Events counted toward the brute-force threshold
BRUTE_EVENTS: frozenset[str] = frozenset({
    "SSH_FAILED",
    "INVALID_USER",
    "WIN_LOGON_FAILED",
})

# Events we explicitly ignore (e.g. successful non-root logins)
IGNORED_EVENTS: frozenset[str] = frozenset({
    "WIN_LOGON_SUCCESS",
    "PAM_FAILURE",    # low-noise; can change to BRUTE_EVENTS if desired
})


# ---------------------------------------------------------------------------
# BruteTracker
# ---------------------------------------------------------------------------

class BruteTracker:
    """
    Sliding-window brute-force tracker.

    Parameters
    ----------
    config : SupConfig
        Uses config.brute_threshold and config.brute_window.
    """

    def __init__(self, config: SupConfig):
        self.threshold   = config.brute_threshold
        self.window      = config.brute_window      # seconds
        self._lock       = threading.Lock()
        # ip → deque of float monotonic timestamps
        self._windows: dict[str, deque] = defaultdict(deque)
        # ip → float monotonic time when cooldown expires
        self._cooldown:  dict[str, float] = {}

    # ------------------------------------------------------------------
    def process(self, event: dict) -> Optional[dict]:
        """
        Process one parsed event dict from log_parser.

        Returns a trigger dict if an alert should be raised, else None.

        Trigger dict schema
        -------------------
        {
            **event,                     # all original event fields
            "attempt_count": int,        # 1 for immediate; N for threshold
            "trigger":       str,        # "IMMEDIATE" | "THRESHOLD"
        }
        """
        etype = event.get("event_type", "")

        # ── Immediate-fire events (bypass window) ────────────────────
        if etype in IMMEDIATE_EVENTS:
            return {**event, "attempt_count": 1, "trigger": "IMMEDIATE"}

        # ── Ignored events ────────────────────────────────────────────
        if etype in IGNORED_EVENTS or etype not in BRUTE_EVENTS:
            return None

        # ── Sliding-window logic ──────────────────────────────────────
        ip  = event.get("src_ip") or "_no_ip_"
        now = time.monotonic()

        with self._lock:
            # Check cooldown — suppress duplicate alerts
            if ip in self._cooldown and now < self._cooldown[ip]:
                return None

            dq = self._windows[ip]
            dq.append(now)

            # Prune entries outside the window
            cutoff = now - self.window
            while dq and dq[0] < cutoff:
                dq.popleft()

            count = len(dq)

        if count >= self.threshold:
            with self._lock:
                # Set cooldown so this IP doesn't spam alerts
                self._cooldown[ip] = now + self.window
                # Clear the window so the next burst is counted fresh
                self._windows[ip].clear()

            return {
                **event,
                "attempt_count": count,
                "trigger":       "THRESHOLD",
            }

        return None

    # ------------------------------------------------------------------
    def reset_ip(self, ip: str) -> None:
        """Manually clear the window and cooldown for a specific IP."""
        with self._lock:
            self._windows.pop(ip, None)
            self._cooldown.pop(ip, None)

    # ------------------------------------------------------------------
    def stats(self) -> dict:
        """
        Return a snapshot of current window sizes and cooldowns.

        Returns
        -------
        dict with keys:
            "windows"   : { ip: count }
            "cooldowns" : { ip: seconds_remaining }
        """
        now = time.monotonic()
        with self._lock:
            windows   = {ip: len(dq) for ip, dq in self._windows.items() if dq}
            cooldowns = {
                ip: round(exp - now, 1)
                for ip, exp in self._cooldown.items()
                if exp > now
            }
        return {"windows": windows, "cooldowns": cooldowns}

    # ------------------------------------------------------------------
    def active_ips(self) -> list[str]:
        """Return IPs that currently have entries in their sliding window."""
        with self._lock:
            return [ip for ip, dq in self._windows.items() if dq]