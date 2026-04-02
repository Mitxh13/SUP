"""
sup_ids/splunk_forwarder.py
===========================
PHASE 6 — FORWARD

Sends alert dicts to Splunk via the HTTP Event Collector (HEC).
Features:
  • Bearer token authentication
  • Automatic retry with exponential backoff (3 attempts)
  • Every alert always written to local JSONL backup regardless of HEC status
  • Dry-run mode — skips HTTP POST, prints locally only
  • Connection pooling via requests.Session

Public API
----------
    fwd = SplunkForwarder(hec_url, hec_token, ...)
    ok  = fwd.send(alert_dict)      # returns bool
    ok  = fwd.test_connection()     # sends synthetic test event
    fwd.close()                     # release Session
"""

from __future__ import annotations

import json
import sys
import time
from typing import Optional

import requests
from requests.exceptions import RequestException


class SplunkForwarder:
    """
    Forwards alert dicts to Splunk HEC.

    Parameters
    ----------
    hec_url    : str   — base URL, e.g. "http://localhost:8088"
    hec_token  : str   — Splunk HEC token (Bearer auth)
    index      : str   — target Splunk index name
    verify_ssl : bool  — verify TLS certificate (set True in production)
    dry_run    : bool  — skip HTTP POST; print locally only
    verbose    : bool  — log forwarding details to stdout
    """

    MAX_RETRIES   = 3
    BACKOFF_BASE  = 2.0   # seconds; doubled on each retry: 2s, 4s, 8s

    # HTTP status codes that are permanent failures — no point retrying
    PERMANENT_FAIL_CODES = {400, 401, 403}

    def __init__(
        self,
        hec_url:    str,
        hec_token:  str,
        index:      str  = "sup_ids",
        verify_ssl: bool = False,
        dry_run:    bool = False,
        verbose:    bool = False,
    ):
        self.endpoint  = hec_url.rstrip("/") + "/services/collector/event"
        self.index     = index
        self.dry_run   = dry_run
        self.verbose   = verbose

        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Splunk {hec_token}",
            "Content-Type":  "application/json",
        })
        self._session.verify = verify_ssl

    # ------------------------------------------------------------------
    def send(self, alert: dict) -> bool:
        """
        Forward a single alert dict to Splunk HEC.

        In dry_run mode the HTTP POST is skipped and True is returned.

        Parameters
        ----------
        alert : dict
            A fully-built alert payload from AlertEngine.build().

        Returns
        -------
        bool
            True on success (HTTP 200) or dry-run.
            False on permanent HTTP failure or exhausted retries.
        """
        payload = {
            "index":      self.index,
            "sourcetype": "sup:alert",
            "event":      alert,
        }
        body = json.dumps(payload)

        if self.dry_run:
            if self.verbose:
                print(f"[HEC][DRY-RUN] {body[:160]}", flush=True)
            return True

        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                resp = self._session.post(self.endpoint, data=body, timeout=5)

                if resp.status_code == 200:
                    if self.verbose:
                        print("[HEC] ✓ Forwarded (HTTP 200)", flush=True)
                    return True

                print(
                    f"[HEC] HTTP {resp.status_code}: {resp.text[:200]}",
                    file=sys.stderr,
                )

                # Permanent failures — do not retry
                if resp.status_code in self.PERMANENT_FAIL_CODES:
                    return False

            except RequestException as exc:
                print(
                    f"[HEC] Attempt {attempt}/{self.MAX_RETRIES} failed: {exc}",
                    file=sys.stderr,
                )

            if attempt < self.MAX_RETRIES:
                wait = self.BACKOFF_BASE ** attempt   # 2s, 4s, 8s
                time.sleep(wait)

        print("[HEC] ✗ All retries exhausted — alert not forwarded.", file=sys.stderr)
        return False

    # ------------------------------------------------------------------
    def test_connection(self) -> bool:
        """
        Send a synthetic test event to verify HEC connectivity.

        Prints a pass/fail result to stdout.
        Returns True if Splunk responds with HTTP 200.
        """
        test_event = {
            "index":      self.index,
            "sourcetype": "sup:alert",
            "event": {
                "alert_type": "HEC_TEST",
                "severity":   "LOW",
                "message":    "SUP IDS HEC connectivity test — please ignore",
            },
        }
        print(f"[HEC] Testing connection to {self.endpoint} …")
        try:
            resp = self._session.post(
                self.endpoint,
                data=json.dumps(test_event),
                timeout=5,
            )
            if resp.status_code == 200:
                print("[HEC] ✓ Connection OK — HTTP 200")
                return True
            else:
                print(f"[HEC] ✗ Failed — HTTP {resp.status_code}: {resp.text[:300]}")
                return False
        except RequestException as exc:
            print(f"[HEC] ✗ Connection error: {exc}")
            return False

    # ------------------------------------------------------------------
    def close(self) -> None:
        """Release the underlying HTTP session."""
        self._session.close()

    # ------------------------------------------------------------------
    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()