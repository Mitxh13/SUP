"""
sup_ids/platform_reader.py
==========================
PHASE 1 — INPUT

Abstracts OS differences for reading authentication / security logs
in real time. Each reader is a generator that yields entries to the
main pipeline.

  Linux   → tails /var/log/auth.log (and siblings) via poll + inode check
  Windows → reads Security Event Log via win32evtlog (pywin32 required)

Public interface
----------------
    reader = get_reader(config)        # factory — auto-detects OS
    reader.stream()                    # generator of str (Linux) | dict (Windows)
    reader.stop()                      # signal graceful shutdown

Log rotation (Linux)
---------------------
    Detected by comparing the file's inode number between polls.
    On rotation the file is closed and reopened from the beginning.
"""

from __future__ import annotations

import os
import sys
import time
import queue
import threading
from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path

from sup_ids.config import SupConfig


# ===========================================================================
# Abstract base
# ===========================================================================

class BaseReader(ABC):
    """Common interface for all platform readers."""

    def __init__(self, config: SupConfig, verbose: bool = False):
        self.config       = config
        self.verbose      = verbose
        self._stop_event  = threading.Event()

    # ------------------------------------------------------------------
    def stop(self) -> None:
        """Signal the reader to stop at the next poll."""
        self._stop_event.set()

    @property
    def stopped(self) -> bool:
        return self._stop_event.is_set()

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(f"[READER] {msg}", flush=True)

    # ------------------------------------------------------------------
    @abstractmethod
    def stream(self) -> Iterator:
        """Yield log entries indefinitely until stop() is called."""
        ...


# ===========================================================================
# Linux — file tailer
# ===========================================================================

class _FileTailer:
    """
    Tails a single text file and yields new lines as they appear.
    Handles log rotation by checking the file inode on each poll cycle.
    """

    def __init__(
        self,
        path: Path,
        poll_interval: float,
        tail_mode: bool,
        stop_event: threading.Event,
        verbose: bool = False,
    ):
        self.path          = path
        self.poll_interval = poll_interval
        self.tail_mode     = tail_mode
        self._stop         = stop_event
        self.verbose       = verbose

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(f"[TAILER:{self.path.name}] {msg}", flush=True)

    def _wait_for_file(self) -> bool:
        """Block until the file exists or stop is signalled. Returns False if stopped."""
        if not self.path.exists():
            self._vprint(f"Waiting for {self.path} to appear …")
        while not self.path.exists():
            if self._stop.is_set():
                return False
            time.sleep(self.poll_interval)
        return True

    def _open(self):
        """Open the log file and return (file_handle, inode)."""
        fh    = self.path.open("r", errors="replace")
        inode = os.stat(self.path).st_ino
        return fh, inode

    def lines(self) -> Iterator[str]:
        """Yield lines from the file forever, handling rotation."""
        if not self._wait_for_file():
            return

        fh, inode = self._open()
        self._vprint(f"Opened (inode={inode}, tail={self.tail_mode})")

        if self.tail_mode:
            fh.seek(0, 2)   # SEEK_END — skip existing content

        try:
            while not self._stop.is_set():
                line = fh.readline()

                if line:                 # new data available
                    yield line
                    continue

                # ── No new data: poll and check for rotation ─────────
                time.sleep(self.poll_interval)

                try:
                    new_inode = os.stat(self.path).st_ino
                except FileNotFoundError:
                    new_inode = inode   # briefly missing during rotation

                if new_inode != inode:
                    self._vprint("Log rotation detected — reopening file")
                    fh.close()
                    time.sleep(self.poll_interval)
                    if not self._wait_for_file():
                        return
                    fh, inode = self._open()
        finally:
            fh.close()


class LinuxReader(BaseReader):
    """
    PHASE 1 — INPUT (Linux)

    Monitors one or more log files concurrently (one thread per file).
    All lines are merged onto a shared queue and yielded in order to
    the caller via stream().
    """

    _QUEUE_MAX = 20_000

    def __init__(self, config: SupConfig, verbose: bool = False):
        super().__init__(config, verbose)
        self._queue: queue.Queue[str] = queue.Queue(maxsize=self._QUEUE_MAX)
        self._threads: list[threading.Thread] = []

    # ------------------------------------------------------------------
    def _tail_worker(self, path: Path) -> None:
        """Thread target — tails one file and puts lines onto the queue."""
        tailer = _FileTailer(
            path=path,
            poll_interval=self.config.poll_interval,
            tail_mode=self.config.tail_mode,
            stop_event=self._stop_event,
            verbose=self.verbose,
        )
        for line in tailer.lines():
            if self.stopped:
                break
            try:
                self._queue.put_nowait(line)
            except queue.Full:
                pass   # drop under extreme backpressure

    # ------------------------------------------------------------------
    def stream(self) -> Iterator[str]:
        """Yield raw log lines from all monitored files."""
        paths = [Path(p) for p in self.config.log_files]
        if not paths:
            print(
                "[WARN] No log files configured. "
                "Set log_files in sup.toml or pass --log-file.",
                file=sys.stderr,
            )
            return

        # Start one tailer thread per log file
        for path in paths:
            t = threading.Thread(
                target=self._tail_worker,
                args=(path,),
                daemon=True,
                name=f"sup:tail:{path.name}",
            )
            t.start()
            self._threads.append(t)
            self._vprint(f"Tailer started for {path}")

        # Drain the queue until stopped
        while not self.stopped:
            try:
                line = self._queue.get(timeout=0.25)
                yield line
            except queue.Empty:
                continue


# ===========================================================================
# Windows — Security Event Log reader
# ===========================================================================

class WindowsReader(BaseReader):
    """
    PHASE 1 — INPUT (Windows)

    Reads the Windows Security Event Log via pywin32 (win32evtlog).
    Yields structured dicts (not raw strings) to the pipeline.

    Requires: pip install pywin32

    Monitored Event IDs
    -------------------
      4625 — An account failed to log on
      4624 — An account was successfully logged on
      4672 — Special privileges assigned to new logon
      4740 — A user account was locked out
    """

    MONITORED_IDS = {4625, 4624, 4672, 4740}

    def __init__(self, config: SupConfig, verbose: bool = False):
        super().__init__(config, verbose)
        self._check_pywin32()

    # ------------------------------------------------------------------
    @staticmethod
    def _check_pywin32() -> None:
        try:
            import win32evtlog      # noqa: F401
            import win32evtlogutil  # noqa: F401
            import pywintypes       # noqa: F401
        except ImportError:
            raise RuntimeError(
                "pywin32 is required on Windows.\n"
                "  pip install pywin32\n"
                "  python -m pywin32_postinstall -install"
            )

    # ------------------------------------------------------------------
    def stream(self) -> Iterator[dict]:
        """Yield Windows Security event dicts for monitored Event IDs."""
        import win32evtlog
        import win32evtlogutil
        import pywintypes

        LOG_TYPE   = "Security"
        FWD_FLAGS  = (
            win32evtlog.EVENTLOG_FORWARDS_READ
            | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

        hand = win32evtlog.OpenEventLog(None, LOG_TYPE)
        self._vprint("Opened Windows Security Event Log")

        # Skip existing events in tail mode
        if self.config.tail_mode:
            self._vprint("Tail mode: fast-forwarding past existing events …")
            back_flags = (
                win32evtlog.EVENTLOG_BACKWARDS_READ
                | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )
            while True:
                evts = win32evtlog.ReadEventLog(hand, back_flags, 0)
                if not evts:
                    break
            win32evtlog.CloseEventLog(hand)
            hand = win32evtlog.OpenEventLog(None, LOG_TYPE)

        try:
            while not self.stopped:
                try:
                    events = win32evtlog.ReadEventLog(hand, FWD_FLAGS, 0)
                except pywintypes.error:
                    time.sleep(self.config.poll_interval)
                    continue

                if not events:
                    time.sleep(self.config.poll_interval)
                    continue

                for evt in events:
                    if self.stopped:
                        break

                    eid = evt.EventID & 0xFFFF
                    if eid not in self.MONITORED_IDS:
                        continue

                    # Extract message text safely
                    try:
                        msg = win32evtlogutil.SafeFormatMessage(evt, LOG_TYPE)
                    except Exception:
                        msg = ""

                    # Extract IP from formatted message
                    ip = ""
                    for part in (msg or "").splitlines():
                        if any(k in part for k in ("Source Network Address", "Client Address")):
                            candidate = part.split(":")[-1].strip()
                            if candidate and candidate not in {"-", "::1", "127.0.0.1"}:
                                ip = candidate
                                break

                    # Username is typically StringInserts[5] for 4625/4624
                    username = ""
                    if evt.StringInserts and len(evt.StringInserts) > 5:
                        username = str(evt.StringInserts[5]).strip()

                    # Timestamp
                    try:
                        ts = evt.TimeGenerated.Format()
                    except Exception:
                        ts = str(evt.TimeGenerated)

                    yield {
                        "event_id":  eid,
                        "src_ip":    ip,
                        "username":  username,
                        "timestamp": ts,
                        "raw":       (msg or "")[:512],
                    }
        finally:
            win32evtlog.CloseEventLog(hand)
            self._vprint("Event Log handle closed")


# ===========================================================================
# Factory
# ===========================================================================

def get_reader(config: SupConfig, verbose: bool = False) -> BaseReader:
    """
    Return the appropriate reader for the current OS.

      Linux / macOS → LinuxReader
      Windows       → WindowsReader
    """
    if sys.platform == "win32":
        return WindowsReader(config, verbose=verbose)
    return LinuxReader(config, verbose=verbose)


# ===========================================================================
# Standalone smoke-test
# ===========================================================================

if __name__ == "__main__":  # pragma: no cover
    from sup_ids.config import SupConfig

    cfg             = SupConfig()
    cfg.tail_mode   = False     # read existing lines for testing
    cfg.poll_interval = 0.05

    reader = get_reader(cfg, verbose=True)
    print(f"\n[TEST] Reader: {type(reader).__name__}")
    print("[TEST] Streaming up to 10 entries …\n")

    count = 0
    for entry in reader.stream():
        preview = str(entry)[:100]
        print(f"  {count+1:>3}. {preview}")
        count += 1
        if count >= 10:
            reader.stop()
            break

    print(f"\n[TEST] Done — {count} entries read.")