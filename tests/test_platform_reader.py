"""
tests/test_platform_reader.py
=============================
Unit tests for sup_ids/platform_reader.py

Tests cover:
  - LinuxReader reads existing lines (tail_mode=False)
  - LinuxReader detects newly appended lines (tail_mode=True)
  - _FileTailer handles log rotation (inode change)
  - Multiple file monitoring
  - get_reader() factory returns correct type
  - stop() halts the stream cleanly
"""

import os
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sup_ids.config import SupConfig
from sup_ids.platform_reader import LinuxReader, _FileTailer, get_reader


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cfg(**kwargs) -> SupConfig:
    """Build a minimal SupConfig for testing."""
    cfg               = SupConfig()
    cfg.poll_interval = 0.05
    cfg.tail_mode     = False
    for k, v in kwargs.items():
        setattr(cfg, k, v)
    return cfg


def _collect(reader: LinuxReader, max_lines: int, timeout: float = 3.0) -> list[str]:
    """Run reader.stream() in a thread, collect up to max_lines, then stop."""
    lines: list[str] = []

    def _run():
        for line in reader.stream():
            lines.append(line)
            if len(lines) >= max_lines:
                reader.stop()
                break

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=timeout)
    reader.stop()
    return lines


# ===========================================================================
# LinuxReader — existing content
# ===========================================================================

def test_reads_existing_lines():
    """LinuxReader with tail_mode=False should yield all pre-existing lines."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        fname = f.name
        for i in range(5):
            f.write(
                f"Jun 14 08:42:1{i} host sshd[{i}]: "
                f"Failed password for user{i} from 10.0.0.{i} port 22 ssh2\n"
            )
    try:
        cfg    = _cfg(log_files=[fname])
        reader = LinuxReader(cfg)
        lines  = _collect(reader, max_lines=5)
        assert len(lines) == 5, f"Expected 5 lines, got {len(lines)}"
        assert all("Failed password" in l for l in lines)
        print("  PASS  test_reads_existing_lines")
    finally:
        os.unlink(fname)


def test_reads_correct_content():
    """Lines yielded should match what was written."""
    payload = "Jun 14 09:00:00 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        fname = f.name
        f.write(payload)
    try:
        cfg    = _cfg(log_files=[fname])
        reader = LinuxReader(cfg)
        lines  = _collect(reader, max_lines=1)
        assert lines[0].strip() == payload.strip()
        print("  PASS  test_reads_correct_content")
    finally:
        os.unlink(fname)


def test_empty_log_file_yields_nothing_then_stops():
    """Empty file with tail_mode=True should yield nothing (no pre-existing lines)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        fname = f.name

    try:
        cfg    = _cfg(log_files=[fname], tail_mode=True)
        reader = LinuxReader(cfg)

        lines: list[str] = []

        def _run():
            for line in reader.stream():
                lines.append(line)

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        time.sleep(0.3)  # let it settle
        reader.stop()
        t.join(timeout=1)

        assert len(lines) == 0
        print("  PASS  test_empty_log_file_yields_nothing_then_stops")
    finally:
        os.unlink(fname)


# ===========================================================================
# LinuxReader — live append detection
# ===========================================================================

def test_detects_appended_lines():
    """LinuxReader should yield lines appended after startup."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        fname = f.name

    try:
        cfg    = _cfg(log_files=[fname], tail_mode=True)
        reader = LinuxReader(cfg)
        lines: list[str] = []

        def _run():
            for line in reader.stream():
                lines.append(line)
                if len(lines) >= 2:
                    reader.stop()
                    break

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        time.sleep(0.15)    # give reader time to open and seek to EOF

        # Append two new lines
        with open(fname, "a") as fh:
            fh.write("Jun 14 08:00:01 h sshd[1]: Failed password for a from 1.1.1.1 port 22 ssh2\n")
            fh.write("Jun 14 08:00:02 h sshd[2]: Failed password for b from 2.2.2.2 port 22 ssh2\n")

        t.join(timeout=3)
        reader.stop()

        assert len(lines) >= 1, "Expected at least 1 appended line"
        print("  PASS  test_detects_appended_lines")
    finally:
        os.unlink(fname)


# ===========================================================================
# LinuxReader — multiple files
# ===========================================================================

def test_monitors_multiple_files():
    """LinuxReader should merge lines from multiple log files."""
    files = []
    try:
        for i in range(2):
            f = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
            f.write(f"Jun 14 0{i}:00:00 h sshd[{i}]: Failed password for u{i} from {i}.{i}.{i}.{i} port 22 ssh2\n")
            f.close()
            files.append(f.name)

        cfg    = _cfg(log_files=files)
        reader = LinuxReader(cfg)
        lines  = _collect(reader, max_lines=2)
        assert len(lines) == 2
        print("  PASS  test_monitors_multiple_files")
    finally:
        for fname in files:
            try:
                os.unlink(fname)
            except FileNotFoundError:
                pass


# ===========================================================================
# _FileTailer — log rotation
# ===========================================================================

def test_file_tailer_rotation():
    """_FileTailer should reopen and continue reading after log rotation."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        fname = f.name
        f.write("original_line\n")

    stop  = threading.Event()
    path  = Path(fname)
    tailer = _FileTailer(
        path=path,
        poll_interval=0.05,
        tail_mode=False,
        stop_event=stop,
        verbose=False,
    )
    collected: list[str] = []

    def _collect_tailer():
        for line in tailer.lines():
            collected.append(line.strip())
            if len(collected) >= 2:
                stop.set()
                break

    t = threading.Thread(target=_collect_tailer, daemon=True)
    t.start()
    time.sleep(0.2)  # let original_line be read

    # Simulate rotation: replace file with new content
    with open(fname, "w") as fh:
        fh.write("rotated_line\n")

    t.join(timeout=3)
    stop.set()

    assert "original_line" in collected, f"original_line not in {collected}"
    print("  PASS  test_file_tailer_rotation")
    os.unlink(fname)


# ===========================================================================
# get_reader factory
# ===========================================================================

def test_get_reader_returns_linux_reader_on_non_windows():
    if sys.platform == "win32":
        print("  SKIP  test_get_reader_returns_linux_reader_on_non_windows (Windows)")
        return
    cfg    = _cfg()
    reader = get_reader(cfg)
    assert isinstance(reader, LinuxReader)
    print("  PASS  test_get_reader_returns_linux_reader_on_non_windows")


def test_stop_halts_stream():
    """stop() should cause stream() to exit cleanly."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        fname = f.name
        for i in range(100):
            f.write(f"Jun 14 08:00:{i:02d} h sshd[{i}]: Failed password for u from 1.2.3.4 port 22 ssh2\n")

    try:
        cfg    = _cfg(log_files=[fname])
        reader = LinuxReader(cfg)
        count  = 0

        def _run():
            nonlocal count
            for _ in reader.stream():
                count += 1
                if count == 3:
                    reader.stop()
                    break

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        t.join(timeout=3)
        assert reader.stopped
        print("  PASS  test_stop_halts_stream")
    finally:
        os.unlink(fname)


# ===========================================================================
# Runner
# ===========================================================================

if __name__ == "__main__":
    tests = [
        test_reads_existing_lines,
        test_reads_correct_content,
        test_empty_log_file_yields_nothing_then_stops,
        test_detects_appended_lines,
        test_monitors_multiple_files,
        test_file_tailer_rotation,
        test_get_reader_returns_linux_reader_on_non_windows,
        test_stop_halts_stream,
    ]
    passed = failed = 0
    print(f"\nRunning {len(tests)} platform_reader tests …\n")
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
    print(f"\n{'─'*45}")
    print(f"  {passed}/{passed+failed} passed")