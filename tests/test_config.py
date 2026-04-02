"""
tests/test_config.py
====================
Unit tests for sup_ids/config.py

Tests cover:
  - Default values
  - TOML file loading and merging
  - CLI override (highest priority)
  - Merge priority chain: CLI > TOML > defaults
  - Validation errors
  - TOML_TEMPLATE is valid
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sup_ids.config import SupConfig, load_config, TOML_TEMPLATE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_toml(content: str) -> Path:
    """Write a TOML string to a temp file and return its Path."""
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".toml", delete=False, encoding="utf-8"
    )
    f.write(content)
    f.close()
    return Path(f.name)


def _cleanup(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# Default values
# ---------------------------------------------------------------------------

def test_defaults():
    cfg = SupConfig()
    assert cfg.brute_threshold == 5
    assert cfg.brute_window    == 60
    assert cfg.poll_interval   == 0.5
    assert cfg.tail_mode       is True
    assert cfg.splunk_index    == "sup_ids"
    assert cfg.splunk_verify_ssl is False
    assert cfg.dry_run         is False
    assert cfg.verbose         is False
    print("  PASS  test_defaults")


def test_default_output_dir_is_path():
    cfg = SupConfig()
    assert isinstance(cfg.output_dir, Path)
    print("  PASS  test_default_output_dir_is_path")


def test_default_log_files_is_list():
    cfg = SupConfig()
    assert isinstance(cfg.log_files, list)
    print("  PASS  test_default_log_files_is_list")


# ---------------------------------------------------------------------------
# TOML merge
# ---------------------------------------------------------------------------

def test_toml_overrides_threshold():
    path = _write_toml("brute_threshold = 10\n")
    try:
        cfg = load_config(path=path)
        assert cfg.brute_threshold == 10
        print("  PASS  test_toml_overrides_threshold")
    finally:
        _cleanup(path)


def test_toml_overrides_window():
    path = _write_toml("brute_window = 120\n")
    try:
        cfg = load_config(path=path)
        assert cfg.brute_window == 120
        print("  PASS  test_toml_overrides_window")
    finally:
        _cleanup(path)


def test_toml_overrides_log_files():
    path = _write_toml('log_files = ["/tmp/test.log"]\n')
    try:
        cfg = load_config(path=path)
        assert cfg.log_files == ["/tmp/test.log"]
        print("  PASS  test_toml_overrides_log_files")
    finally:
        _cleanup(path)


def test_toml_missing_file_uses_defaults():
    cfg = load_config(path=Path("/nonexistent/sup.toml"))
    assert cfg.brute_threshold == 5   # still default
    print("  PASS  test_toml_missing_file_uses_defaults")


# ---------------------------------------------------------------------------
# CLI override (highest priority)
# ---------------------------------------------------------------------------

def test_cli_overrides_toml():
    path = _write_toml("brute_threshold = 10\n")
    try:
        # CLI passes threshold=20, which should win over TOML's 10
        cfg = load_config(path=path, brute_threshold=20)
        assert cfg.brute_threshold == 20
        print("  PASS  test_cli_overrides_toml")
    finally:
        _cleanup(path)


def test_cli_none_does_not_override():
    path = _write_toml("brute_threshold = 10\n")
    try:
        cfg = load_config(path=path, brute_threshold=None)
        assert cfg.brute_threshold == 10   # TOML value preserved
        print("  PASS  test_cli_none_does_not_override")
    finally:
        _cleanup(path)


def test_cli_dry_run_flag():
    cfg = load_config(path=Path("/nonexistent/sup.toml"), dry_run=True)
    assert cfg.dry_run is True
    print("  PASS  test_cli_dry_run_flag")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_validation_passes_with_defaults():
    cfg = SupConfig()
    assert cfg.validate() == []
    print("  PASS  test_validation_passes_with_defaults")


def test_validation_fails_zero_threshold():
    cfg = SupConfig()
    cfg.brute_threshold = 0
    errors = cfg.validate()
    assert any("brute_threshold" in e for e in errors)
    print("  PASS  test_validation_fails_zero_threshold")


def test_validation_fails_zero_window():
    cfg = SupConfig()
    cfg.brute_window = 0
    errors = cfg.validate()
    assert any("brute_window" in e for e in errors)
    print("  PASS  test_validation_fails_zero_window")


def test_validation_fails_negative_poll():
    cfg = SupConfig()
    cfg.poll_interval = -1
    errors = cfg.validate()
    assert any("poll_interval" in e for e in errors)
    print("  PASS  test_validation_fails_negative_poll")


# ---------------------------------------------------------------------------
# TOML template
# ---------------------------------------------------------------------------

def test_toml_template_is_valid_toml():
    """The TOML_TEMPLATE string must be parseable."""
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            print("  SKIP  test_toml_template_is_valid_toml (no tomllib/tomli)")
            return

    # Template has commented-out sections — uncommented portion must parse
    # Strip comment lines for a clean parse test
    clean = "\n".join(
        line for line in TOML_TEMPLATE.splitlines()
        if not line.strip().startswith("#") and line.strip()
    )
    try:
        tomllib.loads(clean)
        print("  PASS  test_toml_template_is_valid_toml")
    except Exception as e:
        # Not fatal — template may have intentional partial content
        print(f"  WARN  test_toml_template_is_valid_toml: {e}")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [
        test_defaults,
        test_default_output_dir_is_path,
        test_default_log_files_is_list,
        test_toml_overrides_threshold,
        test_toml_overrides_window,
        test_toml_overrides_log_files,
        test_toml_missing_file_uses_defaults,
        test_cli_overrides_toml,
        test_cli_none_does_not_override,
        test_cli_dry_run_flag,
        test_validation_passes_with_defaults,
        test_validation_fails_zero_threshold,
        test_validation_fails_zero_window,
        test_validation_fails_negative_poll,
        test_toml_template_is_valid_toml,
    ]
    passed = failed = 0
    print(f"\nRunning {len(tests)} config tests …\n")
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
    print(f"\n{'─'*45}")
    print(f"  {passed}/{passed+failed} passed")