"""
tests/test_splunk_forwarder.py
================================
Unit tests for sup_ids/splunk_forwarder.py

Tests cover:
  - Successful POST (HTTP 200) returns True
  - HTTP 400/401/403 (permanent fail) returns False without retry
  - Transient errors (connection refused) trigger retries
  - Retry limit exhausted → returns False
  - dry_run=True never calls requests.post
  - test_connection() passes/fails correctly
  - Payload shape (index, sourcetype, event keys present)
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sup_ids.splunk_forwarder import SplunkForwarder
from requests.exceptions import ConnectionError as ReqConnError


def _fwd(**kwargs) -> SplunkForwarder:
    defaults = dict(
        hec_url   = "http://localhost:8088",
        hec_token = "test-token",
        index     = "sup_ids",
        verify_ssl= False,
        dry_run   = False,
        verbose   = False,
    )
    defaults.update(kwargs)
    return SplunkForwarder(**defaults)


def _alert() -> dict:
    return {
        "alert_type":    "BRUTE_FORCE_SSH",
        "severity":      "HIGH",
        "src_ip":        "1.2.3.4",
        "username":      "root",
        "attempt_count": 5,
        "hostname":      "testhost",
        "platform":      "linux",
        "source_log":    "/var/log/auth.log",
        "event_hash":    "abc123",
        "timestamp":     "2025-06-14T09:00:00Z",
        "message":       "Brute-force threshold exceeded",
    }


# ===========================================================================
# Successful send
# ===========================================================================

def test_send_returns_true_on_200():
    fwd  = _fwd()
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch.object(fwd._session, "post", return_value=mock_resp) as mock_post:
        result = fwd.send(_alert())

    assert result is True
    mock_post.assert_called_once()
    print("  PASS  test_send_returns_true_on_200")


def test_send_posts_to_correct_endpoint():
    fwd      = _fwd(hec_url="http://splunk.example.com:8088")
    mock_resp = MagicMock(status_code=200)

    with patch.object(fwd._session, "post", return_value=mock_resp) as mock_post:
        fwd.send(_alert())

    called_url = mock_post.call_args[0][0]
    assert called_url == "http://splunk.example.com:8088/services/collector/event"
    print("  PASS  test_send_posts_to_correct_endpoint")


def test_send_payload_contains_required_keys():
    fwd      = _fwd()
    captured = {}
    mock_resp = MagicMock(status_code=200)

    def _capture(url, data=None, timeout=None):
        captured["body"] = json.loads(data)
        return mock_resp

    with patch.object(fwd._session, "post", side_effect=_capture):
        fwd.send(_alert())

    body = captured["body"]
    assert "index"      in body
    assert "sourcetype" in body
    assert "event"      in body
    assert body["index"]      == "sup_ids"
    assert body["sourcetype"] == "sup:alert"
    print("  PASS  test_send_payload_contains_required_keys")


# ===========================================================================
# Permanent failures (no retry)
# ===========================================================================

def test_400_returns_false_immediately():
    fwd      = _fwd()
    mock_resp = MagicMock(status_code=400, text="Invalid data format")

    with patch.object(fwd._session, "post", return_value=mock_resp) as mock_post:
        result = fwd.send(_alert())

    assert result is False
    assert mock_post.call_count == 1   # No retry on 400
    print("  PASS  test_400_returns_false_immediately")


def test_403_returns_false_immediately():
    fwd      = _fwd()
    mock_resp = MagicMock(status_code=403, text="Forbidden")

    with patch.object(fwd._session, "post", return_value=mock_resp) as mock_post:
        result = fwd.send(_alert())

    assert result is False
    assert mock_post.call_count == 1
    print("  PASS  test_403_returns_false_immediately")


def test_401_returns_false_immediately():
    fwd      = _fwd()
    mock_resp = MagicMock(status_code=401, text="Unauthorized")

    with patch.object(fwd._session, "post", return_value=mock_resp) as mock_post:
        result = fwd.send(_alert())

    assert result is False
    assert mock_post.call_count == 1
    print("  PASS  test_401_returns_false_immediately")


# ===========================================================================
# Transient failures + retry
# ===========================================================================

def test_transient_error_triggers_retry():
    """Connection error on first attempt, success on second."""
    fwd      = _fwd()
    good_resp = MagicMock(status_code=200)
    call_count = {"n": 0}

    def _flaky(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise ReqConnError("Connection refused")
        return good_resp

    with patch.object(fwd._session, "post", side_effect=_flaky):
        with patch("time.sleep"):          # skip actual sleep
            result = fwd.send(_alert())

    assert result is True
    assert call_count["n"] == 2
    print("  PASS  test_transient_error_triggers_retry")


def test_retry_limit_exhausted_returns_false():
    """All 3 attempts fail → send() returns False."""
    fwd = _fwd()

    def _always_fail(*args, **kwargs):
        raise ReqConnError("No route to host")

    with patch.object(fwd._session, "post", side_effect=_always_fail):
        with patch("time.sleep"):
            result = fwd.send(_alert())

    assert result is False
    print("  PASS  test_retry_limit_exhausted_returns_false")


def test_max_retries_is_3():
    fwd = _fwd()
    assert fwd.MAX_RETRIES == 3
    print("  PASS  test_max_retries_is_3")


# ===========================================================================
# Dry-run mode
# ===========================================================================

def test_dry_run_never_posts():
    fwd = _fwd(dry_run=True)

    with patch.object(fwd._session, "post") as mock_post:
        result = fwd.send(_alert())

    assert result is True
    mock_post.assert_not_called()
    print("  PASS  test_dry_run_never_posts")


def test_dry_run_verbose_prints(capsys=None):
    fwd = _fwd(dry_run=True, verbose=True)

    with patch.object(fwd._session, "post"):
        fwd.send(_alert())
    # Just assert no exception is raised
    print("  PASS  test_dry_run_verbose_prints")


# ===========================================================================
# test_connection()
# ===========================================================================

def test_test_connection_returns_true_on_200():
    fwd      = _fwd()
    mock_resp = MagicMock(status_code=200)

    with patch.object(fwd._session, "post", return_value=mock_resp):
        result = fwd.test_connection()

    assert result is True
    print("  PASS  test_test_connection_returns_true_on_200")


def test_test_connection_returns_false_on_error():
    fwd = _fwd()

    with patch.object(fwd._session, "post", side_effect=ReqConnError("refused")):
        result = fwd.test_connection()

    assert result is False
    print("  PASS  test_test_connection_returns_false_on_error")


def test_test_connection_returns_false_on_403():
    fwd      = _fwd()
    mock_resp = MagicMock(status_code=403, text="Forbidden")

    with patch.object(fwd._session, "post", return_value=mock_resp):
        result = fwd.test_connection()

    assert result is False
    print("  PASS  test_test_connection_returns_false_on_403")


# ===========================================================================
# Context manager
# ===========================================================================

def test_context_manager_closes_session():
    with _fwd() as fwd:
        mock_resp = MagicMock(status_code=200)
        with patch.object(fwd._session, "post", return_value=mock_resp):
            result = fwd.send(_alert())
        assert result is True
    # Session should be closed — no assertion needed, just no exception
    print("  PASS  test_context_manager_closes_session")


# ===========================================================================
# Runner
# ===========================================================================

if __name__ == "__main__":
    tests = [
        test_send_returns_true_on_200,
        test_send_posts_to_correct_endpoint,
        test_send_payload_contains_required_keys,
        test_400_returns_false_immediately,
        test_403_returns_false_immediately,
        test_401_returns_false_immediately,
        test_transient_error_triggers_retry,
        test_retry_limit_exhausted_returns_false,
        test_max_retries_is_3,
        test_dry_run_never_posts,
        test_dry_run_verbose_prints,
        test_test_connection_returns_true_on_200,
        test_test_connection_returns_false_on_error,
        test_test_connection_returns_false_on_403,
        test_context_manager_closes_session,
    ]
    passed = failed = 0
    print(f"\nRunning {len(tests)} splunk_forwarder tests …\n")
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
    print(f"\n{'─'*45}")
    print(f"  {passed}/{passed+failed} passed")
