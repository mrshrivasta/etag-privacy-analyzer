"""Tests for the ETag Privacy Analyzer's Security Engine and rules.

Rule-level tests use synthetic response dicts (no network calls). The
engine-level tests spin up a REAL local HTTP server (Python's http.server,
on an ephemeral localhost port) with controlled headers and perform a REAL
HTTP request against it via the actual ScanEngine/requests code path —
genuine end-to-end HTTP testing without touching any third-party site.
"""
import sys
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security_engine import ScanEngine
from app.detection_rules import (
    rule_etag_on_sensitive_response,
    rule_inode_based_etag_format,
    rule_etag_with_cookie_missing_vary,
    rule_weak_etag_on_sensitive_response,
    rule_etag_without_cache_control,
    rule_etag_looks_like_long_opaque_token,
)


def resp(url="https://example.com/", headers=None):
    headers = headers or {}
    return {"url": url, "status_code": 200, "headers": headers, "headers_lower": {k.lower(): v for k, v in headers.items()}}


def test_etag_on_sensitive_response_flagged():
    result = rule_etag_on_sensitive_response(resp(url="https://example.com/account", headers={"ETag": '"abc123"'}))
    assert result is not None
    assert result["rule_id"] == "EPA-001"


def test_etag_on_non_sensitive_response_not_flagged():
    result = rule_etag_on_sensitive_response(resp(url="https://example.com/about", headers={"ETag": '"abc123"'}))
    assert result is None


def test_inode_based_etag_flagged():
    result = rule_inode_based_etag_format(resp(headers={"ETag": '"5d8c-1a2b-59f3d8f7c1a80"'}))
    assert result is not None
    assert result["rule_id"] == "EPA-002"


def test_normal_hash_etag_not_flagged_as_inode():
    result = rule_inode_based_etag_format(resp(headers={"ETag": '"9f86d081884c7d659a2feaa0c55ad015"'}))
    assert result is None


def test_etag_with_cookie_missing_vary_flagged_critical():
    result = rule_etag_with_cookie_missing_vary(resp(headers={"ETag": '"abc123"', "Set-Cookie": "sid=x"}))
    assert result is not None
    assert result["severity"] == "critical"


def test_etag_with_cookie_and_vary_cookie_not_flagged():
    result = rule_etag_with_cookie_missing_vary(resp(headers={"ETag": '"abc123"', "Set-Cookie": "sid=x", "Vary": "Cookie"}))
    assert result is None


def test_weak_etag_on_sensitive_response_flagged():
    result = rule_weak_etag_on_sensitive_response(resp(url="https://example.com/dashboard", headers={"ETag": 'W/"abc123"'}))
    assert result is not None
    assert result["rule_id"] == "EPA-004"


def test_strong_etag_on_sensitive_response_not_flagged_as_weak():
    result = rule_weak_etag_on_sensitive_response(resp(url="https://example.com/dashboard", headers={"ETag": '"abc123"'}))
    assert result is None


def test_etag_without_cache_control_flagged():
    result = rule_etag_without_cache_control(resp(headers={"ETag": '"abc123"'}))
    assert result is not None
    assert result["rule_id"] == "EPA-005"


def test_etag_with_cache_control_not_flagged():
    result = rule_etag_without_cache_control(resp(headers={"ETag": '"abc123"', "Cache-Control": "no-store"}))
    assert result is None


def test_long_opaque_token_etag_flagged():
    result = rule_etag_looks_like_long_opaque_token(resp(headers={"ETag": '"9f86d081884c7d659a2feaa0c55ad015d6c15b0f00a08"'}))
    assert result is not None
    assert result["rule_id"] == "EPA-006"


def test_short_etag_not_flagged_as_long_token():
    result = rule_etag_looks_like_long_opaque_token(resp(headers={"ETag": '"a1b2c3"'}))
    assert result is None


def test_no_etag_no_rules_fire():
    r = resp(url="https://example.com/account", headers={"Set-Cookie": "sid=x"})
    assert rule_etag_on_sensitive_response(r) is None
    assert rule_inode_based_etag_format(r) is None
    assert rule_etag_with_cookie_missing_vary(r) is None
    assert rule_weak_etag_on_sensitive_response(r) is None
    assert rule_etag_without_cache_control(r) is None
    assert rule_etag_looks_like_long_opaque_token(r) is None


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Set-Cookie", "sid=testvalue")
        self.send_header("ETag", '"5d8c-1a2b-59f3d8f7c1a80"')
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        pass  # silence test server logging


def _start_test_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def test_real_engine_against_local_test_server():
    """Genuine end-to-end HTTP test: real request, real response, real
    findings — against a local server we control (not a third party)."""
    server, port = _start_test_server()
    try:
        time.sleep(0.2)
        engine = ScanEngine(f"http://127.0.0.1:{port}/", timeout=5)
        result = engine.run()
        assert result["response"]["status_code"] == 200
        rule_ids = {f["rule_id"] for f in result["findings"]}
        # Inode-format ETag + cookie + no Vary -> both EPA-002 and EPA-003 are real, correct findings
        assert "EPA-002" in rule_ids
        assert "EPA-003" in rule_ids
    finally:
        server.shutdown()


def test_engine_handles_unreachable_target_gracefully():
    engine = ScanEngine("http://127.0.0.1:1/", timeout=2)
    result = engine.run()
    assert result["errors_count"] >= 1
    assert any(f["rule_id"] == "EPA-000" for f in result["findings"])
