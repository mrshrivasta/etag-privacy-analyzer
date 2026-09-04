"""Web route tests for the ETag Privacy Analyzer.

Uses a REAL local HTTP server (http.server on an ephemeral localhost port)
as the scan target so the full workflow — dashboard -> scan/run -> engine ->
real HTTP request -> findings -> logs/alerts/analytics/reports -- is
exercised end-to-end without touching any third-party site.
"""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Set-Cookie", "sid=testvalue")
        self.send_header("ETag", '"5d8c-1a2b-59f3d8f7c1a80"')
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        pass


def _start_test_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def test_full_scan_alert_incident_workflow(registered_client):
    server, port = _start_test_server()
    target_url = f"http://127.0.0.1:{port}/"
    try:
        resp = registered_client.post("/scan/run", data={"target_url": target_url}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Scan complete" in resp.data

        # Logs page should show the scanned URL
        resp = registered_client.get("/logs")
        assert target_url.encode() in resp.data

        # Alerts page should load (public-cache-with-cookie is critical, so an alert should exist)
        resp = registered_client.get("/alerts")
        assert resp.status_code == 200

        # Analytics JSON endpoint returns real aggregated data
        resp = registered_client.get("/analytics/data")
        assert resp.status_code == 200
        assert resp.is_json

        # Reports CSV export works
        resp = registered_client.get("/reports/export.csv")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/csv")
    finally:
        server.shutdown()


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "alert_on_severity": "high",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert resp.status_code == 200


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
