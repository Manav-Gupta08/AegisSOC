"""Web UI tests. Cases and reports are SYNTHETIC fixtures in a temporary repository copy."""
import http.client
import json
import shutil
import threading
from pathlib import Path

import pytest

from aegissoc import cases, web
from aegissoc.cases import record

ROOT = Path(__file__).resolve().parents[2]
ALERT = {"alert_id": "a1", "index": "wazuh-alerts-4.x-2026.10.13", "timestamp": "2026-10-13T11:00:37.012+0000",
         "rule_id": "100200", "rule_level": 10, "agent": "lab-linux",
         "rule_description": "sudoers changed by <script>alert(1)</script>"}


@pytest.fixture
def repo(tmp_path):
    for name in ("detections", "scenarios", "playbooks"):
        shutil.copytree(ROOT / name, tmp_path / name)
    runtime = tmp_path / "reports" / "runtime"
    runtime.mkdir(parents=True)
    (runtime / "health-20261019T100000.json").write_text(json.dumps({
        "generated_at": "2026-10-19T10:00:00+00:00", "overall": "WARNING",
        "checks": [{"name": "agents", "status": "WARNING", "detail": "agent <b>x</b> disconnected"}]}))
    (runtime / "health-broken.json").write_text("{not json")
    store = cases.CaseStore(tmp_path)
    c = cases.new_case("CASE-20261013-001", "Injected <img src=x onerror=alert(1)>", "high", "alice")
    record(c, "alice", "transition", {"to": "triage"})
    record(c, "alice", "add_alert", {"alert": ALERT})
    record(c, "alice", "note", {"text": "\x1b[2J<script>steal()</script>"})
    store.save(c, None)
    tampered = cases.new_case("CASE-20261013-002", "Tampered case", "low", "alice")
    store.save(tampered, None)
    path = store.path("CASE-20261013-002")
    path.write_text(path.read_text().replace('"severity": "low"', '"severity": "critical"'))
    return tmp_path


@pytest.fixture
def site(repo):
    return web.Site(repo, "https://127.0.0.1:5601")


def test_every_page_renders_and_escapes_untrusted_text(site):
    for path, (title, render) in site.routes().items():
        html = web.page(title, render())
        assert "<script>" not in html and "<img" not in html and "<b>" not in html, path
    case_html = web.page("case", site.case("CASE-20261013-001"))
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in case_html and "<script>" not in case_html


def test_overview_reports_health_cases_and_unreadable_files(site):
    html = site.overview()
    assert "WARNING" in html and "health-broken.json" in html
    assert "Wazuh dashboard" in html


def test_tampered_case_is_flagged_not_rendered(site):
    listing = site.case_list()
    assert "CASE-20261013-002" in listing and "FAILED" in listing and "failed integrity verification" in listing
    assert "failed integrity verification" in site.case("CASE-20261013-002")


def test_missing_health_report_is_not_presented_as_healthy(tmp_path):
    for name in ("detections", "scenarios", "playbooks"):
        shutil.copytree(ROOT / name, tmp_path / name)
    html = web.Site(tmp_path, "https://127.0.0.1:5601").overview()
    assert "No health report" in html and "says nothing" in html


@pytest.fixture
def server(repo, capsys):
    srv, url = web.create_server(repo, "https://127.0.0.1:5601", port=0)
    thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    yield srv, url.split("token=", 1)[1]
    srv.shutdown()
    srv.server_close()


def request(srv, method="GET", path="/", headers=None, host=None):
    conn = http.client.HTTPConnection(*srv.server_address, timeout=5)
    conn.putrequest(method, path, skip_host=host is not None)
    if host is not None:
        conn.putheader("Host", host)
    for k, v in (headers or {}).items():
        conn.putheader(k, v)
    conn.endheaders()
    resp = conn.getresponse()
    body = resp.read().decode()
    conn.close()
    return resp, body


def test_server_listens_on_loopback_only(server):
    srv, _ = server
    assert srv.server_address[0] == "127.0.0.1"


def test_requests_without_valid_token_are_refused(server):
    srv, _ = server
    assert request(srv)[0].status == 401
    assert request(srv, path="/?token=wrong")[0].status == 401
    assert request(srv, headers={"Cookie": f"{web.COOKIE}=wrong"})[0].status == 401


def test_token_login_sets_strict_cookie_and_serves_pages(server, capsys):
    srv, token = server
    resp, _ = request(srv, path=f"/cases?token={token}")
    cookie = resp.getheader("Set-Cookie")
    assert resp.status == 303 and resp.getheader("Location") == "/"
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    auth = {"Cookie": f"{web.COOKIE}={token}"}
    resp, body = request(srv, path="/cases/CASE-20261013-001", headers=auth)
    assert resp.status == 200 and "&lt;img" in body
    assert "default-src 'none'" in resp.getheader("Content-Security-Policy")
    assert resp.getheader("X-Content-Type-Options") == "nosniff" and resp.getheader("Cache-Control") == "no-store"
    assert request(srv, path="/style.css", headers=auth)[0].getheader("Content-Type").startswith("text/css")
    assert request(srv, path="/cases/../etc/passwd", headers=auth)[0].status == 404
    assert token not in capsys.readouterr().err, "the token must never be logged"


def test_dns_rebinding_host_is_refused(server):
    srv, token = server
    resp, _ = request(srv, headers={"Cookie": f"{web.COOKIE}={token}"}, host="attacker.example:8765")
    assert resp.status == 421


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_ui_is_read_only(server, method):
    srv, token = server
    resp, _ = request(srv, method=method, headers={"Cookie": f"{web.COOKIE}={token}"})
    assert resp.status == 405 and resp.getheader("Allow") == "GET, HEAD"
