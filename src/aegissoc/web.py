"""Read-only local web UI over AegisSOC files: health reports, detections, scenario results, coverage, cases,
playbooks, and audit history.

It never contacts the stack and never reads credentials. Alerts are investigated in the Wazuh dashboard.
"""
from __future__ import annotations

import hmac
import html
import json
import re
import secrets
import sys
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import parse_qs, urlsplit

from . import cases, coverage, detections, metrics, playbooks, reporting, scenarios

LISTEN_HOST = "127.0.0.1"
COOKIE = "aegis_ui"
CASE_PATH = re.compile(r"^/cases/(CASE-\d{8}-\d{3})$")
SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'none'; style-src 'self'; img-src 'none'; frame-ancestors 'none'; "
                                "base-uri 'none'; form-action 'none'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
CSS = """
body { font: 14px/1.45 system-ui, sans-serif; margin: 0; color: #1d2329; background: #f6f7f9; }
nav { background: #1d2329; padding: 0 16px; }
nav a { color: #d8dee4; display: inline-block; padding: 10px 12px; text-decoration: none; }
nav a:hover { color: #fff; background: #2f3740; }
main { padding: 16px 24px; max-width: 1400px; }
h1 { font-size: 22px; margin: 8px 0 16px; } h2 { font-size: 17px; margin: 24px 0 8px; }
table { border-collapse: collapse; width: 100%; background: #fff; margin-bottom: 12px; }
th, td { border: 1px solid #d5d9de; padding: 5px 8px; text-align: left; vertical-align: top; }
th { background: #eceff2; }
code { font: 12px ui-monospace, monospace; }
.badge { padding: 1px 7px; border-radius: 9px; font-size: 12px; font-weight: 600; white-space: nowrap; }
.ok { background: #d5f2dc; color: #14532d; } .warn { background: #fdf0c4; color: #713f12; }
.bad { background: #fbd5d5; color: #7f1d1d; } .muted { background: #e5e7eb; color: #374151; }
.note { background: #fff; border-left: 4px solid #8a94a0; padding: 8px 12px; margin: 8px 0 16px; }
.error { border-left-color: #b91c1c; }
"""
NAV = [("/", "Overview"), ("/health", "System health"), ("/detections", "Detections"), ("/validation", "Validation"),
       ("/coverage", "Coverage"), ("/cases", "Cases"), ("/playbooks", "Playbooks"), ("/audit", "Audit log")]
_BADGE = {
    "PASS": "ok", "PASSED": "ok", "VERIFIED": "ok", "simulated": "ok", "tested": "ok", "closed": "ok",
    "WARNING": "warn", "NOT_VERIFIED": "warn", "INCONCLUSIVE": "warn", "TIMED_OUT": "warn", "proposed": "warn",
    "approved": "warn", "experimental": "warn", "FAIL": "bad", "FAILED": "bad", "CLEANUP_REQUIRED": "bad",
}


class Html(str):
    """Markup produced by this module. Every other value is escaped before it reaches a page."""


def e(value: Any) -> Html:
    return value if isinstance(value, Html) else Html(html.escape(str(value), quote=True))


def join(parts: Iterable[Any]) -> Html:
    return Html("".join(e(p) for p in parts))


def tag(name: str, content: Any = "", **attrs: str) -> Html:
    rendered = "".join(f' {k.rstrip("_")}="{html.escape(v, quote=True)}"' for k, v in attrs.items())
    return Html(f"<{name}{rendered}>{e(content)}</{name}>")


def badge(status: Any) -> Html:
    return tag("span", status, class_="badge " + _BADGE.get(str(status), "muted"))


def note(text: Any, error: bool = False) -> Html:
    return tag("p", text, class_="note error" if error else "note")


def table(headers: list[str], rows: Iterable[Iterable[Any]], empty: str = "none") -> Html:
    body = join(tag("tr", join(tag("td", c) for c in row)) for row in rows)
    if not body:
        body = tag("tr", tag("td", empty, colspan=str(len(headers))))
    return tag("table", join([tag("thead", tag("tr", join(tag("th", h) for h in headers))), tag("tbody", body)]))


def fmt(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, (list, tuple)):
        return ", ".join(map(str, value)) or "-"
    return str(value)


def page(title: str, body: Html) -> str:
    head = join([Html('<meta charset="utf-8">'), tag("title", f"AegisSOC: {title}"),
                 Html('<link rel="stylesheet" href="/style.css">')])
    nav = tag("nav", join(tag("a", label, href=href) for href, label in NAV))
    return "<!doctype html>\n" + tag("html", join([tag("head", head), tag("body", join([nav, tag("main", join([
        tag("h1", title), body]))]))]), lang="en")


class Site:
    """Renders pages from files under the repository root. Stateless, so one instance serves all threads."""

    def __init__(self, root: Path, dashboard_url: str) -> None:
        self.root = root
        self.dashboard_url = dashboard_url
        self.store = cases.CaseStore(root)

    def _reports(self, pattern: str, include_examples: bool = True) -> tuple[list[tuple[str, dict[str, Any]]], list[str]]:
        """(source, report) oldest first, de-duplicated by generated_at; plus names of unreadable files."""
        folders = [("lab", self.root / "reports" / "runtime")]
        if include_examples:
            folders.append(("committed example", self.root / "reports" / "examples"))
        seen: dict[str, tuple[str, dict[str, Any]]] = {}
        unreadable: list[str] = []
        for source, folder in folders:
            for path in sorted(folder.glob(pattern)) if folder.is_dir() else []:
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    unreadable.append(path.name)
                    continue
                seen.setdefault(str(data.get("generated_at", path.name)), (source, data))
        return [seen[k] for k in sorted(seen)], unreadable

    def _cases(self) -> list[tuple[str, dict[str, Any] | None, str]]:
        """(case_id, verified case or None, problem) for every case file."""
        out = []
        for path in sorted(self.store.dir.glob("CASE-*.json")) if self.store.dir.is_dir() else []:
            try:
                out.append((path.stem, self.store.load(path.stem), ""))
            except (cases.CaseError, OSError, ValueError) as exc:
                out.append((path.stem, None, str(exc)))
        return out

    def overview(self) -> Html:
        parts = [note(f"Read-only view of AegisSOC files. Alerts are investigated in the Wazuh dashboard "
                      f"({self.dashboard_url}). No data on this page is synthetic; committed examples are labelled.")]
        health, bad = self._reports("health-*.json", include_examples=False)
        parts.append(tag("h2", "System health"))
        if health:
            _, latest = health[-1]
            failing = [f"{c['name']}: {c['status']}" for c in latest.get("checks", []) if c.get("status") != "PASS"]
            parts.append(table(["Latest report", "Overall", "Checks not passing"],
                               [[latest.get("generated_at"), badge(latest.get("overall")), fmt(failing)]]))
        else:
            parts.append(note("No health report yet (run `aegis health`). A missing report says nothing about the "
                              "stack's state.", error=True))
        reports, bad_s = self._reports("*scenarios*.json")
        s = metrics.scenario_metrics([r for _, r in reports])
        parts += [tag("h2", "Detection validation"), table(
            ["Scenarios known", "Executed (latest run each)", "Latest pass rate", "Failures", "Regressions"],
            [[s["scenarios_known"], s["latest_executed"], fmt(s["latest_pass_rate"]), fmt(s["latest_failures"]),
              fmt(s["regressions"])]])]
        loaded = self._cases()
        c = metrics.case_metrics([case for _, case, _ in loaded if case])
        pending = sum(1 for _, case, _ in loaded if case for a in case.get("response_actions", [])
                      if a["state"] in cases.PENDING_ACTION_STATES)
        parts += [tag("h2", "Cases"), table(
            ["Cases", "Open", "Closed", "Failed integrity check", "Pending response actions"],
            [[c["cases"], c["open"], c["closed"], sum(1 for _, case, _ in loaded if case is None), pending]])]
        if bad or bad_s:
            parts.append(note(f"Unreadable report files skipped: {fmt(bad + bad_s)}", error=True))
        return join(parts)

    def health(self) -> Html:
        reports, bad = self._reports("health-*.json", include_examples=False)
        if not reports:
            return note("No health report yet (run `aegis health`).", error=True)
        _, latest = reports[-1]
        parts = [tag("p", join(["Latest report ", latest.get("generated_at", ""), ": ", badge(latest.get("overall"))])),
                 table(["Check", "Status", "Detail"],
                       [[c.get("name"), badge(c.get("status")), c.get("detail")] for c in latest.get("checks", [])])]
        a = metrics.availability_metrics([r for _, r in reports])
        parts += [tag("h2", "History"),
                  tag("p", f"Agents all active in {fmt(a['agents_all_active_ratio'])} of {a['health_samples']} "
                           f"snapshots. Snapshots are taken only when `aegis health` runs; this is not an availability SLA."),
                  table(["Generated", "Overall", "Checks not passing"],
                        [[r.get("generated_at"), badge(r.get("overall")),
                          fmt([c["name"] for c in r.get("checks", []) if c.get("status") != "PASS"])]
                         for _, r in reversed(reports)])]
        if bad:
            parts.append(note(f"Unreadable report files skipped: {fmt(bad)}", error=True))
        return join(parts)

    def detections(self) -> Html:
        try:
            detections.validate(self.root)
            status = note("Rules and metadata pass offline validation.")
        except detections.DetectionError as exc:
            status = note(f"Validation failed: {exc}", error=True)
        rows = []
        for rule_id, m in sorted(detections.load_metadata(self.root).items()):
            tests = m.get("tests") or {}
            rows.append([rule_id, m.get("title"), m.get("kind", "detection"), badge(m.get("status")), m.get("level"),
                         fmt(m.get("mitre")), len(tests.get("logtest") or []), len(tests.get("e2e") or []),
                         fmt(m.get("telemetry"))])
        return join([status, table(["Rule", "Title", "Kind", "Status", "Level", "ATT&CK", "Logtest cases", "E2E tests",
                                    "Telemetry"], rows)])

    def validation(self) -> Html:
        loaded = scenarios.load_scenarios(self.root)
        reports, bad = self._reports("*scenarios*.json")
        parts = [note("Scenarios run only from the CLI with `aegis scenarios run --authorize`; this view is read-only."),
                 table(["Scenario", "Technique", "Title", "Expected rules", "Forbidden rules", "Window (s)"],
                       [[sc["id"], sc["technique"], sc["title"], fmt(sc["expected"].get("detection_rules")),
                         fmt(sc["expected"].get("forbidden_rules")), sc["timeout_seconds"]] for sc in loaded.values()])]
        parts.append(tag("h2", "Run history (newest first)"))
        rows = [[rep.get("generated_at"), source, r.get("scenario_id"), badge(r.get("status")), r.get("reason"),
                 fmt(r.get("first_detection_latency_s")), r.get("cleanup")]
                for source, rep in reversed(reports) for r in rep.get("results", [])]
        parts.append(table(["Run", "Source", "Scenario", "Status", "Reason", "Latency (s)", "Cleanup"], rows,
                           empty="no scenario runs recorded"))
        if bad:
            parts.append(note(f"Unreadable report files skipped: {fmt(bad)}", error=True))
        return join(parts)

    def coverage(self) -> Html:
        reports, _ = self._reports("*scenarios*.json")
        matrix = coverage.build_matrix(self.root, reports[-1][1] if reports else None)
        rows = [[r["rule_id"], r["title"], fmt(r["techniques"]), badge(r["rule_status"]), r["logtest_cases"],
                 f"+{len(r['positive_scenarios'])} / -{len(r['negative_scenarios'])}",
                 fmt([f"{k}: {v}" for k, v in r["scenario_results"].items()]) if r["scenario_results"] else "not run",
                 "yes" if r["observed_in_lab"] else "no", fmt(r["min_latency_s"])] for r in matrix["rows"]]
        return join([
            note("A mapped technique, an existing rule, a passing test, and an observation in this lab are different "
                 "claims. None of them measures real-world detection rate or complete protection."),
            tag("p", f"Scenario results from the report of {fmt(matrix['scenario_report_generated_at'])}."),
            table(["Rule", "Title", "ATT&CK", "Status", "Logtest", "Scenarios (+/-)", "Last results", "Observed in lab",
                   "Min latency (s)"], rows),
            tag("h2", "Known gaps"),
            tag("ul", join(tag("li", f"{r['rule_id']}: {'; '.join(r['limitations'])}") for r in matrix["rows"]))])

    def case_list(self) -> Html:
        rows = []
        for case_id, case, problem in self._cases():
            link = tag("a", case_id, href=f"/cases/{case_id}")
            if case is None:
                rows.append([link, "-", "-", "-", "-", badge("FAILED"), problem])
            else:
                rows.append([link, badge(case["status"]), case["severity"], case["classification"], case["title"],
                             badge("VERIFIED"), ""])
        return table(["Case", "Status", "Severity", "Classification", "Title", "Integrity", "Problem"], rows,
                     empty="no cases")

    def case(self, case_id: str) -> Html:
        try:
            c = self.store.load(case_id)
        except cases.CaseError as exc:
            return note(str(exc), error=True)
        evidence_problems = self.store.verify_evidence_files(c)
        fields = [[k, c.get(k, "")] for k in ("title", "severity", "classification", "confidence", "created_at")]
        fields += [["status", badge(c["status"])], ["affected endpoints", fmt(c["affected_endpoints"])],
                   ["audit trail", badge("VERIFIED")],
                   ["evidence files", badge("VERIFIED") if not evidence_problems else
                    join([badge("FAILED"), " ", fmt(evidence_problems)])]]
        parts = [table(["Field", "Value"], fields),
                 tag("h2", "Source alerts"),
                 table(["Time", "Rule", "Level", "ATT&CK", "Agent", "Description", "Alert id"],
                       [[a["timestamp"], a["rule_id"], a["rule_level"], fmt(a.get("mitre", [])), a["agent"],
                         a["rule_description"], a["alert_id"]] for a in c["source_alerts"]]),
                 tag("h2", "Evidence"),
                 table(["Id", "Kind", "Reference", "SHA-256", "Description"],
                       [[x["evidence_id"], x["kind"], x["reference"], tag("code", x["sha256"]), x.get("description", "")]
                        for x in c["evidence"]]),
                 tag("h2", "Timeline (UTC)"),
                 table(["Time", "Source", "Event"],
                       [[t.isoformat(timespec="seconds"), src, text] for t, src, text in reporting.timeline(c)]),
                 tag("h2", "Findings"), tag("p", c.get("findings") or "None recorded."),
                 tag("h2", "Recommendations (not executed)"),
                 tag("ul", join(tag("li", r) for r in c["recommendations"]) or tag("li", "None.")),
                 tag("h2", "Response actions (simulation only)"),
                 table(["Id", "Playbook", "Action", "Endpoint", "Target", "Purpose", "State", "Proposed by",
                        "Approved by", "Simulated plan"],
                       [[a["action_id"], f"{a['playbook']} step {a['step']}", a["action_type"], a["endpoint"], a["target"],
                         a["purpose"], badge(a["state"]), a["proposed_by"], a.get("approved_by", "-"), a.get("plan", "-")]
                        for a in c.get("response_actions", [])]),
                 tag("h2", "Analyst notes"),
                 table(["Time", "Author", "Note"], [[n["at"], n["author"], n["text"]] for n in c["notes"]]),
                 tag("h2", "Audit trail"),
                 table(["Seq", "Time", "Actor", "Action", "Hash"],
                       [[a["seq"], a["at"], a["actor"], a["action"], tag("code", a["hash"][:16])] for a in c["audit"]])]
        if c.get("closure_reason"):
            parts[1:1] = [tag("h2", "Closure"), tag("p", c["closure_reason"])]
        return join(parts)

    def playbooks(self) -> Html:
        parts = [note("Action steps can only be proposed, approved by a second analyst, and simulated from the CLI "
                      "(`aegis case propose|approve|execute --simulate`). Nothing changes an endpoint.")]
        for pb in playbooks.load_playbooks(self.root).values():
            parts += [tag("h2", f"{pb['id']}: {pb['title']}"), tag("p", f"Applies to rules {fmt(pb['applies_to_rules'])}. "
                                                                         f"{pb['description']}"),
                      table(["Step", "Kind", "Action", "Instruction"],
                            [[n, s["kind"], s.get("action", "-"), s["text"]] for n, s in enumerate(pb["steps"], start=1)])]
        return join(parts)

    def audit(self) -> Html:
        rows = []
        for case_id, case, _ in self._cases():
            if case is None:
                continue
            rows += [(t, case_id, src, text) for t, src, text in reporting.timeline(case) if src.startswith("audit #")]
        rows.sort(key=lambda r: r[0], reverse=True)
        deploys, _ = self._reports("detections-deploy-*.json", include_examples=False)
        runs, _ = self._reports("*scenarios*.json")
        return join([
            note("Security-sensitive actions recorded by AegisSOC. Actor names are self-declared on the CLI."),
            tag("h2", "Case changes and response authorizations"),
            table(["Time (UTC)", "Case", "Entry", "Event"],
                  [[t.isoformat(timespec="seconds"), tag("a", cid, href=f"/cases/{cid}"), src, text]
                   for t, cid, src, text in rows], empty="no case activity"),
            tag("h2", "Detection deployments"),
            table(["Deployed", "Commit", "Uncommitted changes", "Rule files"],
                  [[d.get("deployed_at"), (d.get("git") or {}).get("commit"), (d.get("git") or {}).get("detections_dirty"),
                    fmt(sorted(d.get("files", {})))] for _, d in reversed(deploys)], empty="no deployments recorded"),
            tag("h2", "Authorized scenario runs"),
            table(["Run", "Source", "Executor", "Summary"],
                  [[r.get("generated_at"), source, (r.get("environment") or {}).get("executor", "n/a"),
                    fmt([f"{k}: {v}" for k, v in (r.get("summary") or {}).items()])] for source, r in reversed(runs)],
                  empty="no scenario runs recorded")])

    def routes(self) -> dict[str, tuple[str, Callable[[], Html]]]:
        return {"/": ("Overview", self.overview), "/health": ("System health", self.health),
                "/detections": ("Detections", self.detections), "/validation": ("Validation", self.validation),
                "/coverage": ("Coverage", self.coverage), "/cases": ("Cases", self.case_list),
                "/playbooks": ("Playbooks", self.playbooks), "/audit": ("Audit log", self.audit)}


def _token_matches(candidate: str, token: str) -> bool:
    return hmac.compare_digest(candidate.encode("utf-8"), token.encode("utf-8"))


def make_handler(site: Site, token: str, port: int) -> type[BaseHTTPRequestHandler]:
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "AegisSOC-UI"
        sys_version = ""

        def do_GET(self) -> None:
            self._handle(head=False)

        def do_HEAD(self) -> None:
            self._handle(head=True)

        def _read_only(self) -> None:
            self._send(HTTPStatus.METHOD_NOT_ALLOWED, "text/plain", b"read-only", extra={"Allow": "GET, HEAD"})

        do_POST = do_PUT = do_PATCH = do_DELETE = _read_only

        def _send(self, status: HTTPStatus, ctype: str, body: bytes, head: bool = False,
                  extra: dict[str, str] | None = None) -> None:
            self.send_response(status)
            for k, v in {**SECURITY_HEADERS, "Content-Type": f"{ctype}; charset=utf-8",
                         "Content-Length": str(len(body)), **(extra or {})}.items():
                self.send_header(k, v)
            self.end_headers()
            if not head:
                self.wfile.write(body)

        def _authorized(self) -> bool:
            try:
                morsel = SimpleCookie(self.headers.get("Cookie", "")).get(COOKIE)
            except CookieError:
                return False
            return morsel is not None and _token_matches(morsel.value, token)

        def _handle(self, head: bool) -> None:
            # Rejecting unexpected Host headers blocks DNS-rebinding pages from reading the UI.
            if self.headers.get("Host") not in allowed_hosts:
                return self._send(HTTPStatus.MISDIRECTED_REQUEST, "text/plain", b"unexpected Host header", head)
            url = urlsplit(self.path)
            supplied = parse_qs(url.query).get("token")
            if supplied:
                if not _token_matches(supplied[0], token):
                    return self._send(HTTPStatus.UNAUTHORIZED, "text/plain", b"invalid token", head)
                return self._send(HTTPStatus.SEE_OTHER, "text/plain", b"", head, extra={
                    "Location": "/", "Set-Cookie": f"{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/"})
            if not self._authorized():
                return self._send(HTTPStatus.UNAUTHORIZED, "text/plain",
                                  b"open the URL with the token printed by `aegis ui`", head)
            try:
                if url.path == "/style.css":
                    return self._send(HTTPStatus.OK, "text/css", CSS.encode(), head)
                routes = site.routes()
                match = CASE_PATH.match(url.path)
                if url.path in routes:
                    title, render = routes[url.path]
                    body = page(title, render())
                elif match:
                    body = page(match.group(1), site.case(match.group(1)))
                else:
                    return self._send(HTTPStatus.NOT_FOUND, "text/plain", b"not found", head)
            except Exception as exc:  # noqa: BLE001 - one broken file must not take the UI down
                self.log_message("error rendering %s: %s: %s", url.path, type(exc).__name__, exc)
                return self._send(HTTPStatus.INTERNAL_SERVER_ERROR, "text/plain",
                                  b"could not render this page; see the server log", head)
            self._send(HTTPStatus.OK, "text/html", body.encode("utf-8"), head)

        def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
            # The request line can carry the token, so only the path is logged.
            self.log_message("%s %s %s", self.command, urlsplit(self.path).path, code)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
            sys.stderr.write(reporting.terminal(f"{self.address_string()} {format % args}") + "\n")

    return Handler


def create_server(root: Path, dashboard_url: str, port: int = 8765) -> tuple[ThreadingHTTPServer, str]:
    """Bind to loopback only; returns the server and the one-time login URL."""
    token = secrets.token_urlsafe(32)
    server = ThreadingHTTPServer((LISTEN_HOST, port), BaseHTTPRequestHandler)
    server.daemon_threads = True
    actual = server.server_address[1]
    server.RequestHandlerClass = make_handler(Site(root, dashboard_url), token, actual)
    return server, f"http://{LISTEN_HOST}:{actual}/?token={token}"
