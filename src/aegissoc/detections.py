from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

from .clients import ServiceError, WazuhApi

RULE_ID_RANGE = range(100000, 101000)
STATUSES = {"experimental", "tested", "deprecated"}
REQUIRED_FIELDS = ("id", "title", "status", "level", "rule_file", "rationale", "telemetry", "mitre",
                   "false_positives", "limitations", "investigation", "tests")
MITRE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
RULE_FILE_NAME = re.compile(r"^aegissoc_[a-z0-9_]+\.xml$")
# Static decoder fields need dedicated <same_*> options; <same_field> silently never matches them.
STATIC_FIELDS = {"srcip", "dstip", "srcport", "dstport", "srcuser", "user", "dstuser", "protocol",
                 "action", "id", "url", "data", "extra_data", "status", "system_name", "location"}


class DetectionError(ValueError):
    pass


@dataclass(frozen=True)
class RuleInfo:
    id: int
    level: int
    file: Path


def detections_root(root: Path) -> Path:
    return root / "detections"


def rule_files(root: Path) -> list[Path]:
    return sorted((detections_root(root) / "wazuh" / "rules").glob("*.xml"))


def parse_rules(path: Path) -> list[RuleInfo]:
    # Wazuh rule files hold multiple top-level <group> elements, so wrap before parsing.
    try:
        tree = ET.fromstring(f"<root>{path.read_text(encoding='utf-8')}</root>")
    except ET.ParseError as exc:
        raise DetectionError(f"{path.name}: not well-formed XML: {exc}") from exc
    rules = []
    for rule in tree.iter("rule"):
        try:
            rules.append(RuleInfo(int(rule.get("id", "")), int(rule.get("level", "")), path))
        except ValueError as exc:
            raise DetectionError(f"{path.name}: rule with missing/invalid id or level") from exc
        if not (rule.findtext("description") or "").strip():
            raise DetectionError(f"{path.name}: rule {rule.get('id')} has no description")
        for same in rule.iter("same_field"):
            if (same.text or "").strip() in STATIC_FIELDS:
                raise DetectionError(f"{path.name}: rule {rule.get('id')} uses <same_field>{same.text}</same_field>; "
                                     f"use <same_{same.text.strip()} /> for static fields")
    return rules


def load_metadata(root: Path) -> dict[int, dict[str, Any]]:
    meta = {}
    for path in sorted((detections_root(root) / "metadata").glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise DetectionError(f"{path.name}: metadata must be a mapping")
        if str(data.get("id")) != path.stem:
            raise DetectionError(f"{path.name}: id {data.get('id')} does not match file name")
        meta[int(data["id"])] = data
    return meta


def validate(root: Path) -> list[RuleInfo]:
    """Structural validation; safe for CI. Returns all AegisSOC rules."""
    rules: list[RuleInfo] = []
    for path in rule_files(root):
        if not RULE_FILE_NAME.match(path.name):
            raise DetectionError(f"{path.name}: rule files must be named aegissoc_<name>.xml")
        rules += parse_rules(path)

    seen: dict[int, Path] = {}
    for r in rules:
        if r.id not in RULE_ID_RANGE:
            raise DetectionError(f"rule {r.id} in {r.file.name} is outside the AegisSOC range 100000-100999")
        if r.id in seen:
            raise DetectionError(f"rule {r.id} is defined in both {seen[r.id].name} and {r.file.name}")
        seen[r.id] = r.file

    meta = load_metadata(root)
    for r in rules:
        m = meta.get(r.id)
        if m is None:
            raise DetectionError(f"rule {r.id} has no detections/metadata/{r.id}.yml")
        # level 0 and an empty ATT&CK list are legitimate for suppressions, so check presence, not truthiness.
        missing = [f for f in REQUIRED_FIELDS
                   if (f not in m if f in ("mitre", "level") else not m.get(f))]
        if missing:
            raise DetectionError(f"rule {r.id}: metadata missing {missing}")
        is_suppression = m.get("kind") == "suppression"
        if is_suppression and (r.level != 0 or not 100900 <= r.id <= 100999):
            raise DetectionError(f"rule {r.id}: suppressions must be level 0 and use ids 100900-100999")
        if not is_suppression and not m["mitre"]:
            raise DetectionError(f"rule {r.id}: detections need at least one ATT&CK mapping")
        if m["status"] not in STATUSES:
            raise DetectionError(f"rule {r.id}: status must be one of {sorted(STATUSES)}")
        if int(m["level"]) != r.level:
            raise DetectionError(f"rule {r.id}: metadata level {m['level']} != rule level {r.level}")
        if r.level == 0 and not is_suppression:
            raise DetectionError(f"rule {r.id}: level 0 silences alerts; declare kind: suppression")
        if (root / m["rule_file"]).resolve() != r.file.resolve():
            raise DetectionError(f"rule {r.id}: metadata rule_file does not point to {r.file.name}")
        bad = [t for t in m["mitre"] if not MITRE_ID.match(str(t))]
        if bad:
            raise DetectionError(f"rule {r.id}: invalid ATT&CK ids {bad}")
        tests = m["tests"]
        if not (tests.get("logtest") or tests.get("e2e")):
            raise DetectionError(f"rule {r.id}: needs at least one logtest or e2e test")
        for t in tests.get("logtest") or []:
            if not t.get("events") or not (t.get("expect_last") or t.get("expect_none")):
                raise DetectionError(f"rule {r.id}: logtest '{t.get('name')}' needs events and expect_last/expect_none")
    orphans = sorted(set(meta) - set(seen))
    if orphans:
        raise DetectionError(f"metadata without a rule: {orphans}")
    return rules


@dataclass
class TestResult:
    rule_id: int
    name: str
    status: str
    detail: str
    matched: list[str] = field(default_factory=list)


def run_logtest_case(api: WazuhApi, case: dict[str, Any]) -> list[str]:
    """Send events through one logtest session; return the rule id matched by each event."""
    token = None
    matched = []
    try:
        for event in case["events"]:
            body = {"event": event, "log_format": case.get("log_format", "syslog"), "location": case.get("location", "aegis-test")}
            if token:
                body["token"] = token
            data = api.request("PUT", "/logtest", json=body)["data"]
            token = data.get("token", token)
            matched.append(str(data["output"].get("rule", {}).get("id", "")))
    finally:
        if token:
            try:
                api.request("DELETE", f"/logtest/sessions/{token}")
            except ServiceError:
                pass
    return matched


def evaluate_case(rule_id: int, case: dict[str, Any], matched: list[str]) -> TestResult:
    name = case["name"]
    if case.get("expect_last"):
        expected = str(case["expect_last"])
        ok = bool(matched) and matched[-1] == expected
        detail = f"last event matched {matched[-1] if matched else None}, expected {expected}"
    else:
        forbidden = {str(x) for x in case["expect_none"]}
        hits = sorted(forbidden & set(matched))
        ok = not hits
        detail = f"forbidden rules matched: {hits}" if hits else f"none of {sorted(forbidden)} matched"
    return TestResult(rule_id, name, "PASSED" if ok else "FAILED", detail, matched)


def run_tests(root: Path, api: WazuhApi) -> list[TestResult]:
    results = []
    for rule_id, meta in sorted(load_metadata(root).items()):
        for case in meta["tests"].get("logtest") or []:
            try:
                matched = run_logtest_case(api, case)
                results.append(evaluate_case(rule_id, case, matched))
            except ServiceError as exc:
                results.append(TestResult(rule_id, case["name"], "INCONCLUSIVE", str(exc)))
        for case in meta["tests"].get("e2e") or []:
            results.append(TestResult(rule_id, case["name"], "SKIPPED", "end-to-end test; run via scenario runner"))
    return results


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_state(root: Path, run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> dict[str, Any]:
    head = run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True)
    dirty = run(["git", "-C", str(root), "status", "--porcelain", "--", "detections"], capture_output=True, text=True)
    return {
        "commit": head.stdout.strip() if head.returncode == 0 else None,
        "detections_dirty": bool(dirty.stdout.strip()) if dirty.returncode == 0 else None,
    }


def deploy(root: Path, api: WazuhApi, allow_dirty: bool = False, log: Callable[[str], None] = print,
           run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
           sleep: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    validate(root)
    state = git_state(root, run)
    if state["detections_dirty"] and not allow_dirty:
        raise DetectionError("detections/ has uncommitted changes; commit (review) them first or pass --allow-dirty")

    files = rule_files(root)
    for path in files:
        api.request("PUT", f"/rules/files/{path.name}", params={"overwrite": "true"},
                    data=path.read_bytes(), headers={"Content-Type": "application/octet-stream"})
        log(f"uploaded {path.name}")

    validation = None
    for attempt in range(1, 4):
        try:
            validation = api.request("GET", "/manager/configuration/validation")["data"]["affected_items"][0]
            break
        except ServiceError as exc:
            # The API's 10 s request timeout surfaces as HTTP 500 on slow storage; retry before giving up.
            if exc.status_code != 500 or attempt == 3:
                raise DetectionError(f"configuration validation unavailable ({exc}); manager NOT restarted") from exc
            log(f"validation attempt {attempt} timed out; retrying")
            sleep(10)
    if validation.get("status") != "OK":
        raise DetectionError(f"manager rejected configuration: {validation}")
    api.request("PUT", "/manager/restart")
    log("manager configuration valid; restart requested")

    return {
        "schema_version": "1.0",
        "deployed_at": datetime.now(timezone.utc).isoformat(),
        "git": state,
        "allow_dirty": allow_dirty,
        "files": {p.name: sha256(p) for p in files},
    }


def write_record(record: dict[str, Any], reports_dir: Path, prefix: str) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = reports_dir / f"{prefix}-{stamp}.json"
    path.write_text(json.dumps(record, indent=2, default=str) + "\n", encoding="utf-8")
    return path


def results_record(results: list[TestResult]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return {"schema_version": "1.0", "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": counts, "results": [asdict(r) for r in results]}
