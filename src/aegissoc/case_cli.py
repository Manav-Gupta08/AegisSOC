from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import cases, provision, reporting
from .settings import Context, find_repo_root


def _store() -> cases.CaseStore:
    return cases.CaseStore(find_repo_root())


def _indexer(ctx: Context):
    return provision.indexer_client(ctx, provision.READER_INDEXER_USER, ctx.secret("INDEXER_READER_PASSWORD"))


def _save(store: cases.CaseStore, case: dict, base_head: str | None) -> None:
    store.save(case, base_head)
    print(f"{case['case_id']}: status={case['status']} alerts={len(case['source_alerts'])} "
          f"evidence={len(case['evidence'])} audit_entries={len(case['audit'])}")


def cmd(args: argparse.Namespace) -> int:
    store = _store()
    a = args.case_action
    if a == "new":
        case = cases.new_case(store.next_id(), args.title, args.severity, args.actor)
        _save(store, case, None)
        return 0
    if a == "list":
        for c in store.list():
            print(reporting.terminal(f"  {c['case_id']}  {c['status']:<24} {c['severity']:<8} {c['title']}"))
        return 0
    if a == "alerts":
        ctx = Context.load()
        since = datetime.now(timezone.utc) - timedelta(minutes=args.minutes)
        filters = [{"range": {"timestamp": {"gte": since.isoformat()}}}, {"range": {"rule.level": {"gte": args.min_level}}}]
        if args.agent:
            filters.append({"term": {"agent.name": args.agent}})
        if args.rule:
            filters.append({"terms": {"rule.id": args.rule}})
        body = {"size": args.limit, "sort": [{"timestamp": "desc"}], "query": {"bool": {"filter": filters}},
                "_source": ["timestamp", "rule.id", "rule.level", "rule.description", "agent.name"]}
        for h in _indexer(ctx).request("POST", "/wazuh-alerts-*/_search", json=body)["hits"]["hits"]:
            s = h["_source"]
            print(reporting.terminal(f"  {h['_id']}  {s['timestamp']}  {s['rule']['id']:>6} L{s['rule']['level']:<2} "
                                     f"{s['agent']['name']}: {s['rule']['description']}"))
        return 0

    case = store.load(args.case_id)
    base = case["audit"][-1]["hash"]
    if a == "show":
        print(json.dumps({k: v for k, v in case.items() if k != "audit"}, indent=2))
        print(f"audit entries: {len(case['audit'])} (verified)")
    elif a == "attach":
        ctx = Context.load()
        body = {"size": len(args.alert_ids), "query": {"ids": {"values": args.alert_ids}}}
        hits = _indexer(ctx).request("POST", "/wazuh-alerts-*/_search", json=body)["hits"]["hits"]
        missing = set(args.alert_ids) - {h["_id"] for h in hits}
        if missing:
            raise cases.CaseError(f"alerts not found: {sorted(missing)}")
        for h in hits:
            cases.record(case, args.actor, "add_alert", {"alert": cases.alert_from_hit(h)})
            raw = json.dumps({"_index": h["_index"], "_id": h["_id"], "_source": h["_source"]}, indent=2, sort_keys=True).encode()
            store.add_file_evidence(case, args.actor, "alert", raw, f"raw alert {h['_id']} from {h['_index']}")
        _save(store, case, base)
    elif a == "note":
        cases.record(case, args.actor, "note", {"text": args.text})
        _save(store, case, base)
    elif a == "set":
        cases.record(case, args.actor, "set", {"field": args.field, "value": args.value})
        _save(store, case, base)
    elif a == "recommend":
        cases.record(case, args.actor, "recommend", {"text": args.text})
        _save(store, case, base)
    elif a == "transition":
        cases.record(case, args.actor, "transition", {"from": case["status"], "to": args.to, "reason": args.reason or ""})
        _save(store, case, base)
    elif a == "correct":
        cases.record(case, args.actor, "correction", {"field": args.field, "value": args.value, "reason": args.reason})
        _save(store, case, base)
    elif a == "verify":
        problems = store.verify_evidence_files(case)
        print("audit trail: VERIFIED")
        print("evidence files: " + ("VERIFIED" if not problems else "FAILED " + "; ".join(problems)))
        return 0 if not problems else 2
    elif a == "report":
        integrity = {"audit": cases.verify(case), "evidence": store.verify_evidence_files(case)}
        out = Path(args.output) if args.output else store.dir / f"{case['case_id']}-report.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(reporting.render_markdown(case, integrity, args.redact), encoding="utf-8")
        out.with_suffix(".json").write_text(json.dumps(reporting.redact(case, args.redact), indent=2) + "\n", encoding="utf-8")
        print(f"Report: {out} (+ .json)")
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("case", help="incident case workflow (audited, hash-chained)")
    p.set_defaults(func=cmd)
    cs = p.add_subparsers(dest="case_action", required=True)

    def with_actor(sp):
        sp.add_argument("--actor", default="analyst", help="name recorded in the audit trail")
        return sp

    n = with_actor(cs.add_parser("new"))
    n.add_argument("--title", required=True)
    n.add_argument("--severity", required=True, choices=["low", "medium", "high", "critical"])
    cs.add_parser("list")
    al = cs.add_parser("alerts", help="find alert ids to attach")
    al.add_argument("--agent")
    al.add_argument("--rule", nargs="*")
    al.add_argument("--minutes", type=int, default=60)
    al.add_argument("--min-level", type=int, default=3)
    al.add_argument("--limit", type=int, default=20)

    for name in ("show", "verify"):
        cs.add_parser(name).add_argument("case_id")
    at = with_actor(cs.add_parser("attach", help="attach alerts by id (stored as hashed evidence)"))
    at.add_argument("case_id")
    at.add_argument("alert_ids", nargs="+")
    for name in ("note", "recommend"):
        sp = with_actor(cs.add_parser(name))
        sp.add_argument("case_id")
        sp.add_argument("text")
    st = with_actor(cs.add_parser("set"))
    st.add_argument("case_id")
    st.add_argument("field", choices=sorted(cases.SETTABLE))
    st.add_argument("value")
    tr = with_actor(cs.add_parser("transition"))
    tr.add_argument("case_id")
    tr.add_argument("to", choices=sorted(cases.TRANSITIONS))
    tr.add_argument("--reason")
    co = with_actor(cs.add_parser("correct", help="post-closure correction (audited)"))
    co.add_argument("case_id")
    co.add_argument("field", choices=sorted(cases.SETTABLE))
    co.add_argument("value")
    co.add_argument("--reason", required=True)
    rp = cs.add_parser("report")
    rp.add_argument("case_id")
    rp.add_argument("--redact", nargs="*", default=[], help="terms to replace with [REDACTED] (hostnames, users)")
    rp.add_argument("--output")
