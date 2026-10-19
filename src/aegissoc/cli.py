from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from . import (agentconfig, backup, case_cli, cases, coverage, deploy, detections, health, metrics, playbooks, preflight,
               provision, scenarios, telemetry, web)
from .clients import ServiceError
from .settings import Context, Paths, find_repo_root

_EXIT = {health.PASS: 0, health.WARNING: 1, health.FAIL: 2}


def _print_results(results: list[health.CheckResult]) -> str:
    width = max((len(r.name) for r in results), default=10)
    for r in results:
        print(f"  {r.status:<12} {r.name:<{width}}  {r.detail}")
    overall = health.overall_status(results)
    print(f"\nOverall: {overall}")
    return overall


def cmd_preflight(_: argparse.Namespace) -> int:
    overall = _print_results(preflight.run_preflight(Paths(find_repo_root())))
    return _EXIT[overall]


def cmd_init_secrets(_: argparse.Namespace) -> int:
    paths = Paths(find_repo_root())
    added = deploy.init_secrets(paths)
    print(f"Added to {paths.env_file}: {', '.join(added)}" if added else f"{paths.env_file} already complete; nothing changed")
    return 0


def cmd_prepare(args: argparse.Namespace) -> int:
    deploy.prepare(Context.load(), force_render=args.force_render, rehash_users=args.rehash_users)
    return 0


def cmd_up(_: argparse.Namespace) -> int:
    ctx = Context.load()
    deploy.require_prepared(ctx)
    deploy.ensure_max_map_count()
    return subprocess.run(deploy.compose_command(ctx, "up", "-d"), env=deploy.compose_env(ctx)).returncode


def cmd_stop(_: argparse.Namespace) -> int:
    ctx = Context.load()
    return subprocess.run(deploy.compose_command(ctx, "stop"), env=deploy.compose_env(ctx)).returncode


def cmd_compose(args: argparse.Namespace) -> int:
    ctx = Context.load()
    deploy.guard_compose_args(args.compose_args)
    return subprocess.run(deploy.compose_command(ctx, *args.compose_args), env=deploy.compose_env(ctx)).returncode


def cmd_provision(_: argparse.Namespace) -> int:
    provision.provision(Context.load())
    return 0


def cmd_health(args: argparse.Namespace) -> int:
    ctx = Context.load()
    results = health.run_health(ctx, credential_test=args.credential_test)
    overall = _print_results(results)
    if not args.no_report:
        path = health.write_report(health.build_report(ctx, results, datetime.now(timezone.utc)), ctx.paths.reports_dir)
        print(f"Report: {path}")
    return _EXIT[overall]


def cmd_agent_config(args: argparse.Namespace) -> int:
    paths = Paths(find_repo_root())
    configs = agentconfig.load_group_configs(paths)
    print(f"valid: {', '.join(c.name for c in configs)}")
    if args.action == "apply":
        ctx = Context.load(paths.root)
        api = provision.api_client(ctx)
        api.authenticate("wazuh-wui", ctx.secret("WAZUH_API_WUI_PASSWORD"))
        agentconfig.apply_group_configs(api, configs)
    elif args.action == "assign":
        if not (args.agent and args.group):
            raise agentconfig.AgentConfigError("assign needs --agent and --group")
        ctx = Context.load(paths.root)
        agent_id = agentconfig.assign_group(_admin_api(ctx), args.agent, args.group, {c.name for c in configs})
        print(f"agent {args.agent} ({agent_id}) is in group {args.group}")
    return 0


def _admin_api(ctx: Context):
    api = provision.api_client(ctx)
    api.authenticate("wazuh-wui", ctx.secret("WAZUH_API_WUI_PASSWORD"))
    return api


def cmd_detections(args: argparse.Namespace) -> int:
    root = find_repo_root()
    rules = detections.validate(root)
    print(f"valid: {len(rules)} rule(s): {', '.join(str(r.id) for r in rules)}")
    if args.action == "validate":
        return 0
    ctx = Context.load(root)
    if args.action == "deploy":
        record = detections.deploy(root, _admin_api(ctx), allow_dirty=args.allow_dirty)
        print(f"Deployment record: {detections.write_record(record, ctx.paths.reports_dir, 'detections-deploy')}")
        return 0
    results = detections.run_tests(root, _admin_api(ctx))
    for r in results:
        print(f"  {r.status:<12} {r.rule_id}  {r.name}  ({r.detail})")
    record = detections.results_record(results)
    print(f"Summary: {record['summary']}")
    print(f"Report: {detections.write_record(record, ctx.paths.reports_dir, 'detections-test')}")
    return 2 if any(r.status in ("FAILED", "INCONCLUSIVE") for r in results) else 0


def cmd_scenarios(args: argparse.Namespace) -> int:
    root = find_repo_root()
    loaded = scenarios.load_scenarios(root)
    if args.action in ("validate", "list"):
        for sc in loaded.values():
            exp = sc["expected"]
            print(f"  {sc['id']}  {sc['technique']:<10} {sc['title']}  "
                  f"expect={exp.get('detection_rules') or []} forbid={exp.get('forbidden_rules') or []}")
        print(f"valid: {len(loaded)} scenario(s)")
        return 0

    ids = list(loaded) if args.all else args.ids
    unknown = [i for i in ids if i not in loaded]
    if not ids or unknown:
        raise scenarios.ScenarioError(f"specify scenario ids or --all (unknown: {unknown})")
    if not args.authorize:
        raise scenarios.ScenarioError("refusing to execute simulations without --authorize "
                                      "(confirms the targets are lab endpoints you own)")
    ctx = Context.load(root)
    executor = scenarios.Executor.parse(ctx.env.get("AEGIS_LINUX_EXECUTOR") or scenarios.default_executor())
    api = provision.api_client(ctx)
    api.authenticate(provision.READER_API_USER, ctx.secret("WAZUH_API_READER_PASSWORD"))
    indexer = provision.indexer_client(ctx, provision.READER_INDEXER_USER, ctx.secret("INDEXER_READER_PASSWORD"))

    results = []
    for sid in ids:
        print(f"running {sid} via {executor.spec} ...")
        r = scenarios.run_scenario(loaded[sid], api, indexer, executor)
        lat = f" latency={r.first_detection_latency_s}s" if r.first_detection_latency_s is not None else ""
        print(f"  {r.status:<16} {sid}  {r.reason}{lat}  cleanup={r.cleanup}")
        results.append(r)

    git = detections.git_state(root)
    env = {"wazuh_version": ctx.lock.wazuh_version, "git": git, "executor": executor.spec,
           "rule_files": {p.name: detections.sha256(p) for p in detections.rule_files(root)}}
    record = scenarios.run_record(results, env)
    print(f"Summary: {record['summary']}")
    print(f"Report: {detections.write_record(record, ctx.paths.reports_dir, 'scenarios')}")
    return 0 if all(r.status == scenarios.PASSED for r in results) else 2


def cmd_playbooks(_: argparse.Namespace) -> int:
    loaded = playbooks.load_playbooks(find_repo_root())
    for pb in loaded.values():
        actions = [f"{n}:{s['action']}" for n, s in enumerate(pb["steps"], start=1) if s["kind"] == "action"]
        print(f"  {pb['id']}  rules={pb['applies_to_rules']}  actions={actions}  {pb['title']}")
    print(f"valid: {len(loaded)} playbook(s)")
    return 0


def cmd_telemetry(args: argparse.Namespace) -> int:
    root = find_repo_root()
    sources = telemetry.load_sources(root)
    if args.validate:
        print(f"valid: {len(sources)} source(s): {', '.join(s['id'] for s in sources)}")
        return 0
    ctx = Context.load(root)
    api = provision.api_client(ctx)
    api.authenticate(provision.READER_API_USER, ctx.secret("WAZUH_API_READER_PASSWORD"))
    indexer = provision.indexer_client(ctx, provision.READER_INDEXER_USER, ctx.secret("INDEXER_READER_PASSWORD"))
    now = datetime.now(timezone.utc)
    results = telemetry.check_sources(api, indexer, sources, now)
    overall = _print_results(results)
    report = {"schema_version": "1.0", "generated_at": now.isoformat(), "overall": overall,
              "checks": [asdict(r) for r in results]}
    print(f"Report: {detections.write_record(report, ctx.paths.reports_dir, 'telemetry')}")
    return _EXIT[overall]


def cmd_ui(args: argparse.Namespace) -> int:
    ctx = Context.load(require_env=False)
    dashboard = f"https://127.0.0.1:{ctx.env['AEGIS_DASHBOARD_PORT']}"
    server, url = web.create_server(ctx.paths.root, dashboard, args.port)
    print(f"AegisSOC UI (read-only, this machine only): {url}")
    print("The token in the URL grants access until the server stops. Press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    root = find_repo_root()
    paths = Paths(root)
    report = json.loads(Path(args.report).read_text(encoding="utf-8")) if args.report else coverage.latest_report(paths.reports_dir)
    matrix = coverage.build_matrix(root, report)
    out = Path(args.output) if args.output else paths.reports_dir / "coverage.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(coverage.render_markdown(matrix), encoding="utf-8")
    out.with_suffix(".json").write_text(json.dumps(matrix, indent=2) + "\n", encoding="utf-8")
    print(f"Coverage matrix: {out} (+ .json)")
    return 0


def cmd_metrics(args: argparse.Namespace) -> int:
    ctx = Context.load()
    root = ctx.paths.root
    folders = [ctx.paths.reports_dir, root / "reports" / "examples"]
    indexer = provision.indexer_client(ctx, provision.READER_INDEXER_USER, ctx.secret("INDEXER_READER_PASSWORD"))
    now = datetime.now(timezone.utc)
    total = indexer.request("GET", "/wazuh-alerts-*/_count")["count"]
    m = {
        "schema_version": "1.0",
        "generated_at": now.isoformat(),
        "wazuh_version": ctx.lock.wazuh_version,
        "scenarios": metrics.scenario_metrics(metrics.load_reports(folders, "*scenarios*.json")),
        "availability": metrics.availability_metrics(metrics.load_reports([ctx.paths.reports_dir], "health-*.json")),
        "cases": metrics.case_metrics(cases.CaseStore(root).list()),
        "alert_volume": metrics.alert_volume(indexer, args.days, now),
        "storage": metrics.storage(indexer, total),
        "resources": metrics.resources(ctx.lock.compose_project),
    }
    m["storage"]["alerts_all_time"] = total
    out = detections.write_record(m, ctx.paths.reports_dir, "metrics")
    out.with_suffix(".md").write_text(metrics.render_markdown(m), encoding="utf-8")
    print(metrics.render_markdown(m))
    print(f"Metrics: {out} (+ .md)")
    return 0


def _stack_snapshot(ctx: Context) -> dict:
    """Facts a restored stack must reproduce (read via reader accounts; retention via admin)."""
    snap: dict = {}
    idx = provision.indexer_client(ctx, provision.READER_INDEXER_USER, ctx.secret("INDEXER_READER_PASSWORD"))
    snap["alert_count"] = idx.request("GET", "/wazuh-alerts-*/_count")["count"]
    api = provision.api_client(ctx)
    api.authenticate(provision.READER_API_USER, ctx.secret("WAZUH_API_READER_PASSWORD"))
    snap["agents"] = sorted(a["name"] for a in api.affected_items("/agents", {"select": "name", "limit": 500}) if a["id"] != "000")
    ids = [r.id for r in detections.validate(ctx.paths.root)]
    loaded = api.affected_items("/rules", {"rule_ids": ",".join(map(str, ids)), "limit": 500})
    snap["aegissoc_rules"] = ids
    snap["rules_loaded"] = sorted(int(r["id"]) for r in loaded)
    admin = provision.indexer_client(ctx, "admin", ctx.secret("INDEXER_ADMIN_PASSWORD"))
    snap["retention_policy"] = admin.request("GET", f"/_plugins/_ism/policies/{provision.RETENTION_POLICY_ID}")["_id"]
    return snap


def cmd_backup(args: argparse.Namespace) -> int:
    ctx = Context.load()
    if args.action == "create":
        snapshot = _stack_snapshot(ctx)
        folder = backup.create(ctx, snapshot)
        manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
        size = sum(v["bytes"] for v in manifest["volumes"].values())
        print(f"Backup: {folder}\n  volumes={len(manifest['volumes'])} bytes={size} alerts={snapshot['alert_count']} "
              f"downtime={manifest['downtime_seconds']}s")
        print("WARNING: the backup contains .env secrets and private keys; store it with restricted access.")
        return 0

    folder = Path(args.path) if args.path else backup.latest_backup(ctx)

    def live_ready() -> bool:
        # Two healthy checks 30 s apart: manager daemons were seen dying shortly after a first PASS.
        if health.overall_status(health.run_health(ctx)) == health.FAIL:
            return False
        time.sleep(30)
        return health.overall_status(health.run_health(ctx)) != health.FAIL

    result = backup.verify_restore(ctx, folder, checks=lambda: _stack_snapshot(ctx), live_ready=live_ready)
    for k, v in result.get("checks", {}).items():
        print(f"  {'PASS' if v else 'FAIL':<5} {k}")
    print(f"Restore verification: {result.get('status')} recovery={result.get('recovery_seconds')}s "
          f"live_stack_healthy_after={result['live_stack_healthy_after']}")
    print(f"Report: {detections.write_record(result, ctx.paths.reports_dir, 'restore-test')}")
    return 0 if result.get("status") == "PASSED" and result["live_stack_healthy_after"] else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis", description="AegisSOC lab tooling")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("preflight", help="read-only host readiness checks").set_defaults(func=cmd_preflight)
    sub.add_parser("init-secrets", help="create/complete .env with random credentials").set_defaults(func=cmd_init_secrets)

    p = sub.add_parser("prepare", help="fetch pinned upstream, generate certs, render configs")
    p.add_argument("--force-render", action="store_true", help="re-render manager/dashboard configs (not certificates or user hashes)")
    p.add_argument("--rehash-users", action="store_true", help="re-render internal_users.yml (needs securityadmin on an existing stack)")
    p.set_defaults(func=cmd_prepare)

    sub.add_parser("up", help="start the stack").set_defaults(func=cmd_up)
    sub.add_parser("stop", help="stop containers (data is kept)").set_defaults(func=cmd_stop)
    sub.add_parser("provision", help="create reader accounts, rotate default API user").set_defaults(func=cmd_provision)

    h = sub.add_parser("health", help="run health checks and write a JSON report")
    h.add_argument("--no-report", action="store_true")
    h.add_argument("--credential-test", action="store_true",
                   help="also verify upstream default credentials are rejected (performs failed logins; not for loops)")
    h.set_defaults(func=cmd_health)

    a = sub.add_parser("agent-config", help="validate, apply, or assign centralized agent group configs")
    a.add_argument("action", choices=["validate", "apply", "assign"])
    a.add_argument("--agent", help="agent name (assign)")
    a.add_argument("--group", help="additional group, e.g. network-sensor (assign)")
    a.set_defaults(func=cmd_agent_config)

    d = sub.add_parser("detections", help="validate (offline), test (logtest), or deploy custom rules")
    d.add_argument("action", choices=["validate", "test", "deploy"])
    d.add_argument("--allow-dirty", action="store_true", help="deploy even if detections/ has uncommitted changes")
    d.set_defaults(func=cmd_detections)

    s = sub.add_parser("scenarios", help="validate/list scenario manifests or run authorized simulations")
    s.add_argument("action", choices=["validate", "list", "run"])
    s.add_argument("ids", nargs="*", help="scenario ids to run")
    s.add_argument("--all", action="store_true")
    s.add_argument("--authorize", action="store_true", help="confirm targets are authorized lab endpoints")
    s.set_defaults(func=cmd_scenarios)

    pb = sub.add_parser("playbooks", help="validate and list response playbooks (offline)")
    pb.add_argument("action", choices=["validate", "list"])
    pb.set_defaults(func=cmd_playbooks)

    tm = sub.add_parser("telemetry", help="check that each expected telemetry source delivered events recently")
    tm.add_argument("--validate", action="store_true", help="only validate deployment/wazuh/telemetry-sources.yml (offline)")
    tm.set_defaults(func=cmd_telemetry)

    ui = sub.add_parser("ui", help="read-only analyst web UI on 127.0.0.1 (token-protected)")
    ui.add_argument("--port", type=int, default=8765)
    ui.set_defaults(func=cmd_ui)

    cv = sub.add_parser("coverage", help="generate the detection coverage matrix (Markdown + JSON)")
    cv.add_argument("--report", help="scenario report JSON (default: latest in reports/runtime)")
    cv.add_argument("--output", help="Markdown output path (default: reports/runtime/coverage.md)")
    cv.set_defaults(func=cmd_coverage)

    mt = sub.add_parser("metrics", help="compute detection, volume, availability, case, and resource metrics")
    mt.add_argument("--days", type=int, default=7)
    mt.set_defaults(func=cmd_metrics)

    bk = sub.add_parser("backup", help="cold backup, or verify a backup by restoring it into an isolated project")
    bk.add_argument("action", choices=["create", "verify-restore"])
    bk.add_argument("path", nargs="?", help="backup folder (default: latest)")
    bk.set_defaults(func=cmd_backup)

    case_cli.register(sub)

    c = sub.add_parser("compose", help="pass-through to docker compose for this stack (volume deletion refused)")
    c.add_argument("compose_args", nargs=argparse.REMAINDER)
    c.set_defaults(func=cmd_compose)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (deploy.DeployError, detections.DetectionError, scenarios.ScenarioError, cases.CaseError, backup.BackupError,
            ServiceError, OSError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as exc:
        print(f"error: command failed with exit code {exc.returncode}: {exc.cmd[0]} {exc.cmd[1] if len(exc.cmd) > 1 else ''}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
