from __future__ import annotations

import time
from typing import Callable

from .clients import INDEXER_TLS_NAME, MANAGER_TLS_NAME, Indexer, ServiceError, WazuhApi, make_session
from .settings import Context

INDEXER_URL = "https://127.0.0.1:9200"
API_URL = "https://127.0.0.1:55000"
READER_INDEXER_USER = "aegis_reader"
READER_INDEXER_ROLE = "aegis_monitor"
READER_API_USER = "aegis-reader"
READONLY_API_ROLE = "readonly"
WAZUH_INDEX_PATTERNS = ["wazuh-alerts-*", "wazuh-archives-*", "wazuh-monitoring-*", "wazuh-statistics-*"]
RETENTION_POLICY_ID = "aegis-alerts-retention"


def retention_policy(days: int) -> dict:
    if not 1 <= days <= 3650:
        raise ValueError("AEGIS_RETENTION_DAYS must be between 1 and 3650")
    return {"policy": {
        "description": f"AegisSOC: delete wazuh-alerts indices {days} days after creation",
        "default_state": "hot",
        "states": [
            {"name": "hot", "actions": [], "transitions": [{"state_name": "delete", "conditions": {"min_index_age": f"{days}d"}}]},
            {"name": "delete", "actions": [{"delete": {}}], "transitions": []},
        ],
        "ism_template": [{"index_patterns": ["wazuh-alerts-*"], "priority": 100}],
    }}


def provision_retention(admin: Indexer, days: int, superadmin: Indexer | None = None) -> dict:
    """Create/update the ISM policy and attach it to existing alert indices. Idempotent."""
    body = retention_policy(days)
    path = f"/_plugins/_ism/policies/{RETENTION_POLICY_ID}"
    try:
        current = admin.request("GET", path)
        params = {"if_seq_no": current["_seq_no"], "if_primary_term": current["_primary_term"]}
        admin.request("PUT", path, params=params, json=body)
    except ServiceError as exc:
        if exc.status_code != 404:
            raise
        admin.request("PUT", path, json=body)
    # Already-managed indices are reported as failures by this API; that is expected on re-runs.
    added = admin.request("POST", "/_plugins/_ism/add/wazuh-alerts-*", json={"policy_id": RETENTION_POLICY_ID})
    # ISM creates system indices with 1 replica, which a single node can never assign (cluster stays yellow).
    (superadmin or admin).request("PUT", "/.opendistro-ism-*,.opendistro-job-scheduler-lock/_settings",
                                  params={"expand_wildcards": "all"}, json={"index": {"number_of_replicas": 0}})
    return added


def indexer_client(ctx: Context, username: str, password: str) -> Indexer:
    session = make_session(ctx.paths.certs_dir(ctx.lock) / "root-ca.pem", INDEXER_TLS_NAME)
    return Indexer(session, INDEXER_URL, username, password)


def indexer_superadmin(ctx: Context) -> Indexer:
    """Client-certificate (admin.pem) access; required only to change protected system indices."""
    certs = ctx.paths.certs_dir(ctx.lock)
    session = make_session(certs / "root-ca.pem", INDEXER_TLS_NAME, client_cert=(certs / "admin.pem", certs / "admin-key.pem"))
    return Indexer(session, INDEXER_URL, "admin", ctx.secret("INDEXER_ADMIN_PASSWORD"))


def api_client(ctx: Context) -> WazuhApi:
    # The override serves the API with wazuh.manager.pem, which the stack root CA signs.
    session = make_session(ctx.paths.certs_dir(ctx.lock) / "root-ca.pem", MANAGER_TLS_NAME)
    return WazuhApi(session, API_URL)


def provision_indexer(admin: Indexer, reader_password: str) -> None:
    admin.request("PUT", f"/_plugins/_security/api/roles/{READER_INDEXER_ROLE}", json={
        "description": "AegisSOC read-only monitoring",
        "cluster_permissions": ["cluster_monitor"],
        "index_permissions": [{"index_patterns": WAZUH_INDEX_PATTERNS, "allowed_actions": ["read"]}],
    })
    admin.request("PUT", f"/_plugins/_security/api/internalusers/{READER_INDEXER_USER}", json={
        "password": reader_password,
        "opendistro_security_roles": [READER_INDEXER_ROLE],
        "description": "AegisSOC read-only tooling account",
    })


def _user_id(api: WazuhApi, username: str) -> int | None:
    for user in api.affected_items("/security/users", {"limit": 500}):
        if user.get("username") == username:
            return int(user["id"])
    return None


def _set_password(api: WazuhApi, user_id: int, username: str, password: str,
                  verify_login: Callable[[str, str], bool], sleep: Callable[[float], None] = time.sleep) -> None:
    if verify_login(username, password):
        return
    try:
        api.request("PUT", f"/security/users/{user_id}", json={"password": password})
    except ServiceError as exc:
        if exc.status_code != 500:
            raise
        # The API can time out (HTTP 500) while still committing the change; confirm once it settles.
        for _ in range(4):
            sleep(5)
            if verify_login(username, password):
                return
        raise


def provision_api(api: WazuhApi, wazuh_user_password: str, reader_password: str,
                  verify_login: Callable[[str, str], bool], sleep: Callable[[float], None] = time.sleep) -> None:
    wazuh_id = _user_id(api, "wazuh")
    if wazuh_id is not None:
        _set_password(api, wazuh_id, "wazuh", wazuh_user_password, verify_login, sleep)

    reader_id = _user_id(api, READER_API_USER)
    if reader_id is None:
        try:
            created = api.request("POST", "/security/users", json={"username": READER_API_USER, "password": reader_password})
            reader_id = int(created["data"]["affected_items"][0]["id"])
        except ServiceError as exc:
            reader_id = _user_id(api, READER_API_USER) if exc.status_code == 500 else None
            if reader_id is None:
                raise
    else:
        _set_password(api, reader_id, READER_API_USER, reader_password, verify_login, sleep)

    roles = [r for r in api.affected_items("/security/roles", {"search": READONLY_API_ROLE}) if r.get("name") == READONLY_API_ROLE]
    if not roles:
        raise ServiceError(f"Wazuh API role {READONLY_API_ROLE!r} not found")
    reader = next((u for u in api.affected_items("/security/users", {"limit": 500}) if int(u["id"]) == reader_id), {})
    if roles[0]["id"] not in (reader.get("roles") or []):
        api.request("POST", f"/security/users/{reader_id}/roles", params={"role_ids": roles[0]["id"]})


def provision(ctx: Context, log: Callable[[str], None] = print) -> None:
    log("Indexer: creating role aegis_monitor and user aegis_reader")
    admin = indexer_client(ctx, "admin", ctx.secret("INDEXER_ADMIN_PASSWORD"))
    provision_indexer(admin, ctx.secret("INDEXER_READER_PASSWORD"))

    days = ctx.int_setting("AEGIS_RETENTION_DAYS")
    added = provision_retention(admin, days, superadmin=indexer_superadmin(ctx))
    log(f"Indexer: retention policy {RETENTION_POLICY_ID} ({days} days); newly attached indices: {added.get('updated_indices', 0)}")

    log("Wazuh API: rotating default 'wazuh' user and creating read-only 'aegis-reader'")
    api = api_client(ctx)
    api.authenticate("wazuh-wui", ctx.secret("WAZUH_API_WUI_PASSWORD"))
    def verify_login(username: str, password: str) -> bool:
        try:
            api_client(ctx).authenticate(username, password)
            return True
        except ServiceError:
            return False

    provision_api(api, ctx.secret("WAZUH_API_WAZUH_PASSWORD"), ctx.secret("WAZUH_API_READER_PASSWORD"), verify_login)

    log("Verifying reader accounts")
    indexer_client(ctx, READER_INDEXER_USER, ctx.secret("INDEXER_READER_PASSWORD")).request("GET", "/_cluster/health")
    reader = api_client(ctx)
    reader.authenticate(READER_API_USER, ctx.secret("WAZUH_API_READER_PASSWORD"))
    reader.affected_items("/agents", {"limit": 1})
    log("Provisioning complete")
