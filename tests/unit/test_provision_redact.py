from unittest.mock import Mock

import pytest

from aegissoc.clients import Indexer, ServiceError, WazuhApi, make_session
from aegissoc.provision import READER_API_USER, provision_api, provision_indexer
from aegissoc.redact import REDACTED, redact


def test_redact_nested_structures():
    data = {"a": "pw=Secret.1", "b": ["x Secret.1 y", {"c": "Secret.1"}], "n": 3}
    assert redact(data, ["Secret.1"]) == {"a": f"pw={REDACTED}", "b": [f"x {REDACTED} y", {"c": REDACTED}], "n": 3}


def test_redact_prefers_longest_secret_first():
    assert redact("abcdef", ["abc", "abcdef"]) == REDACTED


def test_redact_ignores_empty_secrets():
    assert redact("text", ["", None]) == "text"


def test_client_session_requires_ca_and_enables_service_hostname_verification(tmp_path):
    ca_file = tmp_path / "ca.pem"
    with pytest.raises(FileNotFoundError):
        make_session(ca_file, "wazuh.manager")
    ca_file.write_text("test certificate")
    session = make_session(ca_file, "wazuh.manager", (tmp_path / "client.pem", tmp_path / "client.key"))
    assert session.verify == str(ca_file)
    assert session.cert == (str(tmp_path / "client.pem"), str(tmp_path / "client.key"))
    adapter = session.get_adapter("https://127.0.0.1")
    assert adapter.poolmanager.connection_pool_kw["assert_hostname"] == "wazuh.manager"
    assert adapter.poolmanager.connection_pool_kw["server_hostname"] == "wazuh.manager"
    session.close()


def test_wazuh_api_authentication_and_request():
    session = Mock()
    session.post.return_value = Mock(status_code=200, json=Mock(return_value={"data": {"token": "test-token"}}))
    session.request.return_value = Mock(status_code=200, json=Mock(return_value={"data": {"affected_items": [{"id": "001"}]}}))
    api = WazuhApi(session, "https://127.0.0.1:55000/")
    with pytest.raises(ServiceError, match="not authenticated"):
        api.request("GET", "/agents")
    api.authenticate("reader", "test-password")
    assert api.affected_items("/agents", {"limit": 1}) == [{"id": "001"}]
    session.request.assert_called_once_with("GET", "https://127.0.0.1:55000/agents",
                                            headers={"Authorization": "Bearer test-token"}, timeout=15.0,
                                            params={"limit": 1})


@pytest.mark.parametrize("status,body,match", [
    (403, {}, "HTTP 403"),
    (200, {"error": 123, "message": "denied"}, "error 123: denied"),
])
def test_wazuh_api_rejects_http_and_api_errors(status, body, match):
    session = Mock()
    session.post.return_value = Mock(status_code=200, json=Mock(return_value={"data": {"token": "test-token"}}))
    session.request.return_value = Mock(status_code=status, json=Mock(return_value=body))
    api = WazuhApi(session, "https://127.0.0.1:55000")
    api.authenticate("reader", "test-password")
    with pytest.raises(ServiceError, match=match):
        api.request("GET", "/agents")


def test_wazuh_api_rejects_failed_authentication():
    session = Mock()
    session.post.return_value = Mock(status_code=401)
    with pytest.raises(ServiceError, match="HTTP 401") as error:
        WazuhApi(session, "https://127.0.0.1:55000").authenticate("reader", "test-password")
    assert error.value.status_code == 401


@pytest.mark.parametrize("status", [200, 403])
def test_indexer_request_success_and_error(status):
    session = Mock()
    session.request.return_value = Mock(status_code=status, json=Mock(return_value={"count": 1}))
    indexer = Indexer(session, "https://127.0.0.1:9200/", "reader", "test-password")
    if status == 200:
        assert indexer.request("GET", "/alerts") == {"count": 1}
    else:
        with pytest.raises(ServiceError, match="HTTP 403") as error:
            indexer.request("GET", "/alerts")
        assert error.value.status_code == 403
    session.request.assert_called_once_with("GET", "https://127.0.0.1:9200/alerts",
                                            auth=("reader", "test-password"), timeout=15.0)


class RecordingApi:
    """Synthetic Wazuh API stand-in that records calls."""

    def __init__(self, users, roles, fail=None):
        self.users, self.roles, self.calls, self.fail = users, roles, [], fail or {}

    def affected_items(self, path, params=None):
        return {"/security/users": self.users, "/security/roles": self.roles}[path]

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        if (method, path) in self.fail:
            raise ServiceError("timeout", self.fail[(method, path)])
        if method == "POST" and path == "/security/users":
            return {"data": {"affected_items": [{"id": 100}]}}
        return {"data": {}}


ALWAYS = lambda u, p: True  # noqa: E731
NEVER = lambda u, p: False  # noqa: E731


def test_provision_api_creates_reader_and_rotates_default_user():
    api = RecordingApi([{"id": 1, "username": "wazuh"}, {"id": 2, "username": "wazuh-wui"}],
                       [{"id": 2, "name": "readonly"}, {"id": 9, "name": "readonly_extra"}])
    provision_api(api, "New.Wazuh-Pass1", "Reader.Pass-1", NEVER)
    assert ("PUT", "/security/users/1", {"json": {"password": "New.Wazuh-Pass1"}}) in api.calls
    assert ("POST", "/security/users", {"json": {"username": READER_API_USER, "password": "Reader.Pass-1"}}) in api.calls
    assert ("POST", "/security/users/100/roles", {"params": {"role_ids": 2}}) in api.calls
    assert not any(p == "/security/users/2" for _, p, _ in api.calls), "must not modify wazuh-wui"


def test_provision_api_is_idempotent_for_existing_reader():
    api = RecordingApi([{"id": 1, "username": "wazuh"}, {"id": 7, "username": READER_API_USER}], [{"id": 2, "name": "readonly"}])
    provision_api(api, "a", "b", NEVER)
    assert not any(m == "POST" and p == "/security/users" for m, p, _ in api.calls)
    assert ("PUT", "/security/users/7", {"json": {"password": "b"}}) in api.calls


def test_existing_role_link_is_not_recreated():
    # Regression: re-running provision failed with "No link was created to user aegis-reader".
    api = RecordingApi([{"id": 1, "username": "wazuh"}, {"id": 7, "username": READER_API_USER, "roles": [2]}],
                       [{"id": 2, "name": "readonly"}])
    provision_api(api, "a", "b", ALWAYS)
    assert not any(p.endswith("/roles") for _, p, _ in api.calls)


def test_provision_api_fails_without_readonly_role():
    api = RecordingApi([{"id": 1, "username": "wazuh"}], [])
    with pytest.raises(ServiceError):
        provision_api(api, "a", "b", NEVER)


def test_password_timeout_accepted_when_login_confirms_change():
    # Regression: Wazuh API returned HTTP 500 (request timeout) after committing the password change.
    api = RecordingApi([{"id": 1, "username": "wazuh"}, {"id": 7, "username": READER_API_USER}],
                       [{"id": 2, "name": "readonly"}], fail={("PUT", "/security/users/1"): 500})
    attempts = {"wazuh": 0}

    def settles_later(user, pw):
        if user != "wazuh":
            return True
        attempts["wazuh"] += 1
        return attempts["wazuh"] >= 3

    provision_api(api, "a", "b", settles_later, sleep=lambda s: None)
    assert ("PUT", "/security/users/1", {"json": {"password": "a"}}) in api.calls
    assert ("POST", "/security/users/7/roles", {"params": {"role_ids": 2}}) in api.calls


def test_password_already_set_skips_update():
    api = RecordingApi([{"id": 1, "username": "wazuh"}, {"id": 7, "username": READER_API_USER}], [{"id": 2, "name": "readonly"}])
    provision_api(api, "a", "b", ALWAYS)
    assert not any(m == "PUT" for m, _, _ in api.calls)


def test_password_timeout_raises_when_change_not_applied():
    api = RecordingApi([{"id": 1, "username": "wazuh"}], [{"id": 2, "name": "readonly"}],
                       fail={("PUT", "/security/users/1"): 500})
    with pytest.raises(ServiceError):
        provision_api(api, "a", "b", NEVER, sleep=lambda s: None)


def test_non_timeout_errors_are_not_masked():
    api = RecordingApi([{"id": 1, "username": "wazuh"}], [{"id": 2, "name": "readonly"}],
                       fail={("PUT", "/security/users/1"): 403})
    with pytest.raises(ServiceError):
        provision_api(api, "a", "b", NEVER, sleep=lambda s: None)


def test_provision_indexer_role_is_read_only():
    calls = []

    class Idx:
        def request(self, method, path, **kwargs):
            calls.append((method, path, kwargs))

    provision_indexer(Idx(), "pw")
    role = calls[0][2]["json"]
    assert role["cluster_permissions"] == ["cluster_monitor"]
    assert all(p["allowed_actions"] == ["read"] for p in role["index_permissions"])
    assert calls[1][2]["json"]["opendistro_security_roles"] == ["aegis_monitor"]


def test_retention_policy_shape_and_bounds():
    from aegissoc.provision import retention_policy

    p = retention_policy(30)["policy"]
    assert p["states"][0]["transitions"][0]["conditions"] == {"min_index_age": "30d"}
    assert p["states"][1]["actions"] == [{"delete": {}}]
    assert p["ism_template"][0]["index_patterns"] == ["wazuh-alerts-*"]
    for bad in (0, 5000):
        with pytest.raises(ValueError):
            retention_policy(bad)


def test_provision_retention_creates_then_updates_with_concurrency_tokens():
    from aegissoc.provision import provision_retention

    class Idx:
        def __init__(self, exists):
            self.exists, self.calls = exists, []

        def request(self, method, path, **kw):
            self.calls.append((method, path, kw.get("params")))
            if method == "GET":
                if not self.exists:
                    raise ServiceError("missing", 404)
                return {"_seq_no": 7, "_primary_term": 1}
            return {"updated_indices": 2}

    new = Idx(exists=False)
    provision_retention(new, 30)
    assert [c[0] for c in new.calls] == ["GET", "PUT", "POST", "PUT"] and new.calls[1][2] is None
    assert new.calls[3][1].startswith("/.opendistro-ism-"), "ISM system indices must be set to 0 replicas (single node)"
    existing = Idx(exists=True)
    provision_retention(existing, 30)
    assert existing.calls[1][2] == {"if_seq_no": 7, "if_primary_term": 1}
