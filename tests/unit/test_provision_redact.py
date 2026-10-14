import pytest

from aegissoc.clients import ServiceError
from aegissoc.provision import READER_API_USER, provision_api, provision_indexer
from aegissoc.redact import REDACTED, redact


def test_redact_nested_structures():
    data = {"a": "pw=Secret.1", "b": ["x Secret.1 y", {"c": "Secret.1"}], "n": 3}
    assert redact(data, ["Secret.1"]) == {"a": f"pw={REDACTED}", "b": [f"x {REDACTED} y", {"c": REDACTED}], "n": 3}


def test_redact_prefers_longest_secret_first():
    assert redact("abcdef", ["abc", "abcdef"]) == REDACTED


def test_redact_ignores_empty_secrets():
    assert redact("text", ["", None]) == "text"


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
