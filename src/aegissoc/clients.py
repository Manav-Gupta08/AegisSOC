from __future__ import annotations

from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter

MANAGER_TLS_NAME = "wazuh.manager"
INDEXER_TLS_NAME = "wazuh.indexer"


class _AssertHostnameAdapter(HTTPAdapter):
    """Verifies the certificate chain against the stack CA and checks the cert's service name.

    Services are reached via 127.0.0.1, but their certificates are issued for container
    hostnames; this keeps full verification without editing the hosts file.
    """

    def __init__(self, tls_hostname: str, **kwargs: Any) -> None:
        self._tls_hostname = tls_hostname
        super().__init__(**kwargs)

    def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
        # Send SNI for the service name too; the indexer drops TLS handshakes that lack it.
        kwargs["assert_hostname"] = self._tls_hostname
        kwargs["server_hostname"] = self._tls_hostname
        super().init_poolmanager(*args, **kwargs)


class ServiceError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def make_session(ca_file: Path, tls_hostname: str) -> requests.Session:
    if not ca_file.is_file():
        raise FileNotFoundError(f"CA bundle not found: {ca_file}")
    session = requests.Session()
    session.verify = str(ca_file)
    session.mount("https://", _AssertHostnameAdapter(tls_hostname))
    return session


class WazuhApi:
    def __init__(self, session: requests.Session, base_url: str, timeout: float = 15.0) -> None:
        self._session = session
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._token: str | None = None

    def authenticate(self, username: str, password: str) -> None:
        resp = self._session.post(
            f"{self._base}/security/user/authenticate",
            auth=(username, password),
            timeout=self._timeout,
        )
        if resp.status_code != 200:
            raise ServiceError(f"Wazuh API authentication failed for {username!r}: HTTP {resp.status_code}", resp.status_code)
        self._token = resp.json()["data"]["token"]

    def request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        if self._token is None:
            raise ServiceError("Wazuh API client is not authenticated")
        headers = {**kwargs.pop("headers", {}), "Authorization": f"Bearer {self._token}"}
        resp = self._session.request(method, f"{self._base}{path}", headers=headers, timeout=self._timeout, **kwargs)
        if resp.status_code >= 400:
            raise ServiceError(f"Wazuh API {method} {path}: HTTP {resp.status_code}", resp.status_code)
        body = resp.json()
        if body.get("error", 0) not in (0, None):
            raise ServiceError(f"Wazuh API {method} {path}: error {body.get('error')}: {body.get('message', '')}")
        return body

    def affected_items(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        return self.request("GET", path, params=params)["data"]["affected_items"]


class Indexer:
    def __init__(self, session: requests.Session, base_url: str, username: str, password: str, timeout: float = 15.0) -> None:
        self._session = session
        self._base = base_url.rstrip("/")
        self._auth = (username, password)
        self._timeout = timeout

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        resp = self._session.request(method, f"{self._base}{path}", auth=self._auth, timeout=self._timeout, **kwargs)
        if resp.status_code >= 400:
            raise ServiceError(f"Indexer {method} {path}: HTTP {resp.status_code}", resp.status_code)
        return resp.json()
