import socket

import pytest

from aegissoc.health import PASS, WARNING
from aegissoc.preflight import check_ports, parse_version, parse_wslconfig_memory, port_bindable


@pytest.mark.parametrize("text,expected", [("2.40.3", (2, 40, 3)), ("v2.24.4-desktop.1", (2, 24, 4)), ("none", None)])
def test_parse_version(text, expected):
    assert parse_version(text) == expected


def test_parse_wslconfig_memory_reads_wsl2_section_only():
    text = "[experimental]\nmemory=1GB\n[wsl2]\n# memory=2GB\nprocessors=6\nmemory = 10GB # cap\n"
    assert parse_wslconfig_memory(text) == "10GB"
    assert parse_wslconfig_memory("[wsl2]\nprocessors=2\n") is None


def test_check_ports_reports_busy_ports():
    settings = {"AEGIS_AGENT_BIND": "127.0.0.1", "AEGIS_DASHBOARD_PORT": "8443"}
    result = check_ports(settings, bindable=lambda h, p: p != 8443)
    assert result.status == WARNING and "127.0.0.1:8443" in result.detail
    assert check_ports(settings, bindable=lambda h, p: True).status == PASS


def test_port_bindable_detects_listener():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        assert not port_bindable("127.0.0.1", listener.getsockname()[1])
