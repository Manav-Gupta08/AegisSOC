import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from aegissoc.agentconfig import (
    AgentConfigError, GroupConfig, apply_group_configs, group_for_platform, load_group_configs, validate_group_config,
)
from aegissoc.settings import Paths

ROOT = Path(__file__).resolve().parents[2]


def test_repository_group_configs_are_valid():
    names = {c.name for c in load_group_configs(Paths(ROOT))}
    assert {"linux", "windows"} <= names


@pytest.mark.parametrize("text,match", [
    ("<agent_config><localfile>", "well-formed"),
    ("<ossec_config/>", "root element"),
    ("<agent_config><remote/></agent_config>", "unsupported"),
    ("<agent_config><localfile><location>x</location></localfile></agent_config>", "log_format"),
])
def test_invalid_group_configs_rejected(text, match):
    with pytest.raises(AgentConfigError, match=match):
        validate_group_config("g", text)


def test_invalid_group_name_rejected():
    with pytest.raises(AgentConfigError):
        validate_group_config("../etc", "<agent_config/>")


@pytest.mark.parametrize("platform,group", [("windows", "windows"), ("ubuntu", "linux"), ("centos", "linux"), (None, None)])
def test_group_for_platform(platform, group):
    assert group_for_platform(platform) == group


class Api:
    def __init__(self, groups, agents):
        self.groups, self.agents, self.calls = groups, agents, []

    def affected_items(self, path, params=None):
        return {"/groups": self.groups, "/agents": self.agents}[path]

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        return {"data": {}}


def test_apply_creates_groups_uploads_and_assigns():
    api = Api([{"name": "default"}], [
        {"id": "000", "name": "manager", "os": {"platform": "amzn"}},
        {"id": "001", "name": "lnx", "os": {"platform": "ubuntu"}, "group": ["default"]},
        {"id": "002", "name": "win", "os": {"platform": "windows"}, "group": ["default", "windows"]},
    ])
    cfgs = [GroupConfig("linux", Path("linux/agent.conf"), "<agent_config/>"),
            GroupConfig("windows", Path("windows/agent.conf"), "<agent_config/>")]
    result = apply_group_configs(api, cfgs, log=lambda m: None)
    assert ("POST", "/groups", {"json": {"group_id": "linux"}}) in api.calls
    assert any(m == "PUT" and p == "/groups/linux/configuration" and k["headers"]["Content-Type"] == "application/xml"
               for m, p, k in api.calls)
    assert result["assigned"] == {"lnx": "linux"}
    assert not any(p.startswith("/agents/000") for _, p, _ in api.calls)


def test_sysmon_config_is_well_formed_and_scoped():
    root = ET.parse(ROOT / "deployment" / "endpoints" / "windows" / "sysmon-aegis.xml").getroot()
    assert root.tag == "Sysmon"
    filtering = root.find("EventFiltering")
    for disabled in ("ImageLoad", "DnsQuery", "FileDelete", "PipeEvent"):
        assert filtering.find(f".//{disabled}") is None, f"{disabled} is intentionally disabled for volume"


def test_audit_rules_use_wazuh_known_keys_only():
    text = (ROOT / "deployment" / "endpoints" / "linux" / "audit" / "aegissoc.rules").read_text()
    rules = [l for l in text.splitlines() if l.strip() and not l.startswith("#")]
    assert rules
    keys = {re.search(r"-k (\S+)", r).group(1) for r in rules}
    assert keys <= {"audit-wazuh-w", "audit-wazuh-r", "audit-wazuh-a", "audit-wazuh-x", "audit-wazuh-c"}
    assert all("-S execve" not in r or "auid>=1000" in r for r in rules), "execve auditing must be scoped to user sessions"
