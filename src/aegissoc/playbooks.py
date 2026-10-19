"""Reviewed response playbooks. Action steps can only be simulated: AegisSOC never changes an endpoint."""
from __future__ import annotations

import hashlib
import ipaddress
import posixpath
import re
from pathlib import Path
from typing import Any, Callable

import yaml

from .detections import load_metadata

PLAYBOOK_ID = re.compile(r"^PB-\d{3}$")
LINUX_ACCOUNT = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
STEP_KINDS = {"manual", "action"}


class PlaybookError(ValueError):
    pass


def _account(value: str) -> str:
    if not LINUX_ACCOUNT.match(value) or value == "root":
        raise PlaybookError(f"invalid account {value!r}: expected a non-root Linux user name")
    return value


def _file(value: str) -> str:
    if not value.startswith("/") or posixpath.normpath(value) != value or any(c in value for c in "\0\n\r"):
        raise PlaybookError(f"invalid path {value!r}: expected a normalized absolute path")
    if value in ("/", "/etc", "/usr", "/bin", "/sbin", "/boot", "/var", "/home", "/root"):
        raise PlaybookError(f"refusing to target system directory {value!r}")
    return value


def _ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise PlaybookError(f"invalid IP address {value!r}") from exc
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise PlaybookError(f"refusing to block {value}: loopback, unspecified, and multicast addresses are excluded")
    return str(address)


# action -> (target validator or None when the target is the endpoint itself, simulation plan template)
ACTIONS: dict[str, tuple[Callable[[str], str] | None, str]] = {
    "isolate_host": (None, "on {endpoint}: block all network traffic except to the Wazuh manager"),
    "disable_account": (_account, "on {endpoint}: lock account {target} and expire it (usermod --lock --expiredate 1)"),
    "quarantine_file": (_file, "on {endpoint}: move {target} to a root-only quarantine directory, keeping it as evidence"),
    "block_ip": (_ip, "on {endpoint}: drop inbound and outbound traffic for {target}"),
}


def validate_playbook(data: Any, path: Path, rule_ids: set[int]) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise PlaybookError(f"{path.name}: must be a mapping")
    pid = str(data.get("id", ""))
    if not PLAYBOOK_ID.match(pid) or not path.name.startswith(pid):
        raise PlaybookError(f"{path.name}: id must match PB-NNN and prefix the file name")
    for key in ("title", "description", "applies_to_rules", "steps"):
        if not data.get(key):
            raise PlaybookError(f"{pid}: missing {key}")
    unknown = sorted({str(r) for r in data["applies_to_rules"]} - {str(r) for r in rule_ids})
    if unknown:
        raise PlaybookError(f"{pid}: applies_to_rules references unknown rules {unknown}")
    for number, step in enumerate(data["steps"], start=1):
        if not isinstance(step, dict) or step.get("kind") not in STEP_KINDS or not step.get("text"):
            raise PlaybookError(f"{pid}: step {number} needs kind ({sorted(STEP_KINDS)}) and text")
        if step["kind"] == "action" and step.get("action") not in ACTIONS:
            raise PlaybookError(f"{pid}: step {number} action must be one of {sorted(ACTIONS)}")
    data["_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return data


def load_playbooks(root: Path) -> dict[str, dict[str, Any]]:
    rule_ids = set(load_metadata(root))
    playbooks: dict[str, dict[str, Any]] = {}
    for path in sorted((root / "playbooks").glob("*.yml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise PlaybookError(f"{path.name}: invalid YAML: {exc}") from exc
        pb = validate_playbook(data, path, rule_ids)
        if pb["id"] in playbooks:
            raise PlaybookError(f"duplicate playbook id {pb['id']}")
        playbooks[pb["id"]] = pb
    return playbooks


def proposal(playbook: dict[str, Any], step: int, case: dict[str, Any], endpoint: str, target: str | None,
             purpose: str) -> dict[str, Any]:
    """Build a validated response-action proposal for a case. The case audit trail stores the result."""
    if not 1 <= step <= len(playbook["steps"]) or playbook["steps"][step - 1]["kind"] != "action":
        raise PlaybookError(f"{playbook['id']} step {step} is not an action step")
    case_rules = {a["rule_id"] for a in case["source_alerts"]}
    if not case_rules & {str(r) for r in playbook["applies_to_rules"]}:
        raise PlaybookError(f"{playbook['id']} applies to rules {playbook['applies_to_rules']}; "
                            f"the case's alerts are {sorted(case_rules) or 'none'}")
    if not purpose.strip():
        raise PlaybookError("a purpose is required")
    action = playbook["steps"][step - 1]["action"]
    check, _ = ACTIONS[action]
    if check is None:
        if target not in (None, endpoint):
            raise PlaybookError(f"{action} targets the endpoint itself; omit --target")
        target = endpoint
    elif target is None:
        raise PlaybookError(f"{action} needs --target")
    else:
        target = check(target)
    return {"playbook": playbook["id"], "playbook_sha256": playbook["_sha256"], "step": step,
            "action_type": action, "endpoint": endpoint, "target": target, "purpose": purpose.strip()}


def simulation_plan(action: dict[str, Any]) -> str:
    return ACTIONS[action["action_type"]][1].format(endpoint=action["endpoint"], target=action["target"])
