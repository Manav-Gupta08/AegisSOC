#!/usr/bin/env bash
# Installs auditd and the AegisSOC audit rules on Debian/Ubuntu (including WSL2 with systemd).
# Usage: sudo ./configure-auditd.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_SRC="${SCRIPT_DIR}/audit/aegissoc.rules"
RULES_DST="/etc/audit/rules.d/aegissoc.rules"

die() { echo "error: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo)"
[[ -f "$RULES_SRC" ]] || die "rules file not found: $RULES_SRC"
[[ "$(cat /proc/1/comm)" == "systemd" ]] || die "systemd is not PID 1"

if ! dpkg-query -W -f='${Status}' auditd 2>/dev/null | grep -q "install ok installed"; then
  apt-get update -qq
  apt-get install -y -qq auditd >/dev/null
fi

# WSL2 distros run outside the kernel's initial namespace, where audit netlink is refused.
if ! auditctl -s >/dev/null 2>&1; then
  systemctl disable --now auditd >/dev/null 2>&1 || true
  die "kernel audit is not accessible from this system (expected on WSL2); auditd disabled, FIM falls back to real-time"
fi

install -m 0640 -o root -g root "$RULES_SRC" "$RULES_DST"
systemctl enable --now auditd
augenrules --load >/dev/null

auditctl -s | grep -q "^enabled 1" || die "kernel audit is not enabled (auditctl -s)"
loaded="$(auditctl -l | grep -c 'key=audit-wazuh-c' || true)"
[[ "$loaded" -ge 1 ]] || die "AegisSOC audit rules are not loaded"
[[ -f /var/log/audit/audit.log ]] || die "/var/log/audit/audit.log missing"

echo "[ok] auditd active, ${loaded} AegisSOC rule(s) loaded"
echo "Restart the agent so whodata FIM can register its audit rules: systemctl restart wazuh-agent"
