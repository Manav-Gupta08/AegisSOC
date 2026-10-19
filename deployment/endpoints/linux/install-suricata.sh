#!/usr/bin/env bash
# Installs Suricata in IDS mode on a Debian/Ubuntu Wazuh agent (optional network sensor, Profile B).
# Usage: sudo ./install-suricata.sh --interface <iface>
# Monitors one interface with af-packet (passive; never inline, never drops traffic), loads the ET Open
# ruleset with suricata-update, and writes alerts to /var/log/suricata/eve.json for the Wazuh agent.
set -euo pipefail

IFACE=""
EVE="/var/log/suricata/eve.json"
DROPIN_DIR="/etc/systemd/system/suricata.service.d"

die() { echo "error: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --interface) IFACE="${2:-}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root (sudo)"
[[ "$IFACE" =~ ^[A-Za-z0-9._-]{1,15}$ ]] || die "--interface <name> is required (see: ip -br link)"
[[ -d "/sys/class/net/${IFACE}" ]] || die "interface ${IFACE} does not exist"
[[ "$(cat /proc/1/comm)" == "systemd" ]] || die "systemd is not PID 1"
systemctl is-active --quiet wazuh-agent || die "wazuh-agent is not running; install and enroll the agent first"

if ! command -v suricata >/dev/null; then
  apt-get update -qq
  apt-get install -y -qq suricata >/dev/null
fi
if ! command -v suricata-update >/dev/null; then
  apt-get install -y -qq suricata-update >/dev/null
fi
echo "[ok] $(suricata -V)"

# The packaged unit starts af-packet on the interface from suricata.yaml; pin it to the chosen interface instead
# of editing the packaged configuration.
install -d -m 0755 "$DROPIN_DIR"
cat >"${DROPIN_DIR}/aegissoc.conf" <<EOF
[Service]
ExecStart=
ExecStart=/usr/bin/suricata -D --af-packet=${IFACE} -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid
EOF
systemctl daemon-reload

suricata-update --no-test >/dev/null
suricata --dump-config 2>/dev/null | grep -q '^default-rule-path = /var/lib/suricata/rules$' \
  || die "suricata.yaml default-rule-path is not /var/lib/suricata/rules, so suricata-update rules would not load"
suricata -T -c /etc/suricata/suricata.yaml >/dev/null || die "suricata -T rejected the configuration or rules"
grep -rqs 'sid:2100498;' /var/lib/suricata/rules/ || die "ET Open signature 2100498 not found after suricata-update"

systemctl enable --now suricata >/dev/null
systemctl restart suricata
for _ in $(seq 1 30); do
  [[ -s "$EVE" ]] && break
  sleep 2
done
systemctl is-active --quiet suricata || die "suricata service is not active (journalctl -u suricata)"
[[ -s "$EVE" ]] || die "${EVE} is empty or missing; check the eve-log output in /etc/suricata/suricata.yaml"

echo "[ok] Suricata monitoring ${IFACE}; alerts in ${EVE}"
echo "Next, on the stack host: aegis agent-config apply && aegis agent-config assign --agent <this agent> --group network-sensor"
