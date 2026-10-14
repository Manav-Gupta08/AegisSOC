#!/usr/bin/env bash
# Installs and enrolls a pinned Wazuh agent on Debian/Ubuntu (including WSL2 Ubuntu with systemd).
# Usage: sudo ./install-wazuh-agent.sh [--manager 127.0.0.1] [--name <agent-name>] [--version 4.14.8-1]
# The enrollment password is read from WAZUH_REGISTRATION_PASSWORD or prompted (never passed as an argument).
set -euo pipefail

MANAGER="127.0.0.1"
AGENT_NAME="$(hostname)-linux"
AGENT_VERSION="4.14.8-1"
WAZUH_KEY_URL="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
WAZUH_KEY_FPR="0DCFCA5547B19D2A6099506096B3EE5F29111145"
KEYRING="/usr/share/keyrings/wazuh.gpg"
SOURCE_LIST="/etc/apt/sources.list.d/wazuh.list"

die() { echo "error: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manager) MANAGER="$2"; shift 2 ;;
    --name) AGENT_NAME="$2"; shift 2 ;;
    --version) AGENT_VERSION="$2"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root (sudo)"
[[ "$AGENT_NAME" =~ ^[A-Za-z0-9._-]{1,128}$ ]] || die "invalid agent name"
[[ "$(cat /proc/1/comm)" == "systemd" ]] || die "systemd is not PID 1; on WSL add [boot] systemd=true to /etc/wsl.conf and run 'wsl --shutdown'"

for port in 1514 1515; do
  timeout 5 bash -c "</dev/tcp/${MANAGER}/${port}" 2>/dev/null \
    || die "cannot reach ${MANAGER}:${port}; see docs/deployment.md (WSL2 reachability)"
done
echo "[ok] manager ports reachable at ${MANAGER}"

if [[ -z "${WAZUH_REGISTRATION_PASSWORD:-}" ]]; then
  read -rsp "Enrollment password (WAZUH_ENROLLMENT_PASSWORD from .env): " WAZUH_REGISTRATION_PASSWORD
  echo
fi
[[ -n "$WAZUH_REGISTRATION_PASSWORD" ]] || die "empty enrollment password"

if dpkg-query -W -f='${Status}' wazuh-agent 2>/dev/null | grep -q "install ok installed"; then
  echo "[skip] wazuh-agent already installed ($(dpkg-query -W -f='${Version}' wazuh-agent)); not reinstalling"
else
  apt-get update -qq
  apt-get install -y -qq curl gnupg apt-transport-https >/dev/null

  tmpkey="$(mktemp)"
  trap 'rm -f "$tmpkey"' EXIT
  curl -fsSL "$WAZUH_KEY_URL" -o "$tmpkey"
  actual_fpr="$(gpg --show-keys --with-colons "$tmpkey" 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')"
  [[ "$actual_fpr" == "$WAZUH_KEY_FPR" ]] || die "Wazuh GPG key fingerprint mismatch (got '${actual_fpr}')"
  gpg --dearmor <"$tmpkey" >"$KEYRING.tmp" && mv "$KEYRING.tmp" "$KEYRING" && chmod 644 "$KEYRING"
  echo "deb [signed-by=${KEYRING}] https://packages.wazuh.com/4.x/apt/ stable main" >"$SOURCE_LIST"
  apt-get update -qq

  WAZUH_MANAGER="$MANAGER" \
  WAZUH_REGISTRATION_SERVER="$MANAGER" \
  WAZUH_REGISTRATION_PASSWORD="$WAZUH_REGISTRATION_PASSWORD" \
  WAZUH_AGENT_NAME="$AGENT_NAME" \
    apt-get install -y -qq "wazuh-agent=${AGENT_VERSION}"
  # Prevent unplanned upgrades; the agent must not be newer than the manager.
  apt-mark hold wazuh-agent >/dev/null
fi
unset WAZUH_REGISTRATION_PASSWORD

systemctl daemon-reload
systemctl enable --now wazuh-agent

for _ in $(seq 1 30); do
  [[ -s /var/ossec/etc/client.keys ]] && break
  sleep 2
done
[[ -s /var/ossec/etc/client.keys ]] || die "agent did not obtain a key; check /var/ossec/logs/ossec.log"
systemctl is-active --quiet wazuh-agent || die "wazuh-agent service is not active"
echo "[ok] agent '${AGENT_NAME}' enrolled and running; confirm with 'aegis health' (agents check)"
