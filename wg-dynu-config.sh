#!/usr/bin/env bash
set -euo pipefail

# Configure Dynu IP Update Client (Linux) via /usr/share/dynu-ip-update-client/appsettings.json
# - Derives Group from FQDN using only [a-z A-Z 0-9]
# - Stores only MD5Password (Password left empty)
# - PollInterval=300 (5 min)
# - ConnectionType=DETECTIPONSERVERSIDE (auto-detect public IP)
#
# Ref: https://www.dynu.com/DynamicDNS/IPUpdateClient/Linux

APPSETTINGS_PATH="/usr/share/dynu-ip-update-client/appsettings.json"
SERVICE_NAME="dynu-ip-update-client.service"

usage() {
  cat <<'EOF'
Usage:
  sudo ./wg-dynu-config.sh --username USER --hostname FQDN [--password PASS] [--ipv6 true|false] [--loglevel DETAILED|NORMAL]

Options:
  --username    Dynu account username
  --hostname    FQDN you want to update (used to derive Group)
  --password    Dynu IP update password. If omitted, you will be prompted securely.
  --ipv6        Default: false
  --loglevel    Default: DETAILED
  -h, --help    Show help
EOF
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "ERROR: run as root."
    exit 1
  fi
}

require_tools() {
  local missing=0
  for t in md5sum systemctl date; do
    if ! command -v "$t" >/dev/null 2>&1; then
      echo "ERROR: missing tool: $t"
      missing=1
    fi
  done
  if [[ $missing -ne 0 ]]; then
    exit 1
  fi
}

validate_inputs() {
  if [[ -z "${DYNU_USERNAME:-}" ]]; then
    echo "ERROR: --username is required"
    exit 1
  fi
  if [[ -z "${DYNU_HOSTNAME:-}" ]]; then
    echo "ERROR: --hostname is required"
    exit 1
  fi
  if [[ "${DYNU_HOSTNAME}" =~ [[:space:]] ]]; then
    echo "ERROR: hostname contains whitespace"
    exit 1
  fi
  if [[ "${DYNU_HOSTNAME}" != *.* ]]; then
    echo "ERROR: hostname does not look like an FQDN"
    exit 1
  fi
  if [[ "${DYNU_IPV6}" != "true" && "${DYNU_IPV6}" != "false" ]]; then
    echo "ERROR: --ipv6 must be true or false"
    exit 1
  fi
  if [[ "${DYNU_LOGLEVEL}" != "DETAILED" && "${DYNU_LOGLEVEL}" != "NORMAL" ]]; then
    echo "ERROR: --loglevel must be DETAILED or NORMAL"
    exit 1
  fi
}

prompt_password_if_needed() {
  if [[ -z "${DYNU_PASSWORD:-}" ]]; then
    read -r -s -p "Dynu IP-update password (stored as MD5 only): " DYNU_PASSWORD
    echo
  fi
  if [[ -z "${DYNU_PASSWORD}" ]]; then
    echo "ERROR: password is required"
    exit 1
  fi
}

derive_group_from_hostname() {
  # Only allow [a-zA-Z0-9], as requested.
  # 1) Remove all non-alphanumerics
  # 2) If empty -> "DYNU"
  # 3) Truncate to 32 chars to avoid silly-length group names
  local cleaned
  cleaned="$(printf '%s' "${DYNU_HOSTNAME}" | tr -cd '[:alnum:]')"
  if [[ -z "$cleaned" ]]; then
    cleaned="DYNU"
  fi
  GROUP_NAME="${cleaned:0:32}"
}

backup_existing() {
  if [[ -f "${APPSETTINGS_PATH}" ]]; then
    local ts
    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    cp -a "${APPSETTINGS_PATH}" "${APPSETTINGS_PATH}.bak.${ts}"
  fi
}

write_appsettings() {
  if [[ ! -d "$(dirname "${APPSETTINGS_PATH}")" ]]; then
    echo "ERROR: directory does not exist: $(dirname "${APPSETTINGS_PATH}")"
    echo "Install the Dynu client package first."
    exit 1
  fi

  local md5
  md5="$(printf '%s' "${DYNU_PASSWORD}" | md5sum | awk '{print $1}')"

  cat > "${APPSETTINGS_PATH}" <<EOF
{
  "Settings": {
    "Username": "${DYNU_USERNAME}",
    "Password": "",
    "MD5Password": "${md5}",
    "Group": "${GROUP_NAME}",
    "PollInterval": 300,
    "Logging": "true",
    "LogLevel": "${DYNU_LOGLEVEL}",
    "IPv4": "true",
    "IPv6": "${DYNU_IPV6}",
    "ConnectionType": "DETECTIPONSERVERSIDE",
    "SpecifiedIPv4Address": "",
    "SpecifiedIPv6Address": "",
    "SpecifiedMACID": ""
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  }
}
EOF

  chmod 0600 "${APPSETTINGS_PATH}"
}

enable_restart_service() {
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
  systemctl restart "${SERVICE_NAME}"
}

main() {
  DYNU_USERNAME=""
  DYNU_HOSTNAME=""
  DYNU_PASSWORD=""
  DYNU_IPV6="false"
  DYNU_LOGLEVEL="DETAILED"
  GROUP_NAME=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --username) DYNU_USERNAME="${2:-}"; shift 2 ;;
      --hostname) DYNU_HOSTNAME="${2:-}"; shift 2 ;;
      --password) DYNU_PASSWORD="${2:-}"; shift 2 ;;
      --ipv6) DYNU_IPV6="${2:-}"; shift 2 ;;
      --loglevel) DYNU_LOGLEVEL="${2:-}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "ERROR: unknown argument: $1"; usage; exit 1 ;;
    esac
  done

  require_root
  require_tools
  validate_inputs
  prompt_password_if_needed
  derive_group_from_hostname
  backup_existing
  write_appsettings
  enable_restart_service

  echo "OK: Dynu client configured."
  echo "1. appsettings: ${APPSETTINGS_PATH}"
  echo "2. Hostname requested: ${DYNU_HOSTNAME}"
  echo "3. Derived Group: ${GROUP_NAME}"
  echo "4. PollInterval: 300 seconds"
  echo "5. ConnectionType: DETECTIPONSERVERSIDE"
  echo
  echo "IMPORTANT:"
  echo "Create a Dynu group named '${GROUP_NAME}' in Dynu Control Panel and assign '${DYNU_HOSTNAME}' to it."
  echo
  echo "Status: systemctl status ${SERVICE_NAME} -l"
  echo "Logs:   journalctl -u ${SERVICE_NAME} --no-pager -n 100"
}

main "$@"
