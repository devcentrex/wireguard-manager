#!/usr/bin/env bash
set -euo pipefail

# wg-dynu-config.sh
#
# Configure Dynu IP Update Client (Linux) by writing:
#   /usr/share/dynu-ip-update-client/appsettings.json
#
# Vendor reference:
#   https://www.dynu.com/DynamicDNS/IPUpdateClient/Linux
#
# Behavior:
# - Updates hostnames via Dynu "Group" selection (Linux client uses Group, not a direct hostname field).
# - We derive a Dynu Group name from the provided FQDN using only [a-zA-Z0-9].
# - PollInterval is fixed at 300 seconds (5 minutes).
# - ConnectionType is DETECTIPONSERVERSIDE (Dynu detects external IP automatically).
# - Stores only MD5Password in appsettings.json; Password is left empty.
#
# IMPORTANT:
# You must create a Dynu Group with the derived name in Dynu Control Panel
# and assign your hostname (FQDN) to that group. Then the Linux client will
# update only hostnames in that group.

APPSETTINGS_PATH="/usr/share/dynu-ip-update-client/appsettings.json"
SERVICE_NAME="dynu-ip-update-client.service"

usage() {
  cat <<'EOF'
wg-dynu-config.sh - configure Dynu Linux IP Update Client (appsettings.json)

Usage:
  sudo ./wg-dynu-config.sh --hostname vpn.example.net [--username dynu] [--ipv6 true|false] [--loglevel DETAILED|NORMAL]
  Password options (choose exactly one):
    1. --md5 <md5hash>          Use provided MD5 hash directly (32 hex chars).
    2. --password <plaintext>   Plaintext password is accepted via CLI and converted to MD5.
    3. (no password flag)       Script will prompt securely and convert to MD5.

Options:
  --hostname    FQDN you want to update (required). Used to derive Group.
  --username    Dynu account username. Default: dynu
  --md5         Password MD5 hash (32 hex chars).
  --password    Plaintext password (will be hashed to MD5; NOT stored in cleartext).
  --ipv6        true or false. Default: false
  --loglevel    DETAILED or NORMAL. Default: DETAILED
  -h, --help    Show help

Examples:
  1) Provide MD5 directly:
     sudo ./wg-dynu-config.sh --username dynu --hostname vpn.example.net --md5 4bc372104b580fc150727e51eca1b674

  2) Provide plaintext via CLI (script derives MD5):
     sudo ./wg-dynu-config.sh --username dynu --hostname vpn.example.net --password 'YourSecret'

  3) Prompt for password (script derives MD5):
     sudo ./wg-dynu-config.sh --username dynu --hostname vpn.example.net
EOF
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "ERROR: run as root. Example: sudo $0 ..."
    exit 1
  fi
}

require_tools() {
  local missing=0
  for t in md5sum systemctl date tr awk; do
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

derive_group_from_hostname() {
  # Group supports only [a-zA-Z0-9]
  # Derivation:
  # - Strip all non-alphanumeric
  # - If empty -> DYNU
  # - Truncate to 32 chars to keep names reasonable
  local cleaned
  cleaned="$(printf '%s' "${DYNU_HOSTNAME}" | tr -cd '[:alnum:]')"
  if [[ -z "$cleaned" ]]; then
    cleaned="DYNU"
  fi
  GROUP_NAME="${cleaned:0:32}"
}

is_valid_md5() {
  [[ "$1" =~ ^[a-fA-F0-9]{32}$ ]]
}

resolve_md5_password() {
  # Supports exactly one of:
  # - --md5
  # - --password
  # - prompt
  local has_md5="false"
  local has_pw="false"

  if [[ -n "${DYNU_MD5:-}" ]]; then
    has_md5="true"
  fi
  if [[ -n "${DYNU_PASSWORD:-}" ]]; then
    has_pw="true"
  fi

  if [[ "$has_md5" == "true" && "$has_pw" == "true" ]]; then
    echo "ERROR: use only one of --md5 or --password"
    exit 1
  fi

  if [[ "$has_md5" == "true" ]]; then
    if ! is_valid_md5 "${DYNU_MD5}"; then
      echo "ERROR: --md5 must be exactly 32 hex characters"
      exit 1
    fi
    DYNU_MD5_PASSWORD="${DYNU_MD5,,}"  # normalize to lowercase
    return
  fi

  if [[ "$has_pw" == "true" ]]; then
    DYNU_MD5_PASSWORD="$(printf '%s' "${DYNU_PASSWORD}" | md5sum | awk '{print $1}')"
    return
  fi

  # Prompt securely
  local p1
  read -r -s -p "Dynu IP-update password (will be stored as MD5 only): " p1
  echo
  if [[ -z "$p1" ]]; then
    echo "ERROR: password is required"
    exit 1
  fi
  DYNU_MD5_PASSWORD="$(printf '%s' "$p1" | md5sum | awk '{print $1}')"
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
    echo "Install Dynu client first (dynu-ip-update-client package)."
    exit 1
  fi

  # JSON schema matches Dynu Linux documentation example.
  cat > "${APPSETTINGS_PATH}" <<EOF
{
  "Settings": {
    "Username": "${DYNU_USERNAME}",
    "Password": "",
    "MD5Password": "${DYNU_MD5_PASSWORD}",
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
  DYNU_USERNAME="dynu"
  DYNU_HOSTNAME=""
  DYNU_IPV6="false"
  DYNU_LOGLEVEL="DETAILED"

  DYNU_MD5=""
  DYNU_PASSWORD=""
  DYNU_MD5_PASSWORD=""
  GROUP_NAME=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --username) DYNU_USERNAME="${2:-}"; shift 2 ;;
      --hostname) DYNU_HOSTNAME="${2:-}"; shift 2 ;;
      --md5) DYNU_MD5="${2:-}"; shift 2 ;;
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
  derive_group_from_hostname
  resolve_md5_password
  backup_existing
  write_appsettings
  enable_restart_service

  echo "OK: Dynu Linux client configured."
  echo "1. appsettings: ${APPSETTINGS_PATH}"
  echo "2. Hostname requested: ${DYNU_HOSTNAME}"
  echo "3. Derived Group: ${GROUP_NAME}"
  echo "4. PollInterval: 300 seconds"
  echo "5. ConnectionType: DETECTIPONSERVERSIDE"
  echo
  echo "IMPORTANT:"
  echo "1. In Dynu Control Panel, create a group named '${GROUP_NAME}'."
  echo "2. Assign hostname '${DYNU_HOSTNAME}' to that group."
  echo
  echo "Service:"
  echo "1. Status: systemctl status ${SERVICE_NAME} -l"
  echo "2. Logs:   journalctl -u ${SERVICE_NAME} --no-pager -n 100"
}

main "$@"
