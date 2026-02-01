#!/usr/bin/env bash
set -euo pipefail

# Dynu DDNS updater via IP Update Protocol + systemd timer (every 5 minutes)
# Stores only SHA-256 hash of the IP update password on disk.
# Uses server-side IP detection (no myip parameter).
#
# Vendor refs:
# - IP Update Protocol endpoint and hashed password support: https://www.dynu.com/DynamicDNS/IP-Update-Protocol
# - cURL notes: https://www.dynu.com/DynamicDNS/IPUpdateClient/cURL

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "ERROR: run as root. Example: sudo $0"
    exit 1
  fi
}

require_tools() {
  local missing=0
  for t in curl sha256sum install systemctl; do
    if ! command -v "$t" >/dev/null 2>&1; then
      echo "ERROR: missing required tool: $t"
      missing=1
    fi
  done
  if [[ $missing -ne 0 ]]; then
    echo "Install missing tools, then re-run."
    exit 1
  fi
}

read_inputs() {
  local u h p
  read -r -p "Dynu username: " u
  read -r -p "Hostname to update (FQDN): " h
  read -r -s -p "Dynu IP-update password (will be hashed, not stored in cleartext): " p
  echo

  if [[ -z "$u" || -z "$h" || -z "$p" ]]; then
    echo "ERROR: username, hostname, and password are required."
    exit 1
  fi

  DYNU_USERNAME="$u"
  DYNU_HOSTNAME="$h"
  DYNU_PASS_SHA256="$(printf '%s' "$p" | sha256sum | awk '{print $1}')"
}

write_config() {
  install -d -m 0755 /etc/dynu
  cat > /etc/dynu/dynu-ddns.conf <<EOF
# Dynu DDNS updater config (hash-only)
DYNU_ENDPOINT="https://api.dynu.com/nic/update"
DYNU_USERNAME="${DYNU_USERNAME}"
DYNU_HOSTNAME="${DYNU_HOSTNAME}"
DYNU_PASSWORD_SHA256="${DYNU_PASS_SHA256}"
EOF
  chmod 0600 /etc/dynu/dynu-ddns.conf
}

write_updater() {
  cat > /usr/local/sbin/dynu-ddns-update.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# Load config
# shellcheck disable=SC1091
. /etc/dynu/dynu-ddns.conf

# Server-side IP detection: do NOT pass myip.
# Dynu documentation notes to wrap URL in double quotes so params are sent fully by curl.
resp="$(curl --silent --show-error --fail \
  "${DYNU_ENDPOINT}?hostname=${DYNU_HOSTNAME}&username=${DYNU_USERNAME}&password=${DYNU_PASSWORD_SHA256}")"

ts="$(date -Is)"
echo "${ts} dynu-ddns: ${resp}"
EOF
  chmod 0755 /usr/local/sbin/dynu-ddns-update.sh
}

write_systemd_units() {
  cat > /etc/systemd/system/dynu-ddns-update.service <<'EOF'
[Unit]
Description=Dynu DDNS update (explicit hostname) via IP Update Protocol
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/dynu-ddns-update.sh
EOF

  cat > /etc/systemd/system/dynu-ddns-update.timer <<'EOF'
[Unit]
Description=Run Dynu DDNS update every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now dynu-ddns-update.timer
}

main() {
  require_root
  require_tools
  read_inputs
  write_config
  write_updater
  write_systemd_units

  echo "OK: configured Dynu DDNS updates."
  echo "Config file: /etc/dynu/dynu-ddns.conf (0600, SHA-256 hash only)"
  echo "Timer: dynu-ddns-update.timer (every 5 minutes)"
  echo "Check timer: systemctl status dynu-ddns-update.timer"
  echo "View logs: journalctl -u dynu-ddns-update.service --no-pager -n 50"
  echo "Run once now: /usr/local/sbin/dynu-ddns-update.sh"
}

main "$@"
