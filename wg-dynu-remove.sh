#!/usr/bin/env bash
set -euo pipefail

# Uninstall Dynu IP Update Client (DEB) + remove configs

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "ERROR: run as root. Example: sudo $0"
    exit 1
  fi
}

disable_systemd_units() {
  # Stop/disable timer if present
  if systemctl list-unit-files | awk '{print $1}' | grep -qx "dynu-ddns-update.timer"; then
    systemctl disable --now dynu-ddns-update.timer || true
  fi

  # Stop service if running (oneshot, but just in case)
  if systemctl list-unit-files | awk '{print $1}' | grep -qx "dynu-ddns-update.service"; then
    systemctl stop dynu-ddns-update.service || true
  fi

  # Remove unit files
  rm -f /etc/systemd/system/dynu-ddns-update.timer
  rm -f /etc/systemd/system/dynu-ddns-update.service

  systemctl daemon-reload || true
}

remove_updater_files() {
  rm -f /usr/local/sbin/dynu-ddns-update.sh
  rm -f /etc/dynu/dynu-ddns.conf
  rmdir /etc/dynu 2>/dev/null || true
}

uninstall_dynu_deb() {
  # Package name as installed by Dynu DEB
  if dpkg-query -W -f='${Status}\n' dynu-ip-update-client 2>/dev/null | grep -q "install ok installed"; then
    # Stop vendor service if present
    systemctl stop dynu-ip-update-client.service 2>/dev/null || true
    systemctl disable dynu-ip-update-client.service 2>/dev/null || true

    apt-get update
    apt-get purge -y dynu-ip-update-client
    apt-get autoremove -y
  fi
}

cleanup_downloads() {
  # Remove local .deb files if still present in current directory (common after install script)
  rm -f ./dynu-ip-update-client_*.deb ./packages-microsoft-prod.deb 2>/dev/null || true
}

main() {
  require_root

  disable_systemd_units
  remove_updater_files
  uninstall_dynu_deb
  cleanup_downloads

  echo "OK: Dynu client and related DDNS updater configuration removed."
  echo "If you installed dotnet-runtime specifically for Dynu and no longer need it,"
  echo "you can remove it manually (optional)."
}

main "$@"
