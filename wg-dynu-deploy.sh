#!/usr/bin/env bash
set -euo pipefail

# Dynu IP Update Client install for Ubuntu (DEB)
# Follows Dynu's Linux install guide for Ubuntu 20.04 / 22.04 / 24.04 x64.
# Ref: https://www.dynu.com/DynamicDNS/IPUpdateClient/Linux

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "ERROR: run as root. Example: sudo $0"
    exit 1
  fi
}

require_ubuntu() {
  if [[ ! -r /etc/os-release ]]; then
    echo "ERROR: /etc/os-release not found"
    exit 1
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" ]]; then
    echo "ERROR: this script supports Ubuntu only. Detected ID='${ID:-unknown}'."
    exit 1
  fi
}

require_amd64() {
  local arch
  arch="$(dpkg --print-architecture)"
  if [[ "$arch" != "amd64" ]]; then
    echo "ERROR: this script supports amd64 only. Detected: $arch"
    exit 1
  fi
}

install_ubuntu_24_04_plus() {
  apt-get update
  apt-get install -y wget ca-certificates
  apt-get install -y dotnet-runtime-8.0
  wget --trust-server-names https://www.dynu.com/support/downloadfile/69
  apt-get install -y ./dynu-ip-update-client_1.0.2-1_amd64.deb
}

install_ubuntu_22_04() {
  apt-get update
  apt-get install -y wget ca-certificates
  apt-get install -y dotnet-runtime-6.0
  wget --trust-server-names https://www.dynu.com/support/downloadfile/67
  apt-get install -y ./dynu-ip-update-client_1.0.1-1_amd64.deb
}

install_ubuntu_20_04() {
  apt-get update
  apt-get install -y wget ca-certificates
  wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
  dpkg -i packages-microsoft-prod.deb
  rm -f packages-microsoft-prod.deb
  apt-get update
  apt-get install -y dotnet-runtime-6.0
  wget --trust-server-names https://www.dynu.com/support/downloadfile/67
  apt-get install -y ./dynu-ip-update-client_1.0.1-1_amd64.deb
}

main() {
  require_root
  require_ubuntu
  require_amd64

  # shellcheck disable=SC1091
  . /etc/os-release
  ver="${VERSION_ID:-}"

  case "$ver" in
    24.04|24.10|25.*|26.*)
      install_ubuntu_24_04_plus
      ;;
    22.04|22.10|23.*)
      # Dynu documents 22.04 explicitly; for other 22/23 builds, this is best-effort.
      install_ubuntu_22_04
      ;;
    20.04|20.10|21.*)
      # Dynu documents 20.04 explicitly; for other 20/21 builds, this is best-effort.
      install_ubuntu_20_04
      ;;
    *)
      echo "ERROR: unsupported Ubuntu VERSION_ID='$ver'."
      echo "Dynu documents Ubuntu 20.04, 22.04, 24.04 for the DEB packages."
      exit 1
      ;;
  esac

  echo "OK: Dynu IP Update Client installed."
  echo "Service name: dynu-ip-update-client.service"
  echo "Check status: systemctl status dynu-ip-update-client.service"
}

main "$@"
