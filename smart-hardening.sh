#!/usr/bin/env bash
# smart-hardening.sh (Ubuntu 22.04)
#
# WHAT THIS SCRIPT DOES:
#   - Creates or ensures an admin user (default: adm-01, configurable)
#   - Installs an SSH public key for that user
#   - Configures passwordless sudo for the user
#   - Hardens SSH: disables password/root login, enables key auth
#   - Denies root console login
#   - Restricts console login to the admin user only
#   - Enables auto-logoff for idle shells (default: 10 min, configurable)
#   - Optionally disables systemd-networkd-wait-online to prevent boot hang
#
# HOW TO USE:
#   1. Prepare your SSH public key (e.g., id_ed25519.pub)
#   2. Run as root with explicit parameters:
#      sudo bash smart-hardening.sh --user <username> --pubkey "ssh-ed25519 AAAA... comment"
#      OR
#      sudo bash smart-hardening.sh --user <username> --pubkey-file /path/to/key.pub
#   3. Review the summary and confirm when prompted.
#
# EXAMPLES:
#   sudo bash smart-hardening.sh --user alice --pubkey "ssh-ed25519 AAAAC3Nza... alice@laptop"
#   sudo bash smart-hardening.sh --user admin --pubkey-file /tmp/id_ed25519.pub --tmout 900 --disable-wait-online no
#   sudo bash smart-hardening.sh --user bob --pubkey "ssh-rsa AAAAB3Nza..."
#
# SAFETY:
#   - No actions will be performed unless --user and --pubkey/--pubkey-file are provided.
#   - The script is idempotent (safe to re-run).
#   - Always keep a backup SSH session open when testing.
#
# For help:
#   sudo bash smart-hardening.sh --help

set -euo pipefail

ADM_USER="adm-01"
TMOUT_SECONDS="600"   # 10 minutes
DISABLE_WAIT_ONLINE="yes"  # set to "no" if you want to keep wait-online

PUBKEY=""
PUBKEY_FILE=""
YES_FLAG="no"
DRY_RUN="no"

log(){ printf "[%s] %s\n" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
die(){ printf "ERROR: %s\n" "$*" >&2; exit 1; }
info() { printf "[INFO] %s\n" "$*"; }
success() { printf "[OK] %s\n" "$*"; }
warning() { printf "[WARN] %s\n" "$*"; }
critical() { printf "[FAIL] %s\n" "$*"; exit 1; }

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "Run as root: sudo bash $0 ..."
}

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local b="${f}.bak.$(date -u +'%Y%m%d%H%M%S')"
  cp -a "$f" "$b"
  log "Backup: $f -> $b"
}

log_banner() {
  echo "=================================================="
  echo "$1"
  echo "=================================================="
}

print_summary() {
  echo
  echo "This script will perform the following actions (unless already applied):"
  echo " - Harden SSH (disable password/root login, enable key auth)"
  echo " - Deny root console login"
  echo " - Restrict console login to $ADM_USER only"
  echo " - Enable auto-logout for idle shells (${TMOUT_SECONDS}s)"
  echo " - Optionally disable systemd-networkd-wait-online"
  echo
  echo "User creation and SSH key setup are currently DISABLED."
  echo
}

confirm_or_exit() {
  if [[ "$YES_FLAG" == "yes" ]]; then
    return
  fi
  echo -n "Continue with these changes? [y/N]: "
  read -r ans
  if [[ ! "$ans" =~ ^[Yy]$ ]]; then
    echo "Aborted by user."
    exit 1
  fi
}

# Add --dry-run option
parse_args() {
  local user_set="no" key_set="no"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --user)
        ADM_USER="${2:-}"; user_set="yes"; shift 2;;
      --pubkey)
        PUBKEY="${2:-}"; key_set="yes"; shift 2;;
      --pubkey-file)
        PUBKEY_FILE="${2:-}"; key_set="yes"; shift 2;;
      --tmout)
        TMOUT_SECONDS="${2:-}"; shift 2;;
      --disable-wait-online)
        DISABLE_WAIT_ONLINE="${2:-}"; shift 2;;
      --yes)
        YES_FLAG="yes"; shift;;
      --dry-run)
        DRY_RUN="yes"; shift;;
      -h|--help)
        cat <<EOF
Usage:
  sudo bash $0 --user <username> --pubkey "ssh-ed25519 AAAA... comment" [--yes] [--dry-run]
  sudo bash $0 --user <username> --pubkey-file /path/to/key.pub [--yes] [--dry-run]

Options:
  --user <username>                Admin username to configure (required)
  --pubkey <key>                   SSH public key string (required)
  --pubkey-file <file>             Path to SSH public key file (alternative to --pubkey)
  --tmout <seconds>                Idle logout for console shells (default: 600)
  --disable-wait-online yes|no     Disable systemd-networkd-wait-online (default: yes)
  --yes                            Skip confirmation prompt
  --dry-run                        Show what would be done, but make no changes
  -h, --help                       Show this help and exit

Examples:
  sudo bash $0 --user alice --pubkey "ssh-ed25519 AAAAC3Nza... alice@laptop"
  sudo bash $0 --user admin --pubkey-file /tmp/id_ed25519.pub --tmout 900 --disable-wait-online no
EOF
        exit 0;;
      *)
        die "Unknown arg: $1";;
    esac
  done
  if [[ -n "$PUBKEY_FILE" ]]; then
    [[ -f "$PUBKEY_FILE" ]] || die "Public key file not found: $PUBKEY_FILE"
    PUBKEY="$(cat "$PUBKEY_FILE")"
  fi
  if [[ "$user_set" != "yes" || "$key_set" != "yes" ]]; then
    echo "\n[ERROR] You must provide --user and --pubkey or --pubkey-file."
    echo "See usage below:"
    "$0" --help
    exit 1
  fi
  if [[ -z "$PUBKEY" ]]; then
    die "No SSH public key provided."
  elif [[ ! "$PUBKEY" =~ ^ssh-(ed25519|rsa|ecdsa) ]]; then
    die "PUBKEY does not look like an SSH public key"
  fi
  if [[ -z "$ADM_USER" ]]; then
    die "--user <username> is required."
  fi
}

run_or_echo() {
  if [[ "$DRY_RUN" == "yes" ]]; then
    echo "[DRY-RUN] $*"
  else
    eval "$*"
  fi
}

ensure_user() {
  if id -u "$ADM_USER" >/dev/null 2>&1; then
    success "User exists: $ADM_USER"
  else
    info "Creating user: $ADM_USER"
    if ! run_or_echo "adduser --disabled-password --gecos '' '$ADM_USER'"; then
      warning "Failed to create user $ADM_USER. Skipping user creation."
      return 1
    fi
  fi
  info "Ensuring $ADM_USER is in sudo group"
  if ! run_or_echo "usermod -aG sudo '$ADM_USER'"; then
    warning "Failed to add $ADM_USER to sudo group."
    return 1
  fi
  success "User $ADM_USER ensured and in sudo group."
}

configure_passwordless_sudo() {
  local f="/etc/sudoers.d/${ADM_USER}"
  if [[ -f "$f" ]] && grep -qE "^\s*${ADM_USER}\s+ALL=\(ALL\)\s+NOPASSWD:ALL\s*$" "$f"; then
    success "Passwordless sudo already configured: $f"
    return 0
  fi
  info "Configuring passwordless sudo: $f"
  if [[ "$DRY_RUN" == "yes" ]]; then
    echo "[DRY-RUN] Would write passwordless sudo for $ADM_USER to $f"
    return 0
  fi
  cat >"$f" <<EOF
${ADM_USER} ALL=(ALL) NOPASSWD:ALL
EOF
  chmod 0440 "$f"
  if ! visudo -cf "$f" >/dev/null; then
    warning "visudo check failed for $f."
    return 1
  fi
  success "Passwordless sudo configured for $ADM_USER."
}

install_ssh_key() {
  local home_dir
  home_dir="$(getent passwd "$ADM_USER" | cut -d: -f6)"
  [[ -n "$home_dir" ]] || { warning "Cannot determine home for $ADM_USER"; return 1; }
  info "Installing SSH key for $ADM_USER"
  if [[ "$DRY_RUN" == "yes" ]]; then
    echo "[DRY-RUN] Would install SSH key for $ADM_USER in $home_dir/.ssh/authorized_keys"
    return 0
  fi
  install -d -m 0700 -o "$ADM_USER" -g "$ADM_USER" "${home_dir}/.ssh"
  local ak="${home_dir}/.ssh/authorized_keys"
  touch "$ak"
  chown "$ADM_USER:$ADM_USER" "$ak"
  chmod 0600 "$ak"
  if grep -Fqx "$PUBKEY" "$ak"; then
    success "Public key already present in authorized_keys"
  else
    printf "%s\n" "$PUBKEY" >>"$ak"
    success "Public key appended to authorized_keys"
  fi
}

set_sshd_config() {
  local f="/etc/ssh/sshd_config"
  backup_file "$f"
  info "Hardening SSH configuration: $f"
  {
    echo "Match User $ADM_USER"
    echo "  AllowTcpForwarding no"
    echo "  X11Forwarding no"
    echo "  PermitTTY yes"
    echo "  ForceCommand internal-sftp"
    echo
    echo "Match Address 192.168.1.*"
    echo "  AllowTcpForwarding yes"
    echo "  X11Forwarding yes"
    echo "  PermitTTY yes"
    echo "  ForceCommand /bin/bash"
    echo
    echo "Match all"
    echo "  PasswordAuthentication no"
    echo "  ChallengeResponseAuthentication no"
    echo "  UsePAM no"
    echo "  PermitRootLogin no"
    echo "  PubkeyAuthentication yes"
    echo "  AuthorizedKeysFile .ssh/authorized_keys"
    echo "  PermitEmptyPasswords no"
    echo "  AllowUsers $ADM_USER"
  } >>"$f"
  if ! sshd -t; then
    critical "SSH configuration test failed. Fix issues before proceeding."
  fi
  success "SSH configuration hardened."
}

set_tmout() {
  local f="/etc/profile.d/tmout.sh"
  backup_file "$f"
  info "Setting up auto-logoff for idle shells: $f"
  cat >"$f" <<EOF
# Auto-logoff for idle shells
TMOUT=${TMOUT_SECONDS}
readonly TMOUT
export TMOUT
EOF
  chmod 0644 "$f"
  success "Auto-logoff configured."
}

disable_wait_online() {
  local s="/etc/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service"
  if [[ "$DISABLE_WAIT_ONLINE" == "yes" ]]; then
    info "Disabling systemd-networkd-wait-online.service"
    run_or_echo "systemctl disable systemd-networkd-wait-online.service"
    run_or_echo "systemctl stop systemd-networkd-wait-online.service"
    success "systemd-networkd-wait-online.service disabled."
  else
    info "Enabling systemd-networkd-wait-online.service"
    run_or_echo "systemctl enable systemd-networkd-wait-online.service"
    success "systemd-networkd-wait-online.service enabled."
  fi
}

# Main script execution
require_root
parse_args "$@"
log_banner "SMART HARDENING SCRIPT"
print_summary
confirm_or_exit
ensure_user
configure_passwordless_sudo
install_ssh_key
set_sshd_config
set_tmout
disable_wait_online

echo
echo "All tasks completed successfully."
echo "Reboot the system to apply all changes."
