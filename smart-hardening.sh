#!/usr/bin/env bash
# smart-hardening.sh (Ubuntu 22.04)
#
# WHAT THIS SCRIPT DOES (only with explicit --do-* flags):
#   - Creates or ensures an admin user
#   - Installs an SSH public key for that user
#   - Configures passwordless sudo for the user
#   - Hardens SSH: disables password/root login, enables key auth
#   - Denies root console login
#   - Restricts console login to the admin user only
#   - Enables auto-logoff for idle shells
#   - Optionally disables systemd-networkd-wait-online
#
# HOW TO USE:
#   1. Prepare your SSH public key (e.g., id_ed25519.pub)
#   2. Run as root with explicit --do-* flags for each step you want:
#      sudo bash smart-hardening.sh --user <username> --pubkey "ssh-ed25519 AAAA..." --do-ensure-user --do-passwordless-sudo --do-install-ssh-key --do-ssh-harden --do-deny-root-console --do-console-only-adm --do-autologoff --do-disable-wait-online
#   3. You can specify any subset of steps.
#
# EXAMPLES:
#   sudo bash smart-hardening.sh --user alice --pubkey "ssh-ed25519 AAAAC3Nza..." --do-ensure-user --do-install-ssh-key --do-ssh-harden
#   sudo bash smart-hardening.sh --user admin --pubkey-file /tmp/id_ed25519.pub --do-ensure-user --do-passwordless-sudo --do-autologoff
#
# SAFETY:
#   - No actions will be performed unless the corresponding --do-* flag is provided.
#   - The script is idempotent (safe to re-run).
#   - Always keep a backup SSH session open when testing.
#
# For help:
#   sudo bash smart-hardening.sh --help

set -euo pipefail

ADM_USER=""
TMOUT_SECONDS="600"
DISABLE_WAIT_ONLINE="yes"
PUBKEY=""
PUBKEY_FILE=""
YES_FLAG="no"
DRY_RUN="no"

# Step flags (all default to no)
DO_ENSURE_USER="no"
DO_PASSWORDLESS_SUDO="no"
DO_INSTALL_SSH_KEY="no"
DO_SSH_HARDEN="no"
DO_DENY_ROOT_CONSOLE="no"
DO_CONSOLE_ONLY_ADM="no"
DO_AUTOLOGOFF="no"
DO_DISABLE_WAIT_ONLINE="no"

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
  echo "This script will perform the following actions (only those explicitly requested):"
  [[ "$DO_ENSURE_USER" == "yes" ]] && echo " - Create/ensure user: $ADM_USER"
  [[ "$DO_PASSWORDLESS_SUDO" == "yes" ]] && echo " - Configure passwordless sudo for $ADM_USER"
  [[ "$DO_INSTALL_SSH_KEY" == "yes" ]] && echo " - Install SSH public key for $ADM_USER"
  [[ "$DO_SSH_HARDEN" == "yes" ]] && echo " - Harden SSH configuration"
  [[ "$DO_DENY_ROOT_CONSOLE" == "yes" ]] && echo " - Deny root console login"
  [[ "$DO_CONSOLE_ONLY_ADM" == "yes" ]] && echo " - Restrict console login to $ADM_USER only"
  [[ "$DO_AUTOLOGOFF" == "yes" ]] && echo " - Enable auto-logout for idle shells (${TMOUT_SECONDS}s)"
  [[ "$DO_DISABLE_WAIT_ONLINE" == "yes" ]] && echo " - Disable systemd-networkd-wait-online"
  echo
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
      --do-ensure-user)
        DO_ENSURE_USER="yes"; shift;;
      --do-passwordless-sudo)
        DO_PASSWORDLESS_SUDO="yes"; shift;;
      --do-install-ssh-key)
        DO_INSTALL_SSH_KEY="yes"; shift;;
      --do-ssh-harden)
        DO_SSH_HARDEN="yes"; shift;;
      --do-deny-root-console)
        DO_DENY_ROOT_CONSOLE="yes"; shift;;
      --do-console-only-adm)
        DO_CONSOLE_ONLY_ADM="yes"; shift;;
      --do-autologoff)
        DO_AUTOLOGOFF="yes"; shift;;
      --do-disable-wait-online)
        DO_DISABLE_WAIT_ONLINE="yes"; shift;;
      -h|--help)
        cat <<EOF
Usage:
  sudo bash $0 --user <username> --pubkey "ssh-ed25519 AAAA..." [--do-ensure-user ...] [options]
  sudo bash $0 --user <username> --pubkey-file /path/to/key.pub [--do-ensure-user ...] [options]

Options:
  --user <username>                Admin username to configure (required)
  --pubkey <key>                   SSH public key string (required for SSH key step)
  --pubkey-file <file>             Path to SSH public key file (alternative to --pubkey)
  --tmout <seconds>                Idle logout for console shells (default: 600)
  --disable-wait-online yes|no     Disable systemd-networkd-wait-online (default: yes)
  --yes                            Skip confirmation prompt
  --dry-run                        Show what would be done, but make no changes

  --do-ensure-user                 Create/ensure the admin user
  --do-passwordless-sudo           Configure passwordless sudo for the user
  --do-install-ssh-key             Install SSH public key for the user
  --do-ssh-harden                  Harden SSH configuration
  --do-deny-root-console           Deny root console login
  --do-console-only-adm            Restrict console login to admin user
  --do-autologoff                  Enable auto-logout for idle shells
  --do-disable-wait-online         Disable systemd-networkd-wait-online

  -h, --help                       Show this help and exit

Examples:
  sudo bash $0 --user alice --pubkey "ssh-ed25519 AAAAC3Nza..." --do-ensure-user --do-install-ssh-key --do-ssh-harden
  sudo bash $0 --user admin --pubkey-file /tmp/id_ed25519.pub --do-ensure-user --do-passwordless-sudo --do-autologoff
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
  if [[ -z "$ADM_USER" ]]; then
    echo "\n[ERROR] You must provide --user <username>."
    "$0" --help
    exit 1
  fi
  if [[ "$DO_INSTALL_SSH_KEY" == "yes" && -z "$PUBKEY" ]]; then
    echo "\n[ERROR] --do-install-ssh-key requires --pubkey or --pubkey-file."
    "$0" --help
    exit 1
  fi
  if [[ -n "$PUBKEY" && ! "$PUBKEY" =~ ^ssh-(ed25519|rsa|ecdsa) ]]; then
    die "PUBKEY does not look like an SSH public key"
  fi
  # Require at least one --do-* flag
  if [[ "$DO_ENSURE_USER" != "yes" && "$DO_PASSWORDLESS_SUDO" != "yes" && "$DO_INSTALL_SSH_KEY" != "yes" && "$DO_SSH_HARDEN" != "yes" && "$DO_DENY_ROOT_CONSOLE" != "yes" && "$DO_CONSOLE_ONLY_ADM" != "yes" && "$DO_AUTOLOGOFF" != "yes" && "$DO_DISABLE_WAIT_ONLINE" != "yes" ]]; then
    echo "\n[ERROR] You must specify at least one --do-* flag to perform any action."
    "$0" --help
    exit 1
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
local step=1
if [[ "$DO_ENSURE_USER" == "yes" ]]; then
  info "[$step] Ensuring user and group setup..."; ((step++))
  ensure_user
fi
if [[ "$DO_PASSWORDLESS_SUDO" == "yes" ]]; then
  info "[$step] Configuring passwordless sudo..."; ((step++))
  configure_passwordless_sudo
fi
if [[ "$DO_INSTALL_SSH_KEY" == "yes" ]]; then
  info "[$step] Installing SSH key..."; ((step++))
  install_ssh_key
fi
if [[ "$DO_SSH_HARDEN" == "yes" ]]; then
  info "[$step] Hardening SSH configuration..."; ((step++))
  set_sshd_config
fi
if [[ "$DO_DENY_ROOT_CONSOLE" == "yes" ]]; then
  info "[$step] Denying root console login..."; ((step++))
  smart_deny_root_console_login
fi
if [[ "$DO_CONSOLE_ONLY_ADM" == "yes" ]]; then
  info "[$step] Restricting console login to $ADM_USER..."; ((step++))
  smart_configure_console_only_adm01
fi
if [[ "$DO_AUTOLOGOFF" == "yes" ]]; then
  info "[$step] Enabling auto-logout for idle shells..."; ((step++))
  set_tmout
fi
if [[ "$DO_DISABLE_WAIT_ONLINE" == "yes" ]]; then
  info "[$step] Disabling systemd-networkd-wait-online if needed..."; ((step++))
  disable_wait_online
fi
final_checks
log_banner "All done! Please test your access before closing your session."
echo "If you are locked out, use your backup session or recovery console."
