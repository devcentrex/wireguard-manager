#!/usr/bin/env bash
# smart-hardening.sh (Ubuntu 22.04)
# - Create/ensure user adm-01 with passwordless sudo
# - Install SSH public key for adm-01
# - Disable SSH password auth; disable root SSH
# - Deny console login for root
# - Allow console login ONLY for adm-01 (PAM access)
# - Auto-logoff idle console shells for all users (TMOUT)
# - Optional: disable systemd-networkd-wait-online to prevent boot hang
#
# Usage:
#   sudo bash smart-hardening.sh --pubkey "ssh-ed25519 AAAA... comment"
#   sudo bash smart-hardening.sh --pubkey-file /path/to/id_ed25519.pub
#
# Notes:
# - Keep an active SSH session while testing; do not lock yourself out.
# - Script is idempotent (safe to re-run).

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
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --user)
        ADM_USER="${2:-}"; shift 2;;
      --pubkey)
        PUBKEY="${2:-}"; shift 2;;
      --pubkey-file)
        PUBKEY_FILE="${2:-}"; shift 2;;
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
  --user <username>                Admin username to configure (default: adm-01)
  --tmout <seconds>                Idle logout for console shells (default: 600)
  --disable-wait-online yes|no     Disable systemd-networkd-wait-online (default: yes)
  --yes                            Skip confirmation prompt
  --dry-run                        Show what would be done, but make no changes
  -h, --help                       Show this help and exit
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
  if [[ -z "$PUBKEY" ]]; then
    log "No SSH public key provided. User setup is skipped."
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

set_ssd
