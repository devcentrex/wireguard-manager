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

set_sshd_kv() {
  # Safe-ish updater for /etc/ssh/sshd_config: set or replace key value
  local key="$1" val="$2" file="/etc/ssh/sshd_config"
  if grep -qiE "^\s*${key}\b" "$file"; then
    sed -i -E "s|^\s*${key}\b.*|${key} ${val}|I" "$file"
  else
    printf "\n%s %s\n" "$key" "$val" >>"$file"
  fi
}

configure_ssh_hardening() {
  local f="/etc/ssh/sshd_config"
  backup_file "$f"

  log "Hardening SSH (no passwords; no root login)"
  set_sshd_kv "PasswordAuthentication" "no"
  set_sshd_kv "KbdInteractiveAuthentication" "no"
  set_sshd_kv "ChallengeResponseAuthentication" "no"
  set_sshd_kv "PermitRootLogin" "no"
  set_sshd_kv "PubkeyAuthentication" "yes"
  set_sshd_kv "UsePAM" "yes"

  # Validate sshd config before reload
  sshd -t || die "sshd_config validation failed. Fix /etc/ssh/sshd_config."

  systemctl reload ssh || systemctl reload sshd
  log "SSH reloaded"
}

deny_root_console_login() {
  # Root console login is controlled via /etc/securetty. Empty => root can't login on tty.
  local f="/etc/securetty"
  backup_file "$f"
  log "Denying root login on console (empty /etc/securetty)"
  : >"$f"
}

ensure_pam_access_enabled() {
  local f="/etc/pam.d/login"
  backup_file "$f"
  if grep -qE "^\s*account\s+required\s+pam_access\.so" "$f"; then
    log "pam_access already enabled in /etc/pam.d/login"
  else
    log "Enabling pam_access in /etc/pam.d/login"
    # Insert near top (after comments) for clarity
    awk 'NR==1{print} /^[[:space:]]*#/ {print; next} !done {print "account required pam_access.so"; done=1} {print}' "$f" > "${f}.tmp"
    mv "${f}.tmp" "$f"
  fi
}

configure_console_only_adm01() {
  ensure_pam_access_enabled

  local f="/etc/security/access.conf"
  backup_file "$f"

  # Remove any previous block we manage, then append fresh
  # Markers keep it idempotent and easy to edit/remove.
  log "Restricting console login: allow $ADM_USER only; deny everyone else (LOCAL)"
  sed -i '/^# BEGIN ADM01_CONSOLE_ONLY$/,/^# END ADM01_CONSOLE_ONLY$/d' "$f" || true

  cat >>"$f" <<EOF

# BEGIN ADM01_CONSOLE_ONLY
# Allow $ADM_USER on local console
+ : $ADM_USER : LOCAL
# Deny everyone else on console
- : ALL : LOCAL
# END ADM01_CONSOLE_ONLY
EOF
}

configure_console_autologoff_tmout() {
  local f="/etc/profile.d/00-autologout.sh"
  log "Configuring console idle auto-logoff (TMOUT=${TMOUT_SECONDS}s): $f"
  cat >"$f" <<EOF
# Auto-logout idle interactive shells (console/tty) after ${TMOUT_SECONDS}s.
# Applies to bash/sh for interactive shells.
case "\$-" in
  *i*)
    TMOUT=${TMOUT_SECONDS}
    readonly TMOUT
    export TMOUT
  ;;
esac
EOF
  chmod 0644 "$f"
}

optional_disable_wait_online() {
  if [[ "$DISABLE_WAIT_ONLINE" == "yes" ]]; then
    log "Disabling systemd-networkd-wait-online to avoid boot hangs"
    systemctl disable --now systemd-networkd-wait-online.service >/dev/null 2>&1 || true
  else
    log "Leaving systemd-networkd-wait-online enabled"
  fi
}

final_checks() {
  info "Final checks"
  info "User groups:"
  id "$ADM_USER" || warning "User $ADM_USER does not exist."
  info "Sudo rule check:"
  sudo -l -U "$ADM_USER" | sed -n '1,120p' || warning "Sudo check failed for $ADM_USER."
  info "SSH effective settings (subset):"
  sshd -T 2>/dev/null | grep -E 'passwordauthentication|kbdinteractiveauthentication|permitrootlogin|pubkeyauthentication|usepam' || warning "Could not get sshd settings."
  info "Console restriction file tail:"
  tail -n 30 /etc/security/access.conf || warning "Could not read /etc/security/access.conf."
  info "Done. Test in a NEW session:"
  cat <<EOF
1) SSH key login:
   ssh ${ADM_USER}@<server>
2) Ensure no password prompt for root shell:
   sudo su -
3) Root SSH should be denied:
   ssh root@<server>   (should fail)
4) Console:
   - root should be denied
   - only ${ADM_USER} should be allowed
EOF
}

main() {
  log_banner "WireGuard Smart Hardening Script (User-Friendly Mode)"
  require_root
  parse_args "$@"
  print_summary
  confirm_or_exit
  ensure_user
  configure_passwordless_sudo
  install_ssh_key
  smart_configure_ssh_hardening
  smart_deny_root_console_login
  smart_configure_console_only_adm01
  smart_configure_console_autologoff_tmout
  smart_optional_disable_wait_online
  final_checks
  log_banner "All done! Please test your access before closing your session."
  echo "If you are locked out, use your backup session or recovery console."
}

# Smart SSH hardening: only change if needed
smart_configure_ssh_hardening() {
  local f="/etc/ssh/sshd_config"
  local needed=0
  grep -q '^PasswordAuthentication no' "$f" || needed=1
  grep -q '^KbdInteractiveAuthentication no' "$f" || needed=1
  grep -q '^ChallengeResponseAuthentication no' "$f" || needed=1
  grep -q '^PermitRootLogin no' "$f" || needed=1
  grep -q '^PubkeyAuthentication yes' "$f" || needed=1
  grep -q '^UsePAM yes' "$f" || needed=1
  if [ "$needed" -eq 0 ]; then
    success "SSH config already hardened."
    return
  fi
  info "Hardening SSH (no passwords; no root login)"
  if [[ "$DRY_RUN" == "yes" ]]; then
    echo "[DRY-RUN] Would update $f for SSH hardening."
    return
  fi
  backup_file "$f"
  set_sshd_kv "PasswordAuthentication" "no"
  set_sshd_kv "KbdInteractiveAuthentication" "no"
  set_sshd_kv "ChallengeResponseAuthentication" "no"
  set_sshd_kv "PermitRootLogin" "no"
  set_sshd_kv "PubkeyAuthentication" "yes"
  set_sshd_kv "UsePAM" "yes"
  if ! sshd -t; then
    critical "sshd_config validation failed. Fix /etc/ssh/sshd_config."
  fi
  systemctl reload ssh || systemctl reload sshd
  success "SSH reloaded and hardened."
}

# Smart deny root console login
smart_deny_root_console_login() {
  local f="/etc/securetty"
  if [ ! -s "$f" ]; then
    success "Root console login already denied."
    return
  fi
  info "Denying root login on console (empty /etc/securetty)"
  if [[ "$DRY_RUN" == "yes" ]]; then
    echo "[DRY-RUN] Would empty $f to deny root console login."
    return
  fi
  backup_file "$f"
  : >"$f"
  success "Root console login denied."
}

# Smart restrict console login to adm-01
smart_configure_console_only_adm01() {
  ensure_pam_access_enabled
  local f="/etc/security/access.conf"
  if grep -q "^# BEGIN ADM01_CONSOLE_ONLY$" "$f" && grep -q "^# END ADM01_CONSOLE_ONLY$" "$f" && grep -q "+ : $ADM_USER : LOCAL" "$f"; then
    success "Console login restriction already set for $ADM_USER."
    return
  fi
  info "Restricting console login: allow $ADM_USER only; deny everyone else (LOCAL)"
  if [[ "$DRY_RUN" == "yes" ]]; then
    echo "[DRY-RUN] Would update $f for console login restriction."
    return
  fi
  backup_file "$f"
  sed -i '/^# BEGIN ADM01_CONSOLE_ONLY$/,/^# END ADM01_CONSOLE_ONLY$/d' "$f" || true
  cat >>"$f" <<EOF

# BEGIN ADM01_CONSOLE_ONLY
# Allow $ADM_USER on local console
+ : $ADM_USER : LOCAL
# Deny everyone else on console
- : ALL : LOCAL
# END ADM01_CONSOLE_ONLY
EOF
  success "Console login restriction applied."
}

# Smart auto-logout idle shells
smart_configure_console_autologoff_tmout() {
  local f="/etc/profile.d/00-autologout.sh"
  if [ -f "$f" ] && grep -q "TMOUT=${TMOUT_SECONDS}" "$f"; then
    success "Auto-logoff already set to ${TMOUT_SECONDS}s."
    return
  fi
  info "Configuring console idle auto-logoff (TMOUT=${TMOUT_SECONDS}s): $f"
  if [[ "$DRY_RUN" == "yes" ]]; then
    echo "[DRY-RUN] Would update $f for auto-logoff."
    return
  fi
  cat >"$f" <<EOF
# Auto-logout idle interactive shells (console/tty) after ${TMOUT_SECONDS}s.
# Applies to bash/sh for interactive shells.
case "\$-" in
  *i*)
    TMOUT=${TMOUT_SECONDS}
    readonly TMOUT
    export TMOUT
  ;;
esac
EOF
  chmod 0644 "$f"
  success "Auto-logoff set to ${TMOUT_SECONDS}s."
}

# Smart optionally disable systemd-networkd-wait-online
smart_optional_disable_wait_online() {
  if [[ "$DISABLE_WAIT_ONLINE" == "yes" ]]; then
    if ! systemctl is-enabled systemd-networkd-wait-online.service 2>/dev/null | grep -q 'enabled'; then
      success "systemd-networkd-wait-online already disabled."
      return
    fi
    info "Disabling systemd-networkd-wait-online to avoid boot hangs"
    if [[ "$DRY_RUN" == "yes" ]]; then
      echo "[DRY-RUN] Would disable systemd-networkd-wait-online.service."
      return
    fi
    systemctl disable --now systemd-networkd-wait-online.service >/dev/null 2>&1 || warning "Failed to disable systemd-networkd-wait-online.service."
    success "systemd-networkd-wait-online disabled."
  else
    info "Leaving systemd-networkd-wait-online enabled"
  fi
}
