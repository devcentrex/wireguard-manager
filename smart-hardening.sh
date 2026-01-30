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

log(){ printf "[%s] %s\n" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
die(){ printf "ERROR: %s\n" "$*" >&2; exit 1; }

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

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pubkey)
        PUBKEY="${2:-}"; shift 2;;
      --pubkey-file)
        PUBKEY_FILE="${2:-}"; shift 2;;
      --tmout)
        TMOUT_SECONDS="${2:-}"; shift 2;;
      --disable-wait-online)
        DISABLE_WAIT_ONLINE="${2:-}"; shift 2;;
      -h|--help)
        cat <<EOF
Usage:
  sudo bash $0 --pubkey "ssh-ed25519 AAAA... comment"
  sudo bash $0 --pubkey-file /path/to/key.pub

Options:
  --tmout <seconds>               Idle logout for console shells (default: 600)
  --disable-wait-online yes|no    Disable systemd-networkd-wait-online (default: yes)
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
  [[ -n "$PUBKEY" ]] || die "Provide --pubkey or --pubkey-file"
  [[ "$PUBKEY" =~ ^ssh-(ed25519|rsa|ecdsa) ]] || die "PUBKEY does not look like an SSH public key"
}

ensure_user() {
  if id -u "$ADM_USER" >/dev/null 2>&1; then
    log "User exists: $ADM_USER"
  else
    log "Creating user: $ADM_USER"
    adduser --disabled-password --gecos "" "$ADM_USER"
  fi

  log "Ensuring $ADM_USER is in sudo group"
  usermod -aG sudo "$ADM_USER"
}

configure_passwordless_sudo() {
  local f="/etc/sudoers.d/${ADM_USER}"
  if [[ -f "$f" ]] && grep -qE "^\s*${ADM_USER}\s+ALL=\(ALL\)\s+NOPASSWD:ALL\s*$" "$f"; then
    log "Passwordless sudo already configured: $f"
    return 0
  fi

  log "Configuring passwordless sudo: $f"
  cat >"$f" <<EOF
${ADM_USER} ALL=(ALL) NOPASSWD:ALL
EOF
  chmod 0440 "$f"
  visudo -cf "$f" >/dev/null
}

install_ssh_key() {
  local home_dir
  home_dir="$(getent passwd "$ADM_USER" | cut -d: -f6)"
  [[ -n "$home_dir" ]] || die "Cannot determine home for $ADM_USER"

  log "Installing SSH key for $ADM_USER"
  install -d -m 0700 -o "$ADM_USER" -g "$ADM_USER" "${home_dir}/.ssh"
  local ak="${home_dir}/.ssh/authorized_keys"
  touch "$ak"
  chown "$ADM_USER:$ADM_USER" "$ak"
  chmod 0600 "$ak"

  if grep -Fqx "$PUBKEY" "$ak"; then
    log "Public key already present in authorized_keys"
  else
    printf "%s\n" "$PUBKEY" >>"$ak"
    log "Public key appended to authorized_keys"
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
  log "Restricting console login: allow ${ADM_USER} only; deny everyone else (LOCAL)"
  sed -i '/^# BEGIN ADM01_CONSOLE_ONLY$/,/^# END ADM01_CONSOLE_ONLY$/d' "$f" || true

  cat >>"$f" <<EOF

# BEGIN ADM01_CONSOLE_ONLY
# Allow adm-01 on local console
+ : ${ADM_USER} : LOCAL
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
  log "Final checks"
  log "User groups:"
  id "$ADM_USER" || true

  log "Sudo rule check:"
  sudo -l -U "$ADM_USER" | sed -n '1,120p' || true

  log "SSH effective settings (subset):"
  sshd -T 2>/dev/null | grep -E 'passwordauthentication|kbdinteractiveauthentication|permitrootlogin|pubkeyauthentication|usepam' || true

  log "Console restriction file tail:"
  tail -n 30 /etc/security/access.conf || true

  log "Done. Test in a NEW session:"
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
  require_root
  parse_args "$@"
  ensure_user
  configure_passwordless_sudo
  install_ssh_key
  configure_ssh_hardening
  deny_root_console_login
  configure_console_only_adm01
  configure_console_autologoff_tmout
  optional_disable_wait_online
  final_checks
}

main "$@"
