#!/usr/bin/env bash
# wg-hardening.sh
#
# Purpose
# . Security hardening for a Linux WireGuard host with various actions:
#   . Admin user management
#   . SSH hardening and SSH port changes
#   . Console access controls
#   . Inbound firewall policy (iptables default, nftables optional)
#
# Behavior
# . No changes unless you pass explicit action flags.
# . Actions are independent and continue even if other actions fail.
# . An action may fail if a prerequisite is missing.
#
# Safety
# . Keep an active SSH session while testing.
# . Some actions can lock you out. Those require --force.

set -euo pipefail

# Default admin name: admin-<random 3 digits>
DEFAULT_ADM_USER="admin-$(printf '%03d' $((RANDOM % 1000)))"
ADM_USER="$DEFAULT_ADM_USER"

TMOUT_SECONDS="600"

SSH_PORT="22"
WG_PORT="51820"
SSH_PORT_EXPLICIT="no"
WG_PORT_EXPLICIT="no"

FW_BACKEND="iptables"  # default firewall backend

PUBKEY=""
PUBKEY_FILE=""
declare -a SSH_ALLOW_LIST=()

# Actions (persistent hardening)
DO_ADD_ADMIN="no"
DO_UPDATE_ADMIN="no"
DO_SUDO_NOPASSWD="no"
DO_INSTALL_SSH_KEY="no"
DO_HARDEN_SSH="no"
DO_SET_SSH_PORT="no"
DO_DENY_ROOT_CONSOLE="no"
DO_CONSOLE_ONLY_ADM="no"
DO_CONSOLE_TMOUT="no"
DO_CONFIGURE_FIREWALL="no"

FORCE="no"

declare -a CHANGES=()
declare -a FAILURES=()

log(){ printf "[%s] %s\n" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
die(){ printf "ERROR: %s\n" "$*" >&2; exit 1; }          # fatal only (parse/root)
fail(){ printf "ERROR: %s\n" "$*" >&2; return 1; }       # per-action
fail_code(){ local rc="$1"; shift; printf "ERROR: %s\n" "$*" >&2; return "$rc"; }
warn(){ printf "WARN: %s\n" "$*" >&2; }
changed(){ CHANGES+=("$1"); log "CHANGED: $1"; }

require_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root: sudo bash $0 ..."; }

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local b="${f}.bak.$(date -u +'%Y%m%d%H%M%S')"
  cp -a "$f" "$b"
  log "Backup: $f -> $b"
}

need_arg() {
  local opt="$1" val="${2-}"
  [[ -n "$val" ]] || die "$opt requires a value"
  [[ "$val" != --* ]] || die "$opt requires a value"
}

print_help() {
  cat <<EOF
wg-hardening.sh

Security hardening for a WireGuard host.

Actions (persistent)
  --add-admin               Create admin user. Fails if user exists.
  --update-admin            Ensure sudo group membership. Fails if user is missing.
  --sudo-nopasswd           Passwordless sudo for --adm-user.
  --install-ssh-key         Install SSH public key for --adm-user.
  --harden-ssh              Disable SSH password auth and root SSH login.
  --set-ssh-port            Change sshd Port.
  --deny-root-console       Deny root login on local console using /etc/securetty.
  --console-only-adm        Allow console login only for --adm-user via pam_access.
  --console-tmout           Set TMOUT for interactive local console shells.
  --configure-firewall      Inbound policy: allow WG UDP, allow SSH only from allow-list, drop other inbound.
                            Ports auto-detected for firewall if you omit --ssh-port and/or --wg-port.

Common options
  --adm-user <name>         Admin username. Default pattern: admin-<3 digits>. Current: ${ADM_USER}
  --pubkey "<text>"         Public key text for --install-ssh-key
  --pubkey-file <path>      Public key file for --install-ssh-key
  --ssh-port <port>         SSH port for --set-ssh-port and optionally --configure-firewall
  --wg-port <port>          WireGuard UDP port for --configure-firewall
  --ssh-allow <cidr|ip>     Allowed source for SSH. Repeatable or comma-separated.
  --fw-backend <backend>    Firewall backend: iptables or nftables. Default: iptables
  --tmout <seconds>         TMOUT for --console-tmout. Default: 600
  --force                   Proceed with risky actions.

Notes
  . Actions continue even if other actions fail.
  . Exit code is non-zero if any selected action failed.

Example: all changes at once
  sudo bash wg-hardening.sh \\
    --add-admin --adm-user admin-123 \\
    --sudo-nopasswd \\
    --install-ssh-key --pubkey-file /root/key.pub \\
    --harden-ssh \\
    --set-ssh-port --ssh-port 2222 \\
    --deny-root-console \\
    --console-only-adm \\
    --console-tmout --tmout 600 \\
    --configure-firewall --ssh-allow 203.0.113.10/32 --ssh-allow 198.51.100.0/24 \\
    --force
EOF
}

# Runner: continue even if an action fails
run_action() {
  local name="$1"; shift
  local rc=0

  log "ACTION: $name"

  set +e
  "$@"
  rc=$?
  set -e

  if [[ $rc -eq 0 ]]; then
    log "OK: $name"
  else
    FAILURES+=("$name (rc=$rc)")
    printf "ERROR: Action failed: %s (rc=%s)\n" "$name" "$rc" >&2
  fi
  return 0
}

normalize_pubkey() {
  PUBKEY="${PUBKEY//$'\r'/}"
  PUBKEY="$(printf '%s' "$PUBKEY" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
}

validate_pubkey() {
  normalize_pubkey
  if ! printf '%s' "$PUBKEY" | awk '
      NF < 2 { exit 1 }
      $1 ~ /^(ssh-|ecdsa-|sk-ssh-|sk-ecdsa-)/ { exit 0 }
      { exit 1 }
    '; then
    fail "PUBKEY does not look like an SSH public key"
  fi
}

parse_ssh_allow_item() {
  local item="$1"
  item="$(printf '%s' "$item" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
  [[ -n "$item" ]] || return 0

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$item" <<'PY' >/dev/null
import ipaddress, sys
s = sys.argv[1]
try:
  if "/" in s:
    ipaddress.ip_network(s, strict=False)
  else:
    ip = ipaddress.ip_address(s)
    _ = f"{ip}/{32 if ip.version==4 else 128}"
except Exception:
  sys.exit(2)
PY
    local rc=$?
    [[ $rc -eq 0 ]] || fail "Invalid --ssh-allow value: $item"
  else
    [[ "$item" =~ ^[0-9a-fA-F:.]+(/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8]))?$ ]] || fail "Invalid --ssh-allow value: $item"
  fi
}

normalize_ssh_allow_list() {
  declare -a out=()
  local x item norm

  for x in "${SSH_ALLOW_LIST[@]}"; do
    IFS=',' read -r -a parts <<<"$x"
    for item in "${parts[@]}"; do
      item="$(printf '%s' "$item" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
      [[ -n "$item" ]] || continue
      parse_ssh_allow_item "$item" || return 1
      if command -v python3 >/dev/null 2>&1; then
        norm="$(python3 - "$item" <<'PY'
import ipaddress, sys
s = sys.argv[1]
if "/" in s:
  n = ipaddress.ip_network(s, strict=False)
else:
  ip = ipaddress.ip_address(s)
  n = ipaddress.ip_network(f"{ip}/{32 if ip.version==4 else 128}", strict=False)
print(str(n))
PY
)"
        out+=("$norm")
      else
        out+=("$item")
      fi
    done
  done

  SSH_ALLOW_LIST=("${out[@]}")
}

parse_args() {
  local saw_action="no"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --adm-user)        need_arg "$1" "${2-}"; ADM_USER="$2"; shift 2;;
      --tmout)           need_arg "$1" "${2-}"; TMOUT_SECONDS="$2"; shift 2;;
      --pubkey)          need_arg "$1" "${2-}"; PUBKEY="$2"; shift 2;;
      --pubkey-file)     need_arg "$1" "${2-}"; PUBKEY_FILE="$2"; shift 2;;
      --ssh-port)        need_arg "$1" "${2-}"; SSH_PORT="$2"; SSH_PORT_EXPLICIT="yes"; shift 2;;
      --wg-port)         need_arg "$1" "${2-}"; WG_PORT="$2"; WG_PORT_EXPLICIT="yes"; shift 2;;
      --ssh-allow)       need_arg "$1" "${2-}"; SSH_ALLOW_LIST+=("$2"); shift 2;;
      --fw-backend)      need_arg "$1" "${2-}"; FW_BACKEND="$2"; shift 2;;

      --add-admin)            DO_ADD_ADMIN="yes"; saw_action="yes"; shift;;
      --update-admin)         DO_UPDATE_ADMIN="yes"; saw_action="yes"; shift;;
      --sudo-nopasswd)        DO_SUDO_NOPASSWD="yes"; saw_action="yes"; shift;;
      --install-ssh-key)      DO_INSTALL_SSH_KEY="yes"; saw_action="yes"; shift;;
      --harden-ssh)           DO_HARDEN_SSH="yes"; saw_action="yes"; shift;;
      --set-ssh-port)         DO_SET_SSH_PORT="yes"; saw_action="yes"; shift;;
      --deny-root-console)    DO_DENY_ROOT_CONSOLE="yes"; saw_action="yes"; shift;;
      --console-only-adm)     DO_CONSOLE_ONLY_ADM="yes"; saw_action="yes"; shift;;
      --console-tmout)        DO_CONSOLE_TMOUT="yes"; saw_action="yes"; shift;;
      --configure-firewall)   DO_CONFIGURE_FIREWALL="yes"; saw_action="yes"; shift;;

      --force)                FORCE="yes"; shift;;

      -h|--help)              print_help; exit 0;;
      *)                      die "Unknown arg: $1";;
    esac
  done

  if [[ "$saw_action" == "no" ]]; then
    print_help
    exit 0
  fi

  [[ -n "$ADM_USER" ]] || die "--adm-user must not be empty"
  [[ "$TMOUT_SECONDS" =~ ^[0-9]+$ ]] || die "--tmout must be integer seconds"
  [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "--ssh-port must be integer"
  [[ "$WG_PORT"  =~ ^[0-9]+$ ]] || die "--wg-port must be integer"
  (( SSH_PORT >= 1 && SSH_PORT <= 65535 )) || die "--ssh-port must be 1..65535"
  (( WG_PORT  >= 1 && WG_PORT  <= 65535 )) || die "--wg-port must be 1..65535"

  case "$FW_BACKEND" in
    iptables|nftables) : ;;
    *) die "--fw-backend must be iptables or nftables" ;;
  esac

  if [[ "$DO_INSTALL_SSH_KEY" == "yes" ]]; then
    if [[ -n "$PUBKEY_FILE" ]]; then
      [[ -f "$PUBKEY_FILE" ]] || die "Public key file not found: $PUBKEY_FILE"
      local nonempty_count
      nonempty_count="$(grep -cve '^[[:space:]]*$' "$PUBKEY_FILE" || true)"
      [[ "$nonempty_count" -ge 1 ]] || die "Public key file is empty: $PUBKEY_FILE"
      [[ "$nonempty_count" -eq 1 ]] || die "Public key file has multiple non-empty lines: $PUBKEY_FILE"
      PUBKEY="$(grep -vE '^[[:space:]]*$' "$PUBKEY_FILE")"
    fi
    [[ -n "$PUBKEY" ]] || die "--install-ssh-key requires --pubkey or --pubkey-file"
    validate_pubkey || die "Invalid SSH public key"
  fi

  if [[ "$DO_CONFIGURE_FIREWALL" == "yes" ]]; then
    [[ "${#SSH_ALLOW_LIST[@]}" -ge 1 ]] || die "--configure-firewall requires at least one --ssh-allow"
    normalize_ssh_allow_list || die "Invalid --ssh-allow list"
  fi
}

log_selected_admin() {
  log "Selected adm-user: ${ADM_USER}"
  if [[ "$ADM_USER" == "$DEFAULT_ADM_USER" && "$DO_ADD_ADMIN" != "yes" ]]; then
    warn "--adm-user not provided; using generated default: ${ADM_USER}"
  fi
}

require_user_exists() {
  id -u "$ADM_USER" >/dev/null 2>&1 || fail "User not found: $ADM_USER"
}

add_admin() {
  if id -u "$ADM_USER" >/dev/null 2>&1; then
    fail "User already exists: $ADM_USER"
  fi

  adduser --disabled-password --gecos "" "$ADM_USER" >/dev/null 2>&1 || fail "adduser failed for $ADM_USER"
  changed "Created user $ADM_USER"

  if id -nG "$ADM_USER" | tr ' ' '\n' | grep -qx sudo; then
    :
  else
    usermod -aG sudo "$ADM_USER" || fail "usermod failed adding $ADM_USER to sudo"
    changed "Added $ADM_USER to sudo group"
  fi
}

update_admin() {
  require_user_exists || return 1
  if id -nG "$ADM_USER" | tr ' ' '\n' | grep -qx sudo; then
    log "No change: $ADM_USER already in sudo group"
  else
    usermod -aG sudo "$ADM_USER" || fail "usermod failed adding $ADM_USER to sudo"
    changed "Added $ADM_USER to sudo group"
  fi
}

configure_passwordless_sudo() {
  require_user_exists || return 1
  local f="/etc/sudoers.d/${ADM_USER}"
  local desired="${ADM_USER} ALL=(ALL) NOPASSWD:ALL"

  if [[ -f "$f" ]] && grep -qE "^[[:space:]]*${ADM_USER}[[:space:]]+ALL=\(ALL\)[[:space:]]+NOPASSWD:ALL[[:space:]]*$" "$f"; then
    log "No change: passwordless sudo already configured for $ADM_USER"
    return 0
  fi

  backup_file "$f"
  printf "%s\n" "$desired" >"$f" || fail "Failed writing $f"
  chmod 0440 "$f" || fail "chmod failed on $f"
  chown root:root "$f" || fail "chown failed on $f"
  visudo -cf "$f" >/dev/null 2>&1 || fail "visudo validation failed for $f"
  changed "Configured passwordless sudo in $f"
}

install_ssh_key() {
  require_user_exists || return 1

  local home_dir
  home_dir="$(getent passwd "$ADM_USER" | cut -d: -f6)"
  [[ -n "$home_dir" ]] || fail "Cannot determine home for $ADM_USER"

  install -d -m 0700 -o "$ADM_USER" -g "$ADM_USER" "${home_dir}/.ssh" || fail "Failed creating ${home_dir}/.ssh"
  local ak="${home_dir}/.ssh/authorized_keys"
  touch "$ak" || fail "Failed touching $ak"
  chown "$ADM_USER:$ADM_USER" "$ak" || fail "Failed chown $ak"
  chmod 0600 "$ak" || fail "Failed chmod $ak"

  if grep -Fqx "$PUBKEY" "$ak"; then
    log "No change: public key already present in authorized_keys"
  else
    printf "%s\n" "$PUBKEY" >>"$ak" || fail "Failed appending to $ak"
    changed "Appended public key to $ak"
  fi
}

sshd_remove_key_global() {
  local key="$1" in="$2" out="$3"
  awk -v key="$key" '
    BEGIN{IGNORECASE=1; inmatch=0}
    /^[[:space:]]*Match[[:space:]]/ {inmatch=1}
    { if (!inmatch && $0 ~ "^[[:space:]]*" key "([[:space:]]+|$)") next; print }
  ' "$in" >"$out"
}

sshd_insert_key_global() {
  local key="$1" val="$2" in="$3" out="$4"
  awk -v key="$key" -v val="$val" '
    BEGIN{IGNORECASE=1; done=0}
    /^[[:space:]]*Match[[:space:]]/ && done==0 { print key " " val; print ""; done=1 }
    {print}
    END{ if (done==0){ print ""; print key " " val } }
  ' "$in" >"$out"
}

sshd_build_updated_config() {
  local f="$1"; shift
  local cur tmp1 tmp2
  cur="$(mktemp)"
  cp -a "$f" "$cur"

  while [[ $# -gt 1 ]]; do
    local k="$1" v="$2"
    shift 2
    tmp1="$(mktemp)"
    tmp2="$(mktemp)"
    sshd_remove_key_global "$k" "$cur" "$tmp1"
    sshd_insert_key_global "$k" "$v" "$tmp1" "$tmp2"
    rm -f "$cur" "$tmp1"
    cur="$tmp2"
  done

  printf '%s' "$cur"
}

apply_file_if_changed() {
  local target="$1" mode="$2" owner="$3" group="$4" tmp="$5"
  if [[ -f "$target" ]] && cmp -s "$tmp" "$target"; then
    log "No change: $target"
    return 1
  fi
  backup_file "$target"
  install -m "$mode" -o "$owner" -g "$group" "$tmp" "$target" || return 2
  return 0
}

reload_sshd() {
  systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1
}

harden_ssh() {
  command -v sshd >/dev/null 2>&1 || fail "sshd not found. Install openssh-server first."
  [[ "$FORCE" == "yes" ]] || fail_code 2 "SSH hardening can lock you out. Re-run with --force."

  local f="/etc/ssh/sshd_config"
  [[ -f "$f" ]] || fail "Missing sshd config: $f"

  local tmp_final tmp_cur
  tmp_final="$(mktemp)"
  tmp_cur="$(sshd_build_updated_config "$f" \
    "PasswordAuthentication" "no" \
    "KbdInteractiveAuthentication" "no" \
    "ChallengeResponseAuthentication" "no" \
    "PermitRootLogin" "no" \
    "PubkeyAuthentication" "yes" \
    "UsePAM" "yes" \
    "PermitEmptyPasswords" "no" \
    "MaxAuthTries" "3" \
  )"
  cp -a "$tmp_cur" "$tmp_final"
  rm -f "$tmp_cur"

  sshd -t -f "$tmp_final" >/dev/null 2>&1 || fail "sshd_config validation failed for proposed changes"

  if apply_file_if_changed "$f" 0644 root root "$tmp_final"; then
    changed "Updated SSH hardening in $f"
  fi
  rm -f "$tmp_final"

  reload_sshd || fail "Failed to reload sshd"
  changed "Reloaded sshd"
}

set_ssh_port() {
  command -v sshd >/dev/null 2>&1 || fail "sshd not found. Install openssh-server first."
  [[ "$FORCE" == "yes" ]] || fail_code 2 "Changing SSH port can lock you out. Re-run with --force."

  local f="/etc/ssh/sshd_config"
  [[ -f "$f" ]] || fail "Missing sshd config: $f"

  local tmp_final tmp_cur
  tmp_final="$(mktemp)"
  tmp_cur="$(sshd_build_updated_config "$f" "Port" "$SSH_PORT")"
  cp -a "$tmp_cur" "$tmp_final"
  rm -f "$tmp_cur"

  sshd -t -f "$tmp_final" >/dev/null 2>&1 || fail "sshd_config validation failed for proposed port change"

  if apply_file_if_changed "$f" 0644 root root "$tmp_final"; then
    changed "Set SSH port to $SSH_PORT in $f"
  fi
  rm -f "$tmp_final"

  reload_sshd || fail "Failed to reload sshd"
  changed "Reloaded sshd"
}

deny_root_console_login() {
  # Handle missing /etc/securetty
  local f="/etc/securetty"
  local pam_login="/etc/pam.d/login"

  if [[ -f "$pam_login" ]]; then
    if ! grep -qE "pam_securetty\.so" "$pam_login"; then
      warn "$pam_login does not reference pam_securetty.so. /etc/securetty may be ignored on this system."
    fi
  else
    warn "Missing $pam_login. Cannot verify pam_securetty usage."
  fi

  if [[ -f "$f" ]]; then
    if [[ ! -s "$f" ]]; then
      log "No change: $f already empty"
      return 0
    fi
    backup_file "$f"
    : >"$f" || fail "Failed to empty $f"
    chmod 0644 "$f" || fail "Failed chmod on $f"
    chown root:root "$f" || fail "Failed chown on $f"
    changed "Emptied $f to deny root console login"
  else
    install -m 0644 -o root -g root /dev/null "$f" || fail "Failed to create $f"
    changed "Created empty $f to deny root console login"
  fi
}

ensure_pam_access_enabled() {
  local f="/etc/pam.d/login"
  [[ -f "$f" ]] || fail "Missing file: $f"

  if grep -qE "^[[:space:]]*account[[:space:]]+required[[:space:]]+pam_access\.so" "$f"; then
    log "No change: pam_access already enabled in $f"
    return 0
  fi

  local tmp
  tmp="$(mktemp)"
  awk '
    BEGIN{ins=0}
    ins==0 && /^[[:space:]]*#/ {print; next}
    ins==0 {print "account required pam_access.so"; ins=1}
    {print}
  ' "$f" >"$tmp"

  if apply_file_if_changed "$f" 0644 root root "$tmp"; then
    changed "Enabled pam_access in $f"
  fi
  rm -f "$tmp"
}

configure_console_only_adm() {
  require_user_exists || return 1
  ensure_pam_access_enabled || return 1

  local f="/etc/security/access.conf"
  [[ -f "$f" ]] || fail "Missing file: $f"

  local tmp
  tmp="$(mktemp)"
  awk '
    BEGIN{skip=0}
    /^# BEGIN WG_HARDENING_CONSOLE_ONLY$/ {skip=1; next}
    /^# END WG_HARDENING_CONSOLE_ONLY$/   {skip=0; next}
    skip==0 {print}
  ' "$f" >"$tmp"

  cat >>"$tmp" <<EOF

# BEGIN WG_HARDENING_CONSOLE_ONLY
+ : ${ADM_USER} : LOCAL
- : ALL : LOCAL
# END WG_HARDENING_CONSOLE_ONLY
EOF

  if apply_file_if_changed "$f" 0644 root root "$tmp"; then
    changed "Restricted console login to ${ADM_USER} in $f"
  fi
  rm -f "$tmp"
}

configure_console_tmout() {
  local f="/etc/profile.d/00-wg-hardening-autologout.sh"
  local tmp
  tmp="$(mktemp)"

  cat >"$tmp" <<EOF
# Set TMOUT for interactive local console shells only.
case "\$-" in
  *i*)
    tty_path="\$(tty 2>/dev/null || true)"
    case "\$tty_path" in
      /dev/tty* )
        TMOUT=${TMOUT_SECONDS}
        readonly TMOUT
        export TMOUT
      ;;
    esac
  ;;
esac
EOF

  if apply_file_if_changed "$f" 0644 root root "$tmp"; then
    changed "Configured TMOUT ${TMOUT_SECONDS}s in $f"
  fi
  rm -f "$tmp"
}

detect_sshd_ports() {
  command -v sshd >/dev/null 2>&1 || return 1
  sshd -T 2>/dev/null \
    | awk 'BEGIN{IGNORECASE=1} $1=="port"{for(i=2;i<=NF;i++) print $i}' \
    | grep -E '^[0-9]+$' \
    | awk '$1>=1 && $1<=65535' \
    | sort -n | uniq
}

detect_wg_listening_ports() {
  command -v wg >/dev/null 2>&1 || return 1
  wg show all dump 2>/dev/null \
    | awk 'NF==5 {print $4}' \
    | grep -E '^[0-9]+$' \
    | awk '$1>=1 && $1<=65535' \
    | sort -n | uniq
}

ipv6_is_enabled() {
  [[ -r /proc/sys/net/ipv6/conf/all/disable_ipv6 ]] || return 1
  [[ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" == "0" ]]
}

sorted_list() { LC_ALL=C sort -u; }

firewall_warn_if_current_ssh_not_allowed() {
  [[ -n "${SSH_CONNECTION-}" ]] || return 0
  local client_ip
  client_ip="$(printf '%s' "$SSH_CONNECTION" | awk '{print $1}')"
  [[ -n "$client_ip" ]] || return 0

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$client_ip" "${SSH_ALLOW_LIST[@]}" <<'PY' || {
import ipaddress, sys
client = ipaddress.ip_address(sys.argv[1])
nets = [ipaddress.ip_network(s, strict=False) for s in sys.argv[2:]]
ok = any(client in n for n in nets)
sys.exit(0 if ok else 3)
PY
      fail "Current SSH client IP $client_ip is NOT included in --ssh-allow list"
      return 1
    }
  else
    warn "Cannot verify current SSH client IP against allow-list without python3"
  fi
}

iptables_apply_firewall() {
  command -v iptables >/dev/null 2>&1 || fail "iptables not found. Install iptables or use --fw-backend nftables."
  [[ "$FORCE" == "yes" ]] || fail_code 2 "Firewall config can lock you out. Re-run with --force."

  firewall_warn_if_current_ssh_not_allowed || return 1

  local -a ssh_ports=()
  local -a wg_ports=()

  if [[ "$SSH_PORT_EXPLICIT" == "yes" ]]; then
    ssh_ports=("$SSH_PORT")
  else
    mapfile -t ssh_ports < <(detect_sshd_ports || true)
    [[ "${#ssh_ports[@]}" -ge 1 ]] || fail "Cannot auto-detect SSH port. Provide --ssh-port."
  fi

  if [[ "$WG_PORT_EXPLICIT" == "yes" ]]; then
    wg_ports=("$WG_PORT")
  else
    mapfile -t wg_ports < <(detect_wg_listening_ports || true)
    [[ "${#wg_ports[@]}" -ge 1 ]] || fail "Cannot auto-detect WireGuard listening port. Provide --wg-port."
  fi

  log "Firewall backend: iptables"
  log "Firewall ports: SSH tcp ${ssh_ports[*]} | WG udp ${wg_ports[*]}"

  local -a v4=() v6=()
  local n
  for n in "${SSH_ALLOW_LIST[@]}"; do
    if [[ "$n" == *:* ]]; then v6+=("$n"); else v4+=("$n"); fi
  done
  [[ "${#v4[@]}" -gt 0 ]] && mapfile -t v4 < <(printf "%s\n" "${v4[@]}" | sorted_list)
  [[ "${#v6[@]}" -gt 0 ]] && mapfile -t v6 < <(printf "%s\n" "${v6[@]}" | sorted_list)

  local CHAIN="WG_HARDENING_INPUT"

  iptables -P INPUT DROP || fail "Failed setting INPUT policy DROP"
  iptables -N "$CHAIN" >/dev/null 2>&1 || true

  while iptables -C INPUT -j "$CHAIN" >/dev/null 2>&1; do
    iptables -D INPUT -j "$CHAIN" || true
  done
  iptables -I INPUT 1 -j "$CHAIN" || fail "Failed inserting jump to $CHAIN in INPUT"

  iptables -F "$CHAIN" || fail "Failed flushing $CHAIN"
  iptables -A "$CHAIN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || fail "Failed rule established"
  iptables -A "$CHAIN" -i lo -j ACCEPT || fail "Failed rule loopback"
  iptables -A "$CHAIN" -p icmp -j ACCEPT || fail "Failed rule icmp"
  local p net port
  for p in "${wg_ports[@]}"; do
    iptables -A "$CHAIN" -p udp --dport "$p" -j ACCEPT || fail "Failed WG rule udp/$p"
  done
  for net in "${v4[@]}"; do
    for port in "${ssh_ports[@]}"; do
      iptables -A "$CHAIN" -s "$net" -p tcp --dport "$port" -j ACCEPT || fail "Failed SSH allow $net tcp/$port"
    done
  done
  iptables -A "$CHAIN" -j DROP || fail "Failed final DROP"

  if ipv6_is_enabled; then
    command -v ip6tables >/dev/null 2>&1 || fail "IPv6 enabled but ip6tables not found."

    local CHAIN6="WG_HARDENING_INPUT"
    ip6tables -P INPUT DROP || fail "Failed setting IPv6 INPUT policy DROP"
    ip6tables -N "$CHAIN6" >/dev/null 2>&1 || true

    while ip6tables -C INPUT -j "$CHAIN6" >/dev/null 2>&1; do
      ip6tables -D INPUT -j "$CHAIN6" || true
    done
    ip6tables -I INPUT 1 -j "$CHAIN6" || fail "Failed inserting jump to $CHAIN6 in IPv6 INPUT"

    ip6tables -F "$CHAIN6" || fail "Failed flushing $CHAIN6"
    ip6tables -A "$CHAIN6" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || fail "Failed v6 established"
    ip6tables -A "$CHAIN6" -i lo -j ACCEPT || fail "Failed v6 loopback"
    ip6tables -A "$CHAIN6" -p ipv6-icmp -j ACCEPT || fail "Failed v6 icmp"
    for p in "${wg_ports[@]}"; do
      ip6tables -A "$CHAIN6" -p udp --dport "$p" -j ACCEPT || fail "Failed v6 WG udp/$p"
    done
    for net in "${v6[@]}"; do
      for port in "${ssh_ports[@]}"; do
        ip6tables -A "$CHAIN6" -s "$net" -p tcp --dport "$port" -j ACCEPT || fail "Failed v6 SSH allow $net tcp/$port"
      done
    done
    ip6tables -A "$CHAIN6" -j DROP || fail "Failed v6 final DROP"
  else
    log "IPv6 disabled: skipping ip6tables rules"
  fi

  changed "Applied iptables inbound firewall policy"

  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
    netfilter-persistent reload >/dev/null 2>&1 || true
    changed "Persisted firewall rules via netfilter-persistent"
  else
    warn "netfilter-persistent not found. Firewall rules may not persist after reboot."
  fi
}

join_nft_set() {
  local out="" x
  for x in "$@"; do
    [[ -n "$out" ]] && out+=", "
    out+="$x"
  done
  printf "%s" "$out"
}

nftables_apply_firewall() {
  command -v nft >/dev/null 2>&1 || fail "nft not found. Install nftables or use --fw-backend iptables."
  [[ "$FORCE" == "yes" ]] || fail_code 2 "Firewall replace can lock you out. Re-run with --force."

  firewall_warn_if_current_ssh_not_allowed || return 1

  local -a ssh_ports=()
  local -a wg_ports=()

  if [[ "$SSH_PORT_EXPLICIT" == "yes" ]]; then
    ssh_ports=("$SSH_PORT")
  else
    mapfile -t ssh_ports < <(detect_sshd_ports || true)
    [[ "${#ssh_ports[@]}" -ge 1 ]] || fail "Cannot auto-detect SSH port. Provide --ssh-port."
  fi

  if [[ "$WG_PORT_EXPLICIT" == "yes" ]]; then
    wg_ports=("$WG_PORT")
  else
    mapfile -t wg_ports < <(detect_wg_listening_ports || true)
    [[ "${#wg_ports[@]}" -ge 1 ]] || fail "Cannot auto-detect WireGuard listening port. Provide --wg-port."
  fi

  log "Firewall backend: nftables"
  log "Firewall ports: SSH tcp ${ssh_ports[*]} | WG udp ${wg_ports[*]}"

  local -a v4=() v6=()
  local n
  for n in "${SSH_ALLOW_LIST[@]}"; do
    if [[ "$n" == *:* ]]; then v6+=("$n"); else v4+=("$n"); fi
  done

  local ssh_ports_set wg_ports_set
  ssh_ports_set="$(join_nft_set "${ssh_ports[@]}")"
  wg_ports_set="$(join_nft_set "${wg_ports[@]}")"

  local f="/etc/nftables.conf"
  local tmp
  tmp="$(mktemp)"

  {
    echo "flush ruleset"
    echo ""
    echo "table inet wg_hardening {"
    echo "  chain input {"
    echo "    type filter hook input priority 0; policy drop;"
    echo "    ct state established,related accept"
    echo "    iifname lo accept"
    echo "    ip protocol icmp accept"
    echo "    ip6 nexthdr icmpv6 accept"
    echo "    udp dport { ${wg_ports_set} } accept"
    if [[ "${#v4[@]}" -gt 0 ]]; then
      printf "    tcp dport { %s } ip saddr { " "$ssh_ports_set"
      local i
      for i in "${!v4[@]}"; do
        [[ "$i" -gt 0 ]] && printf ", "
        printf "%s" "${v4[$i]}"
      done
      echo " } accept"
    fi
    if [[ "${#v6[@]}" -gt 0 ]]; then
      printf "    tcp dport { %s } ip6 saddr { " "$ssh_ports_set"
      local j
      for j in "${!v6[@]}"; do
        [[ "$j" -gt 0 ]] && printf ", "
        printf "%s" "${v6[$j]}"
      done
      echo " } accept"
    fi
    echo "  }"
    echo "  chain output { type filter hook output priority 0; policy accept; }"
    echo "}"
  } >"$tmp"

  nft -c -f "$tmp" >/dev/null 2>&1 || fail "nftables validation failed"

  [[ -f "$f" ]] && backup_file "$f"
  install -m 0644 -o root -g root "$tmp" "$f" || fail "Failed writing $f"
  rm -f "$tmp"
  changed "Wrote nftables config $f"

  nft -f "$f" >/dev/null 2>&1 || fail "Failed loading nftables ruleset from $f"
  changed "Loaded nftables ruleset"

  systemctl enable --now nftables >/dev/null 2>&1 || fail "Failed enabling nftables service"
  changed "Enabled nftables service"
}

configure_firewall() {
  case "$FW_BACKEND" in
    iptables) iptables_apply_firewall ;;
    nftables) nftables_apply_firewall ;;
    *) fail "Invalid firewall backend: $FW_BACKEND" ;;
  esac
}

print_summary() {
  log "Summary"
  if [[ "${#CHANGES[@]}" -eq 0 ]]; then
    log "No changes applied"
  else
    local i=1
    for c in "${CHANGES[@]}"; do
      printf "%s. %s\n" "$i" "$c"
      i=$((i+1))
    done
  fi

  if [[ "${#FAILURES[@]}" -gt 0 ]]; then
    printf "Failures:\n" >&2
    local j=1
    for f in "${FAILURES[@]}"; do
      printf "%s. %s\n" "$j" "$f" >&2
      j=$((j+1))
    done
  fi
}

main() {
  parse_args "$@"
  require_root
  log_selected_admin

  [[ "$DO_ADD_ADMIN" == "yes" ]] && run_action "add-admin" add_admin
  [[ "$DO_UPDATE_ADMIN" == "yes" ]] && run_action "update-admin" update_admin
  [[ "$DO_SUDO_NOPASSWD" == "yes" ]] && run_action "sudo-nopasswd" configure_passwordless_sudo
  [[ "$DO_INSTALL_SSH_KEY" == "yes" ]] && run_action "install-ssh-key" install_ssh_key
  [[ "$DO_HARDEN_SSH" == "yes" ]] && run_action "harden-ssh" harden_ssh
  [[ "$DO_SET_SSH_PORT" == "yes" ]] && run_action "set-ssh-port" set_ssh_port
  [[ "$DO_DENY_ROOT_CONSOLE" == "yes" ]] && run_action "deny-root-console" deny_root_console_login
  [[ "$DO_CONSOLE_ONLY_ADM" == "yes" ]] && run_action "console-only-adm" configure_console_only_adm
  [[ "$DO_CONSOLE_TMOUT" == "yes" ]] && run_action "console-tmout" configure_console_tmout
  [[ "$DO_CONFIGURE_FIREWALL" == "yes" ]] && run_action "configure-firewall" configure_firewall

  print_summary

  [[ "${#FAILURES[@]}" -eq 0 ]] && exit 0
  exit 1
}

main "$@"
