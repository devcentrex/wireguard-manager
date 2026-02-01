#!/usr/bin/env bash
set -euo pipefail

# dynu-ddns.sh
# Dynu DDNS updater with optional systemd timer install.
# Behavior:
# . Does nothing without explicit action flags
# . --run performs one update call
# . --install-systemd installs a timer + service + netrc credentials
# . --remove-systemd removes them

PROG="$(basename "$0")"
SCRIPT_SRC="$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")"

DEFAULT_API_BASE="https://api.dynu.com/nic/update"
DEFAULT_INTERVAL="5min"
DEFAULT_CONNECT="auto"   # auto | 4 | 6
DEFAULT_AUTH="basic"     # basic | query
DEFAULT_IPV4="auto"      # auto | no | <ip>
DEFAULT_IPV6="no"        # auto | no | <ip>

DYNU_DIR="/etc/dynu"
ENV_FILE="$DYNU_DIR/dynu-ddns.env"
NETRC_FILE="$DYNU_DIR/netrc"
INSTALL_PATH="/usr/local/sbin/dynu-ddns"

ACTION=""
CONFIG_FILE=""
HOSTNAME=""
ALIAS=""
GROUP=""
USERNAME=""
PASSWORD=""
PASSWORD_FROM_STDIN="no"
PASSWORD_PROMPT="no"
PASSWORD_FILE=""
HASH_MODE="plain"        # plain | md5 | sha256
AUTH_MODE="$DEFAULT_AUTH"
IPV4_MODE="$DEFAULT_IPV4"
IPV6_MODE="$DEFAULT_IPV6"
CONNECT_MODE="$DEFAULT_CONNECT"
INTERVAL="$DEFAULT_INTERVAL"
QUIET="no"

log() {
  if [[ "$QUIET" != "yes" ]]; then
    echo "$*" >&2
  fi
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"
}

is_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]]
}

usage() {
  cat <<'EOF'
dynu-ddns.sh

Usage
  dynu-ddns.sh --help
  dynu-ddns.sh --run [options]
  dynu-ddns.sh --install-systemd [options]
  dynu-ddns.sh --remove-systemd
  dynu-ddns.sh --status

Actions
  --run
    Perform one Dynu update call now.

  --install-systemd
    Install systemd service + timer.
    Copies this script to /usr/local/sbin/dynu-ddns
    Writes config to /etc/dynu/dynu-ddns.env
    Stores credentials in /etc/dynu/netrc

  --remove-systemd
    Remove the service + timer and optionally the /etc/dynu directory.

  --status
    Show current timer status and the latest journal entries.

Options
  --hostname FQDN
    Target hostname to update, example example.dynu.com
    Required for --run and --install-systemd unless provided via --config.

  --alias NAME
    Update alias or subdomain for hostname. Optional.

  --group NAME
    Update a Dynu group. Optional. When set, hostname is ignored by Dynu.

  --auth basic|query
    basic uses HTTP Authorization header
    query sends username and password in the URL querystring

  --username USER
  --password PASS
  --password-stdin
    Read password from stdin, example: printf '%s' 'secret' | ./dynu-ddns.sh --run --password-stdin ...
  --password-prompt
    Prompt for password securely
  --password-file PATH
    Read password from a file, first line only

  --hash plain|md5|sha256
    Hashing is supported by Dynu when sending password as a query parameter.
    Use --auth query with --hash md5 or --hash sha256.

  --ipv4 auto|no|IP
    auto uses special 10.0.0.0 which Dynu replaces with the source IPv4
    no disables IPv4 update
    IP sets a fixed IPv4

  --ipv6 auto|no|IP
    auto omits myipv6, allowing Dynu to use the source if available
    no disables IPv6 update
    IP sets a fixed IPv6

  --connect auto|4|6
    Force the HTTP connection family used by curl.
    Useful when using auto detection.

  --config PATH
    Load variables from a config file with KEY=VALUE lines.

  --interval DURATION
    systemd timer interval for --install-systemd.
    Examples: 5min 300s 1h

  --quiet
    Reduce logs

Config file keys for --config
  DYNU_HOSTNAME
  DYNU_ALIAS
  DYNU_GROUP
  DYNU_USERNAME
  DYNU_AUTH
  DYNU_IPV4
  DYNU_IPV6
  DYNU_CONNECT
  DYNU_NETRC

Examples
  1. One-shot update with basic auth and IPv4 auto-detect
     ./dynu-ddns.sh --run --hostname example.dynu.com --username u --password-prompt --ipv4 auto --ipv6 no

  2. One-shot update with hashed password in query mode
     ./dynu-ddns.sh --run --hostname example.dynu.com --username u --password-prompt --auth query --hash sha256 --ipv4 auto --ipv6 no

  3. Install systemd timer every 5 minutes
     sudo ./dynu-ddns.sh --install-systemd --hostname example.dynu.com --username u --password-prompt --interval 5min --ipv4 auto --ipv6 no
EOF
}

load_config_file() {
  local f="$1"
  [[ -f "$f" ]] || die "Config file not found: $f"

  # shellcheck disable=SC1090
  source "$f"

  HOSTNAME="${HOSTNAME:-${DYNU_HOSTNAME:-}}"
  ALIAS="${ALIAS:-${DYNU_ALIAS:-}}"
  GROUP="${GROUP:-${DYNU_GROUP:-}}"
  USERNAME="${USERNAME:-${DYNU_USERNAME:-}}"
  AUTH_MODE="${AUTH_MODE:-${DYNU_AUTH:-$AUTH_MODE}}"
  IPV4_MODE="${IPV4_MODE:-${DYNU_IPV4:-$IPV4_MODE}}"
  IPV6_MODE="${IPV6_MODE:-${DYNU_IPV6:-$IPV6_MODE}}"
  CONNECT_MODE="${CONNECT_MODE:-${DYNU_CONNECT:-$CONNECT_MODE}}"

  # If config provides a netrc path, prefer it.
  if [[ -n "${DYNU_NETRC:-}" ]]; then
    NETRC_FILE="$DYNU_NETRC"
  fi
}

read_password_if_needed() {
  if [[ -n "$PASSWORD" ]]; then
    return 0
  fi

  if [[ -n "$PASSWORD_FILE" ]]; then
    [[ -f "$PASSWORD_FILE" ]] || die "Password file not found: $PASSWORD_FILE"
    PASSWORD="$(head -n 1 "$PASSWORD_FILE" | tr -d '\r\n')"
    [[ -n "$PASSWORD" ]] || die "Password file is empty: $PASSWORD_FILE"
    return 0
  fi

  if [[ "$PASSWORD_FROM_STDIN" == "yes" ]]; then
    PASSWORD="$(cat | tr -d '\r\n')"
    [[ -n "$PASSWORD" ]] || die "Password from stdin is empty"
    return 0
  fi

  if [[ "$PASSWORD_PROMPT" == "yes" ]]; then
    read -r -s -p "Dynu password: " PASSWORD
    echo >&2
    [[ -n "$PASSWORD" ]] || die "Empty password"
    return 0
  fi
}

hash_password() {
  local mode="$1"
  local pass="$2"
  case "$mode" in
    plain) echo "$pass" ;;
    md5)
      need_cmd md5sum
      printf '%s' "$pass" | md5sum | awk '{print $1}'
      ;;
    sha256)
      need_cmd sha256sum
      printf '%s' "$pass" | sha256sum | awk '{print $1}'
      ;;
    *)
      die "Unsupported hash mode: $mode"
      ;;
  esac
}

curl_connect_flags() {
  case "$CONNECT_MODE" in
    auto) echo "" ;;
    4) echo "-4" ;;
    6) echo "-6" ;;
    *) die "Invalid --connect: $CONNECT_MODE. Use auto, 4, or 6." ;;
  esac
}

validate_modes() {
  case "$AUTH_MODE" in
    basic|query) ;;
    *) die "Invalid --auth: $AUTH_MODE. Use basic or query." ;;
  esac

  case "$HASH_MODE" in
    plain|md5|sha256) ;;
    *) die "Invalid --hash: $HASH_MODE. Use plain, md5, or sha256." ;;
  esac

  if [[ "$HASH_MODE" != "plain" && "$AUTH_MODE" == "basic" ]]; then
    die "--hash is intended for Dynu querystring password usage. Use --auth query with --hash md5 or --hash sha256."
  fi
}

build_url_query() {
  local -a q=()

  if [[ -n "$GROUP" ]]; then
    q+=("group=$GROUP")
  elif [[ -n "$HOSTNAME" ]]; then
    q+=("hostname=$HOSTNAME")
  else
    die "Missing --hostname or --group"
  fi

  if [[ -n "$ALIAS" ]]; then
    q+=("alias=$ALIAS")
  fi

  # IPv4
  case "$IPV4_MODE" in
    auto) q+=("myip=10.0.0.0") ;;
    no)   q+=("myip=no") ;;
    *)
      q+=("myip=$IPV4_MODE")
      ;;
  esac

  # IPv6
  case "$IPV6_MODE" in
    auto)
      # Omit myipv6 for auto behavior
      ;;
    no)
      q+=("myipv6=no")
      ;;
    *)
      q+=("myipv6=$IPV6_MODE")
      ;;
  esac

  printf '%s\n' "${q[@]}"
}

run_update() {
  need_cmd curl
  validate_modes

  local connect_flags
  connect_flags="$(curl_connect_flags)"

  local resp=""
  local rc=0

  if [[ "$AUTH_MODE" == "basic" ]]; then
    # Prefer netrc if present to avoid password in args.
    # If username/password are provided, use -u.
    local -a curl_args=( -fsS )
    if [[ -n "$connect_flags" ]]; then curl_args+=( "$connect_flags" ); fi
    curl_args+=( -H "User-Agent: dynu-ddns.sh" )

    if [[ -f "$NETRC_FILE" ]]; then
      curl_args+=( --netrc-file "$NETRC_FILE" )
    elif [[ -n "$USERNAME" ]]; then
      read_password_if_needed
      curl_args+=( -u "${USERNAME}:${PASSWORD}" )
    else
      die "No credentials. Provide --username and --password-prompt, or create netrc at $NETRC_FILE"
    fi

    # Use --get with --data-urlencode for safe encoding
    local -a query
    mapfile -t query < <(build_url_query)

    # Build curl request
    local -a data_args=( --get )
    for kv in "${query[@]}"; do
      data_args+=( --data-urlencode "$kv" )
    done

    set +e
    resp="$(curl "${curl_args[@]}" "${data_args[@]}" "$DEFAULT_API_BASE" 2>&1)"
    rc=$?
    set -e
  else
    # query auth
    [[ -n "$USERNAME" ]] || die "Missing --username for --auth query"
    read_password_if_needed
    local pass_out
    pass_out="$(hash_password "$HASH_MODE" "$PASSWORD")"

    local -a curl_args=( -fsS )
    if [[ -n "$connect_flags" ]]; then curl_args+=( "$connect_flags" ); fi
    curl_args+=( -H "User-Agent: dynu-ddns.sh" )

    local -a query
    mapfile -t query < <(build_url_query)
    query+=( "username=$USERNAME" "password=$pass_out" )

    local -a data_args=( --get )
    for kv in "${query[@]}"; do
      data_args+=( --data-urlencode "$kv" )
    done

    set +e
    resp="$(curl "${curl_args[@]}" "${data_args[@]}" "$DEFAULT_API_BASE" 2>&1)"
    rc=$?
    set -e
  fi

  if [[ $rc -ne 0 ]]; then
    echo "$resp"
    return $rc
  fi

  # Dynu returns one-word codes, possibly multiple lines for multiple hosts.
  # Treat good and nochg as success, anything else as failure.
  local ok="yes"
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    local code="${line%% *}"
    case "$code" in
      good|nochg) ;;
      *) ok="no" ;;
    esac
  done <<<"$resp"

  echo "$resp"

  if [[ "$ok" == "yes" ]]; then
    return 0
  fi
  return 2
}

write_netrc() {
  local user="$1"
  local pass="$2"
  install -d -m 0700 "$DYNU_DIR"
  cat >"$NETRC_FILE" <<EOF
machine api.dynu.com
  login $user
  password $pass
EOF
  chmod 0600 "$NETRC_FILE"
}

write_env_file() {
  install -d -m 0700 "$DYNU_DIR"
  cat >"$ENV_FILE" <<EOF
DYNU_HOSTNAME=${HOSTNAME}
DYNU_ALIAS=${ALIAS}
DYNU_GROUP=${GROUP}
DYNU_USERNAME=${USERNAME}
DYNU_AUTH=${AUTH_MODE}
DYNU_IPV4=${IPV4_MODE}
DYNU_IPV6=${IPV6_MODE}
DYNU_CONNECT=${CONNECT_MODE}
DYNU_NETRC=${NETRC_FILE}
EOF
  chmod 0600 "$ENV_FILE"
}

install_systemd() {
  is_root || die "--install-systemd requires root"

  need_cmd systemctl
  need_cmd install
  need_cmd curl || true

  if ! command -v curl >/dev/null 2>&1; then
    log "curl is missing. Installing curl via apt."
    need_cmd apt-get
    apt-get update -y
    apt-get install -y curl
  fi

  [[ -n "$HOSTNAME" || -n "$GROUP" ]] || die "Missing --hostname or --group for --install-systemd"
  [[ -n "$USERNAME" ]] || die "Missing --username for --install-systemd"

  if [[ "$AUTH_MODE" == "query" ]]; then
    read_password_if_needed
    local pass_out
    pass_out="$(hash_password "$HASH_MODE" "$PASSWORD")"
    write_netrc "$USERNAME" "$pass_out"
    AUTH_MODE="basic"
    log "Note: systemd install stores credentials in netrc and uses basic auth for runtime."
    log "If you require query auth at runtime, do not use --install-systemd. Use --run via your own scheduler."
  else
    # For basic auth, store plain password in netrc.
    read_password_if_needed
    write_netrc "$USERNAME" "$PASSWORD"
  fi

  write_env_file

  install -m 0755 "$SCRIPT_SRC" "$INSTALL_PATH"

  cat >/etc/systemd/system/dynu-ddns.service <<EOF
[Unit]
Description=Dynu DDNS update

[Service]
Type=oneshot
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_PATH --run --config $ENV_FILE
EOF

  cat >/etc/systemd/system/dynu-ddns.timer <<EOF
[Unit]
Description=Run Dynu DDNS update periodically

[Timer]
OnBootSec=30s
OnUnitActiveSec=$INTERVAL
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now dynu-ddns.timer

  log "Installed:"
  log ". Script: $INSTALL_PATH"
  log ". Config: $ENV_FILE"
  log ". Netrc:  $NETRC_FILE"
  log ". Timer:  dynu-ddns.timer"
}

remove_systemd() {
  is_root || die "--remove-systemd requires root"
  need_cmd systemctl

  systemctl disable --now dynu-ddns.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/dynu-ddns.timer
  rm -f /etc/systemd/system/dynu-ddns.service
  systemctl daemon-reload

  log "Removed systemd units."
  log "Left files in $DYNU_DIR and $INSTALL_PATH in place."
  log "Delete them manually if you want:"
  log ". sudo rm -f $INSTALL_PATH"
  log ". sudo rm -rf $DYNU_DIR"
}

status_systemd() {
  need_cmd systemctl
  systemctl status dynu-ddns.timer --no-pager -l || true
  echo
  journalctl -u dynu-ddns.service -n 20 --no-pager || true
}

# -------- arg parsing --------

if [[ $# -eq 0 ]]; then
  usage
  exit 2
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;

    --run) ACTION="run"; shift ;;
    --install-systemd) ACTION="install"; shift ;;
    --remove-systemd) ACTION="remove"; shift ;;
    --status) ACTION="status"; shift ;;

    --config) CONFIG_FILE="${2:-}"; shift 2 ;;
    --hostname) HOSTNAME="${2:-}"; shift 2 ;;
    --alias) ALIAS="${2:-}"; shift 2 ;;
    --group) GROUP="${2:-}"; shift 2 ;;

    --username) USERNAME="${2:-}"; shift 2 ;;
    --password) PASSWORD="${2:-}"; shift 2 ;;
    --password-stdin) PASSWORD_FROM_STDIN="yes"; shift ;;
    --password-prompt) PASSWORD_PROMPT="yes"; shift ;;
    --password-file) PASSWORD_FILE="${2:-}"; shift 2 ;;

    --auth) AUTH_MODE="${2:-}"; shift 2 ;;
    --hash) HASH_MODE="${2:-}"; shift 2 ;;

    --ipv4) IPV4_MODE="${2:-}"; shift 2 ;;
    --ipv6) IPV6_MODE="${2:-}"; shift 2 ;;
    --connect) CONNECT_MODE="${2:-}"; shift 2 ;;
    --interval) INTERVAL="${2:-}"; shift 2 ;;

    --quiet) QUIET="yes"; shift ;;

    *)
      die "Unknown argument: $1. Use --help."
      ;;
  esac
done

# Load config file late so it can fill missing flags.
if [[ -n "$CONFIG_FILE" ]]; then
  load_config_file "$CONFIG_FILE"
fi

case "$ACTION" in
  run)
    # For basic auth, netrc is preferred. If netrc is missing, fall back to --username + password.
    # For query auth, username + password are required.
    if [[ -z "$GROUP" && -z "$HOSTNAME" ]]; then
      die "Missing --hostname or --group for --run"
    fi
    run_update
    ;;
  install)
    install_systemd
    ;;
  remove)
    remove_systemd
    ;;
  status)
    status_systemd
    ;;
  *)
    usage
    exit 2
    ;;
esac
