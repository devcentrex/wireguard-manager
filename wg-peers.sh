#!/usr/bin/env bash
# wg-peers-v3.sh — Smart/flexible WireGuard peer manager for Ubuntu 22.04 server.
#
# Goals:
# - Works for BOTH keying models:
#   (A) Server-generated client keys (default) -> produces ready client .conf + optional QR
#   (B) Client-generated keys (BYO) -> you provide --pubkey; script can still:
#       - add the peer on the server
#       - generate a client TEMPLATE (no PrivateKey) + peer-info (PSK, Address, etc.)
#
# Server files expected:
#   /etc/wireguard/<iface>.conf
# Optional defaults used for client config generation:
#   /etc/wireguard/<iface>.endpoint           (server endpoint; host[:port] or host only)
#   /etc/wireguard/<iface>.dns                (DNS for client config)
#   /etc/wireguard/<iface>.client-allowedips  (AllowedIPs for client config; default full-tunnel)
#
# Client artifacts stored:
#   /etc/wireguard/clients/<iface>/<name>/
#     publickey
#     privatekey            (only if known on server; server-generated or imported)
#     psk                   (if used)
#     <name>.conf           (full config only if privatekey known and --no-client-files not set)
#     <name>.template.conf  (template if privatekey unknown)
#     peer-info.txt         (human-friendly details)
#     meta
#
# Commands:
#   add <name> [options]
#   list
#   show <name>
#   qr <name>
#   disable <name>
#   enable <name>
#   revoke <name> [--purge]
#
# Examples:
#   # A) Server-generated keys (ready config + QR):
#   sudo bash ./wg-peers-v3.sh add alice --iface wg0 --ip4 10.27.255.101 --endpoint vmx-prt-vpn-04.ddnsfree.com:51820 --qr
#
#   # B) BYO keys (client behind NAT; you only provide PublicKey):
#   sudo bash ./wg-peers-v3.sh add phone1 --iface wg0 --ip4 10.27.255.100 --pubkey 'CLIENT_PUBLIC_KEY' --endpoint vmx-prt-vpn-04.ddnsfree.com:51820
#   # -> server peer added; template + peer-info generated (no PrivateKey).
#
# Notes:
# - NAT on client side is OK; client config uses PersistentKeepalive (default 25s).
# - This script edits /etc/wireguard/<iface>.conf using BEGIN/END markers, then applies via wg syncconf.

set -euo pipefail
umask 077

log(){ echo "[$(date -Is)] $*" >&2; }
die(){ echo "ERROR: $*" >&2; exit 1; }
need_root(){ [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root (sudo)."; }
have_cmd(){ command -v "$1" >/dev/null 2>&1; }

IFACE="wg0"
BASE_DIR="/etc/wireguard"
KEYS_DIR="${BASE_DIR}/keys"
CLIENTS_DIR="${BASE_DIR}/clients"

conf_path(){ echo "${BASE_DIR}/${IFACE}.conf"; }
defaults_endpoint_file(){ echo "${BASE_DIR}/${IFACE}.endpoint"; }                 # host[:port] or host only
defaults_dns_file(){ echo "${BASE_DIR}/${IFACE}.dns"; }                           # e.g. 1.1.1.1
defaults_client_allowed_file(){ echo "${BASE_DIR}/${IFACE}.client-allowedips"; }  # e.g. 0.0.0.0/0,::/0

client_dir(){ echo "${CLIENTS_DIR}/${IFACE}/$1"; }
client_conf(){ echo "$(client_dir "$1")/$1.conf"; }
client_template(){ echo "$(client_dir "$1")/$1.template.conf"; }
peer_info(){ echo "$(client_dir "$1")/peer-info.txt"; }

usage() {
  cat <<'EOF'
Usage: sudo bash ./wg-peers-v3.sh <command> [args]

Commands:
  add <name>
      [--iface wg0]
      [--ip4 x.x.x.x]                 (if omitted, auto-allocates next free IPv4)
      [--endpoint host[:port]]         (default: /etc/wireguard/<iface>.endpoint; port defaults to server ListenPort)
      [--dns "ip[,ip]"]               (default: /etc/wireguard/<iface>.dns)
      [--client-allowed "cidr,cidr"]  (default: /etc/wireguard/<iface>.client-allowedips)
      [--server-extra-allowed "cidr,cidr"]   (routes behind peer; appended to server AllowedIPs)
      [--keepalive 25]                (client PersistentKeepalive; default 25)
      [--no-psk]                       (do not use a preshared key)
      [--psk "BASE64"]                 (provide preshared key explicitly)
      [--pubkey "BASE64"]              (BYO client public key; script will NOT know PrivateKey)
      [--privkey-file /path/key]       (optional: import client private key from file; public key derived)
      [--no-client-files]              (do not write any client config/template files)
      [--qr]                           (print QR for full client config; requires PrivateKey to be known)

  list [--iface wg0]
  show <name> [--iface wg0]
  qr <name> [--iface wg0]
  disable <name> [--iface wg0]
  enable <name> [--iface wg0]
  revoke <name> [--iface wg0] [--purge]

EOF
}

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  cp -a "$f" "${f}.bak.$(date +%Y%m%d%H%M%S)"
}

read_default() {
  local f="$1"
  [[ -f "$f" ]] && cat "$f" || true
}

ensure_dirs() {
  install -d -m 700 "$BASE_DIR" "$CLIENTS_DIR" "${CLIENTS_DIR}/${IFACE}"
}

sanitize_name() {
  local n="$1"
  [[ "$n" =~ ^[A-Za-z0-9._-]+$ ]] || die "Invalid name '$n' (allowed: A-Z a-z 0-9 . _ -)."
}

lock_or_die() {
  local lockfile="${BASE_DIR}/.${IFACE}.wg-peers-v3.lock"
  if have_cmd flock; then
    exec 200>"$lockfile"
    flock -n 200 || die "Another wg-peers-v3.sh is running for iface ${IFACE}."
  else
    if [[ -e "$lockfile" ]]; then die "Lock exists: $lockfile"; fi
    : >"$lockfile"
    trap 'rm -f "$lockfile"' EXIT
  fi
}

require_server_conf() {
  [[ -f "$(conf_path)" ]] || die "Missing server config: $(conf_path)"
}

require_tools() {
  have_cmd wg || die "Missing 'wg'. Install: apt-get install -y wireguard-tools"
  have_cmd wg-quick || die "Missing 'wg-quick'. Install: apt-get install -y wireguard"
}

ensure_qrencode() {
  if ! have_cmd qrencode; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y qrencode >/dev/null
  fi
}

normalize_csv() {
  echo "$1" | tr ',' '\n' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g' | grep -v '^$' | paste -sd ', ' -
}

# ---------- Parse server config ----------
server_listen_port() {
  awk '
    BEGIN{inif=0}
    /^\[Interface\]/{inif=1; next}
    /^\[/{inif=0}
    inif && $1=="ListenPort" {print $3; exit}
  ' "$(conf_path)" | tr -d '\r'
}

server_ipv4_cidr() {
  awk '
    BEGIN{inif=0}
    /^\[Interface\]/{inif=1; next}
    /^\[/{inif=0}
    inif && $1=="Address" {
      addr=$3
      gsub(/\r/,"",addr)
      n=split(addr,parts,",")
      for(i=1;i<=n;i++){
        gsub(/[[:space:]]+/,"",parts[i])
        if(parts[i] ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/){ print parts[i]; exit }
      }
    }
  ' "$(conf_path)"
}

server_ipv4(){ server_ipv4_cidr | awk -F/ '{print $1}'; }

server_ipv4_net() {
  local cidr; cidr="$(server_ipv4_cidr)"
  [[ -n "$cidr" ]] || die "Could not read server IPv4 Address from $(conf_path) [Interface]."
  python3 - <<PY
import ipaddress
iface = ipaddress.ip_interface("${cidr}")
print(str(iface.network))
PY
}

extract_used_ipv4() {
  grep -E '^[[:space:]]*AllowedIPs[[:space:]]*=' "$(conf_path)" \
    | sed -E 's/.*=[[:space:]]*//g' \
    | tr ',' '\n' \
    | sed -E 's/[[:space:]]+//g' \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/32$' \
    | awk -F/ '{print $1}' \
    | sort -u
}

validate_ip4_in_subnet_or_die() {
  local ip="$1" net="$2"
  python3 - <<PY
import ipaddress, sys
ip = ipaddress.ip_address("${ip}")
net = ipaddress.ip_network("${net}", strict=False)
sys.exit(0 if ip in net else 1)
PY
}

allocate_next_ipv4() {
  local net="$1" srv="$2"
  local used; used="$(extract_used_ipv4 | tr '\n' ' ')"
  python3 - <<PY
import ipaddress
net = ipaddress.ip_network("${net}", strict=False)
srv = ipaddress.ip_address("${srv}")
used = set(ipaddress.ip_address(s) for s in "${used}".split() if s)
for h in net.hosts():
  if h == srv:
    continue
  if h not in used:
    print(str(h))
    raise SystemExit(0)
raise SystemExit("No free IPv4 addresses in %s" % net)
PY
}

# ---------- Endpoint normalization ----------
# If endpoint has no explicit port, append server ListenPort (or 51820).
normalize_endpoint() {
  local ep="$1"
  local port="$2"

  # IPv6 endpoints must be in [addr]:port. If user gives "[...]:1234", keep.
  if [[ "$ep" =~ \]:[0-9]+$ ]]; then
    echo "$ep"; return 0
  fi
  # IPv4/hostname with :port
  if [[ "$ep" =~ :[0-9]+$ ]]; then
    echo "$ep"; return 0
  fi
  echo "${ep}:${port}"
}

# ---------- Peer block management ----------
peer_exists() {
  local name="$1"
  grep -qE "^# BEGIN_PEER[[:space:]]+${name}\$" "$(conf_path)"
}

peer_pubkey_from_block() {
  local name="$1"
  awk -v n="$name" '
    $0 ~ "^# BEGIN_PEER[[:space:]]+" n "$" {inblk=1}
    inblk && $1=="PublicKey" && $2=="=" {print $3; exit}
    inblk && $0 ~ "^#PublicKey[[:space:]]*=" {
      line=$0; sub("^#","",line); gsub(/[[:space:]]+/," ",line); split(line,a," "); print a[3]; exit
    }
    $0 ~ "^# END_PEER[[:space:]]+" n "$" {inblk=0}
  ' "$(conf_path)"
}

append_peer_block() {
  local block="$1"
  printf "\n%s\n" "$block" >>"$(conf_path)"
  chmod 600 "$(conf_path)"
}

remove_peer_block() {
  local name="$1"
  awk -v n="$name" '
    $0 ~ "^# BEGIN_PEER[[:space:]]+" n "$" {inblk=1; next}
    $0 ~ "^# END_PEER[[:space:]]+" n "$" {inblk=0; next}
    !inblk {print}
  ' "$(conf_path)" >"$(conf_path).tmp"
  mv "$(conf_path).tmp" "$(conf_path)"
  chmod 600 "$(conf_path)"
}

set_peer_disabled_state() {
  local name="$1" want="$2" # disable|enable
  local f; f="$(conf_path)"

  awk -v n="$name" -v want="$want" '
    function startswith(s,p){ return index(s,p)==1 }
    BEGIN{inblk=0}
    $0 ~ "^# BEGIN_PEER[[:space:]]+" n "$" {inblk=1; print; next}
    $0 ~ "^# END_PEER[[:space:]]+" n "$" {inblk=0; print; next}
    {
      if (!inblk) { print; next }
      if (want=="disable") {
        if ($0 ~ "^# DISABLED = true$") { print; next }
        if ($0 ~ "^\\[Peer\\]") { print "# DISABLED = true"; print "#[Peer]"; next }
        if ($0 ~ "^(PublicKey|PresharedKey|AllowedIPs)[[:space:]]*=") { print "#" $0; next }
        print (startswith($0,"#") ? $0 : "#" $0)
        next
      } else if (want=="enable") {
        if ($0 ~ "^# DISABLED = true$") { next }
        if ($0 ~ "^#\\[Peer\\]") { sub("^#",""); print; next }
        if ($0 ~ "^#(PublicKey|PresharedKey|AllowedIPs)[[:space:]]*=") { sub("^#",""); print; next }
        print
        next
      }
      print
    }
  ' "$f" >"${f}.tmp"
  mv "${f}.tmp" "$f"
  chmod 600 "$f"
}

peer_block_enabled() {
  local name="$1" pub="$2" psk_line="$3" allowed="$4"
  cat <<EOF
# BEGIN_PEER ${name}
[Peer]
PublicKey = ${pub}
${psk_line}AllowedIPs = ${allowed}
# END_PEER ${name}
EOF
}

# ---------- Runtime apply ----------
apply_runtime() {
  if wg show "$IFACE" >/dev/null 2>&1; then
    wg syncconf "$IFACE" <(wg-quick strip "$IFACE")
  else
    systemctl restart "wg-quick@${IFACE}" >/dev/null
  fi
}

# ---------- Key handling ----------
server_pubkey() {
  local pub="${KEYS_DIR}/server.pub"
  if [[ -f "$pub" ]]; then
    cat "$pub"
  else
    wg show "$IFACE" public-key 2>/dev/null || die "Cannot read server public key (missing ${KEYS_DIR}/server.pub and iface down)."
  fi
}

gen_or_import_client_keys() {
  # Produces in client_dir:
  #   privatekey (optional), publickey (always), psk (optional)
  local name="$1" pubkey_arg="$2" privkey_file="$3" psk_arg="$4" no_psk="$5"
  local d; d="$(client_dir "$name")"
  install -d -m 700 "$d"

  local priv="${d}/privatekey"
  local pub="${d}/publickey"
  local psk="${d}/psk"

  # Public key path:
  if [[ -n "$privkey_file" ]]; then
    [[ -f "$privkey_file" ]] || die "--privkey-file not found: $privkey_file"
    cat "$privkey_file" >"$priv"
    chmod 600 "$priv"
    wg pubkey <"$priv" >"$pub"
    chmod 600 "$pub"
  elif [[ -n "$pubkey_arg" ]]; then
    echo -n "$pubkey_arg" >"$pub"
    chmod 600 "$pub"
    # privatekey intentionally unknown
    rm -f "$priv" 2>/dev/null || true
  else
    # server-generated
    wg genkey >"$priv"
    chmod 600 "$priv"
    wg pubkey <"$priv" >"$pub"
    chmod 600 "$pub"
  fi

  # PSK:
  if [[ "$no_psk" -eq 1 ]]; then
    rm -f "$psk" 2>/dev/null || true
  else
    if [[ -n "$psk_arg" ]]; then
      echo -n "$psk_arg" >"$psk"
      chmod 600 "$psk"
    else
      # generate if missing
      if [[ ! -f "$psk" ]]; then
        wg genpsk >"$psk"
        chmod 600 "$psk"
      fi
    fi
  fi
}

write_peer_info() {
  local name="$1" endpoint="$2" dns="$3" client_allowed="$4" ip4="$5" keepalive="$6"
  local d; d="$(client_dir "$name")"
  local pub; pub="$(cat "${d}/publickey")"
  local psk_line=""
  if [[ -f "${d}/psk" ]]; then
    psk_line="$(cat "${d}/psk")"
  fi

  cat >"$(peer_info "$name")" <<EOF
Peer name:            ${name}
Interface:            ${IFACE}
Client address:       ${ip4}/32
Server endpoint:      ${endpoint}
Client AllowedIPs:    ${client_allowed}
Client DNS:           ${dns}
Client keepalive:     ${keepalive}

Client public key:    ${pub}
Preshared key:        ${psk_line}

Server public key:    $(server_pubkey)

Notes:
- If PrivateKey is NOT in the generated files, you must place the client's PrivateKey in the client config manually.
- Client behind NAT: keepalive helps keep the NAT UDP mapping open.
EOF
  chmod 600 "$(peer_info "$name")"
}

write_client_config_or_template() {
  local name="$1" endpoint="$2" dns="$3" client_allowed="$4" ip4="$5" keepalive="$6" no_client_files="$7"
  [[ "$no_client_files" -eq 1 ]] && return 0

  local d; d="$(client_dir "$name")"
  local psk=""
  [[ -f "${d}/psk" ]] && psk="$(cat "${d}/psk")"
  local spub; spub="$(server_pubkey)"

  dns="$(normalize_csv "$dns")"
  client_allowed="$(normalize_csv "$client_allowed")"

  if [[ -f "${d}/privatekey" ]]; then
    local priv; priv="$(cat "${d}/privatekey")"
    cat >"$(client_conf "$name")" <<EOF
# ${name} — generated by wg-peers-v3.sh on $(date -Is)
[Interface]
PrivateKey = ${priv}
Address = ${ip4}/32
DNS = ${dns}

[Peer]
PublicKey = ${spub}
$( [[ -n "$psk" ]] && echo "PresharedKey = ${psk}" )
Endpoint = ${endpoint}
AllowedIPs = ${client_allowed}
PersistentKeepalive = ${keepalive}
EOF
    chmod 600 "$(client_conf "$name")"
    rm -f "$(client_template "$name")" 2>/dev/null || true
  else
    # BYO public key only -> write template (no PrivateKey)
    cat >"$(client_template "$name")" <<EOF
# ${name} — TEMPLATE (PrivateKey unknown to server)
# Replace <CLIENT_PRIVATE_KEY> with the client's PrivateKey.
[Interface]
PrivateKey = <CLIENT_PRIVATE_KEY>
Address = ${ip4}/32
DNS = ${dns}

[Peer]
PublicKey = ${spub}
$( [[ -n "$psk" ]] && echo "PresharedKey = ${psk}" )
Endpoint = ${endpoint}
AllowedIPs = ${client_allowed}
PersistentKeepalive = ${keepalive}
EOF
    chmod 600 "$(client_template "$name")"
    rm -f "$(client_conf "$name")" 2>/dev/null || true
  fi
}

write_meta() {
  local name="$1" endpoint="$2" dns="$3" client_allowed="$4" ip4="$5" keepalive="$6"
  local d; d="$(client_dir "$name")"
  cat >"${d}/meta" <<EOF
name=${name}
iface=${IFACE}
ip4=${ip4}
endpoint=${endpoint}
dns=${dns}
client_allowed=${client_allowed}
keepalive=${keepalive}
created=$(date -Is)
EOF
  chmod 600 "${d}/meta"
}

# ---------- Commands ----------
cmd_add() {
  local name="$1"; shift
  sanitize_name "$name"

  local endpoint="" dns="" client_allowed="" ip4="" server_extra_allowed=""
  local keepalive="25"
  local want_qr=0 no_client_files=0
  local pubkey_arg="" privkey_file="" psk_arg="" no_psk=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --iface) IFACE="$2"; shift 2 ;;
      --endpoint) endpoint="$2"; shift 2 ;;
      --dns) dns="$2"; shift 2 ;;
      --client-allowed) client_allowed="$2"; shift 2 ;;
      --server-extra-allowed) server_extra_allowed="$2"; shift 2 ;;
      --ip4) ip4="$2"; shift 2 ;;
      --keepalive) keepalive="$2"; shift 2 ;;
      --pubkey) pubkey_arg="$2"; shift 2 ;;
      --privkey-file) privkey_file="$2"; shift 2 ;;
      --psk) psk_arg="$2"; shift 2 ;;
      --no-psk) no_psk=1; shift 1 ;;
      --no-client-files) no_client_files=1; shift 1 ;;
      --qr) want_qr=1; shift 1 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown arg: $1" ;;
    esac
  done

  require_tools
  require_server_conf
  lock_or_die
  ensure_dirs

  local port; port="$(server_listen_port)"
  [[ -n "$port" ]] || port="51820"

  endpoint="${endpoint:-$(read_default "$(defaults_endpoint_file)")}"
  dns="${dns:-$(read_default "$(defaults_dns_file)")}"
  client_allowed="${client_allowed:-$(read_default "$(defaults_client_allowed_file)")}"

  [[ -n "$endpoint" ]] || die "Missing --endpoint and no default at $(defaults_endpoint_file)"
  [[ -n "$dns" ]] || dns="1.1.1.1"
  [[ -n "$client_allowed" ]] || client_allowed="0.0.0.0/0,::/0"

  endpoint="$(normalize_endpoint "$endpoint" "$port")"
  dns="$(normalize_csv "$dns")"
  client_allowed="$(normalize_csv "$client_allowed")"

  [[ "$keepalive" =~ ^[0-9]+$ ]] || die "--keepalive must be an integer seconds"
  (( keepalive >= 0 && keepalive <= 3600 )) || die "--keepalive out of range (0..3600)"

  if peer_exists "$name"; then
    die "Peer '${name}' already exists in $(conf_path)"
  fi

  local net srv
  net="$(server_ipv4_net)"
  srv="$(server_ipv4)"
  [[ -n "$srv" ]] || die "Could not read server IPv4 from $(conf_path) [Interface]."

  if [[ -n "$ip4" ]]; then
    validate_ip4_in_subnet_or_die "$ip4" "$net" || die "--ip4 ${ip4} is not inside server subnet ${net}"
    [[ "$ip4" != "$srv" ]] || die "--ip4 ${ip4} equals server IP ${srv}"
    if extract_used_ipv4 | grep -qx "$ip4"; then
      die "--ip4 ${ip4} is already used in server config"
    fi
  else
    ip4="$(allocate_next_ipv4 "$net" "$srv")"
  fi

  # Generate/import keys
  gen_or_import_client_keys "$name" "$pubkey_arg" "$privkey_file" "$psk_arg" "$no_psk"
  local d; d="$(client_dir "$name")"
  local cpub; cpub="$(cat "${d}/publickey")"

  # Server-side AllowedIPs: peer /32 plus optional routed networks behind peer.
  local server_allowed="${ip4}/32"
  if [[ -n "$server_extra_allowed" ]]; then
    server_extra_allowed="$(normalize_csv "$server_extra_allowed")"
    server_allowed="${server_allowed}, ${server_extra_allowed}"
  fi

  local psk_line=""
  if [[ -f "${d}/psk" ]]; then
    psk_line="PresharedKey = $(cat "${d}/psk")"$'\n'
  fi

  backup_file "$(conf_path)"
  append_peer_block "$(peer_block_enabled "$name" "$cpub" "$psk_line" "$server_allowed")"
  apply_runtime

  write_peer_info "$name" "$endpoint" "$dns" "$client_allowed" "$ip4" "$keepalive"
  write_client_config_or_template "$name" "$endpoint" "$dns" "$client_allowed" "$ip4" "$keepalive" "$no_client_files"
  write_meta "$name" "$endpoint" "$dns" "$client_allowed" "$ip4" "$keepalive"

  # Output: show where artifacts are
  echo "$(client_dir "$name")"

  # QR only possible when full client config exists (PrivateKey known)
  if [[ $want_qr -eq 1 ]]; then
    [[ -f "$(client_conf "$name")" ]] || die "QR requested but PrivateKey is not available on server (BYO mode). Use template or import via --privkey-file."
    ensure_qrencode
    echo
    qrencode -t ansiutf8 <"$(client_conf "$name")"
  fi
}

cmd_list() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --iface) IFACE="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown arg: $1" ;;
    esac
  done

  require_tools
  require_server_conf

  local peers_runtime=""
  if wg show "$IFACE" >/dev/null 2>&1; then
    peers_runtime="$(wg show "$IFACE" peers 2>/dev/null | tr '\n' ' ')"
  fi

  awk -v rt="$peers_runtime" '
    function in_runtime(pub) {
      if (rt=="") return "down"
      return (index(" " rt " ", " " pub " ")>0) ? "up" : "down"
    }
    /^# BEGIN_PEER / {name=$3; disabled=0; pub=""; allowed=""}
    /^# DISABLED = true/ {disabled=1}
    /^PublicKey =/ {pub=$3}
    /^#PublicKey[[:space:]]*=/ { line=$0; sub("^#","",line); gsub(/[[:space:]]+/," ",line); split(line,a," "); pub=a[3] }
    /^AllowedIPs =/ {allowed=substr($0, index($0,"=")+2)}
    /^#AllowedIPs[[:space:]]*=/ {allowed=substr($0, index($0,"=")+2)}
    /^# END_PEER / {
      if (name!="") {
        state = disabled ? "disabled" : "enabled"
        printf "%-20s %-8s %-4s %-44s %s\n", name, state, in_runtime(pub), pub, allowed
      }
      name=""
    }
  ' "$(conf_path)"
}

cmd_show() {
  local name="$1"; shift
  sanitize_name "$name"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --iface) IFACE="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown arg: $1" ;;
    esac
  done

  local d; d="$(client_dir "$name")"
  [[ -d "$d" ]] || die "No client directory: $d"

  if [[ -f "$(client_conf "$name")" ]]; then
    sed -n '1,260p' "$(client_conf "$name")"
    return 0
  fi
  if [[ -f "$(client_template "$name")" ]]; then
    sed -n '1,260p' "$(client_template "$name")"
    return 0
  fi
  if [[ -f "$(peer_info "$name")" ]]; then
    sed -n '1,260p' "$(peer_info "$name")"
    return 0
  fi

  die "No showable artifacts found under: $d"
}

cmd_qr() {
  local name="$1"; shift
  sanitize_name "$name"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --iface) IFACE="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown arg: $1" ;;
    esac
  done

  [[ -f "$(client_conf "$name")" ]] || die "No full client config (PrivateKey missing). Use 'show' to view template/peer-info."
  ensure_qrencode
  qrencode -t ansiutf8 <"$(client_conf "$name")"
}

cmd_disable() {
  local name="$1"; shift
  sanitize_name "$name"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --iface) IFACE="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown arg: $1" ;;
    esac
  done

  require_tools
  require_server_conf
  lock_or_die

  peer_exists "$name" || die "Peer '${name}' not found in $(conf_path)"
  backup_file "$(conf_path)"
  set_peer_disabled_state "$name" "disable"
  apply_runtime
}

cmd_enable() {
  local name="$1"; shift
  sanitize_name "$name"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --iface) IFACE="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown arg: $1" ;;
    esac
  done

  require_tools
  require_server_conf
  lock_or_die

  peer_exists "$name" || die "Peer '${name}' not found in $(conf_path)"
  backup_file "$(conf_path)"
  set_peer_disabled_state "$name" "enable"
  apply_runtime
}

cmd_revoke() {
  local name="$1"; shift
  sanitize_name "$name"
  local purge=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --purge) purge=1; shift 1 ;;
      --iface) IFACE="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown arg: $1" ;;
    esac
  done

  require_tools
  require_server_conf
  lock_or_die

  peer_exists "$name" || die "Peer '${name}' not found in $(conf_path)"

  local pub=""
  pub="$(peer_pubkey_from_block "$name" || true)"
  if [[ -n "$pub" ]] && wg show "$IFACE" >/dev/null 2>&1; then
    wg set "$IFACE" peer "$pub" remove || true
  fi

  backup_file "$(conf_path)"
  remove_peer_block "$name"
  apply_runtime

  if [[ $purge -eq 1 ]]; then
    rm -rf "$(client_dir "$name")" || true
  fi
}

main() {
  need_root
  [[ $# -ge 1 ]] || { usage; exit 1; }

  local cmd="$1"; shift
  case "$cmd" in
    add)
      [[ $# -ge 1 ]] || die "add requires <name>"
      cmd_add "$@"
      ;;
    list) cmd_list "$@" ;;
    show)
      [[ $# -ge 1 ]] || die "show requires <name>"
      cmd_show "$@"
      ;;
    qr)
      [[ $# -ge 1 ]] || die "qr requires <name>"
      cmd_qr "$@"
      ;;
    disable)
      [[ $# -ge 1 ]] || die "disable requires <name>"
      cmd_disable "$@"
      ;;
    enable)
      [[ $# -ge 1 ]] || die "enable requires <name>"
      cmd_enable "$@"
      ;;
    revoke)
      [[ $# -ge 1 ]] || die "revoke requires <name>"
      cmd_revoke "$@"
      ;;
    -h|--help) usage ;;
    *) die "Unknown command: $cmd" ;;
  esac
}

main "$@"
