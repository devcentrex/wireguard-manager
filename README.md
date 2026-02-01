# WireGuard Ubuntu deploy & peer manager

Two bash scripts for a simple WireGuard server on Ubuntu 20+, plus peer lifecycle management.

Files
. `wg-deploy.sh`  
  Deploys a WireGuard server using `wg-quick`, enables IP forwarding, and sets up NAT internet breakout via `iptables` (MASQUERADE). Also writes defaults used for client config generation. :contentReference[oaicite:1]{index=1}
. `wg-peers.sh`  
  Adds, lists, shows, disables, enables, and revokes peers. Generates client configs or templates and can print QR codes for configs when the client private key is known. :contentReference[oaicite:2]{index=2}

## Requirements

. Ubuntu 20+
. Root access
. Systemd
. WireGuard packages are installed automatically by `wg-deploy.sh` via `apt-get` :contentReference[oaicite:3]{index=3}
. `qrencode` is installed automatically by `wg-peers.sh` only when you request QR output :contentReference[oaicite:4]{index=4}

## Quick start

1. Make scripts executable
```bash
chmod +x ./wg-deploy.sh ./wg-peers.sh
````

2. Deploy server

```bash
sudo bash ./wg-deploy.sh deploy \
  --iface wg0 \
  --subnet 10.1.1.0/24 \
  --server-ip 10.1.1.1 \
  --port 51820 \
  --endpoint vpn.example.com \
  --dns 1.1.1.1
```

3. Add a peer

```bash
sudo bash ./wg-peers.sh add alice --iface wg0 --endpoint vpn.example.com:51820 --qr
```

4. Show status

```bash
sudo bash ./wg-deploy.sh status --iface wg0
sudo bash ./wg-peers.sh list --iface wg0
```

## What gets created

Server
. `/etc/wireguard/<iface>.conf`
. `/etc/wireguard/keys/server.key` and `/etc/wireguard/keys/server.pub` 
. NAT rules are applied via `PostUp` and removed via `PostDown` in the WireGuard config 
. If UFW is active, UDP port is allowed 

Defaults for client generation
. `/etc/wireguard/<iface>.endpoint`
. `/etc/wireguard/<iface>.dns`
. `/etc/wireguard/<iface>.client-allowedips`

Peer artifacts
. `/etc/wireguard/clients/<iface>/<name>/`
Contains keys, optional PSK, generated config or template, and metadata. 

## Security notes

. For BYO-key peers, the server only knows the client PublicKey, so it generates a client config template instead of a full config 
. PSK is used by default unless you pass `--no-psk` 

## License

See LICENSE file.

# HOWTO

This document is example-driven. Commands are safe to copy-paste, but always verify interface names, subnets, and endpoints.

## 1. Deploy a WireGuard server with NAT breakout

Typical full-tunnel setup where clients use the server for internet egress.

```bash
sudo bash ./wg-deploy.sh deploy \
  --iface wg0 \
  --subnet 10.1.1.0/24 \
  --server-ip 10.1.1.1 \
  --port 51820 \
  --endpoint vpn.example.com \
  --dns 1.1.1.1 \
  --public-iface "$(ip route show default | awk '/default/ {print $5; exit}')"
````

Notes
. `--public-iface` is auto-detected from the default route. You can set it explicitly if detection is wrong. 
. NAT is implemented via `iptables ` in `PostUp` and removed in `PostDown`. 

## 2. Check server status

```bash
sudo bash ./wg-deploy.sh status --iface wg0
```

This prints systemd status and `wg show`. 

## 3. Add peers

### 3.1 Server-generated keys, full config, QR output

```bash
sudo bash ./wg-peers.sh add alice \
  --iface wg0 \
  --ip4 10.1.1.101 \
  --endpoint vpn.example.com:51820 \
  --print-psk
```

Outputs
. Server config is updated using BEGIN/END peer markers and applied via `wg syncconf` or service restart. 
. Client config is written under `/etc/wireguard/clients/wg0/alice/alice.conf`. 
. Client PSK is printed to stdout.

### 3.2 BYO client keys, server knows only PublicKey

Use this when the client already exists and you do not want the server to hold the client private key.

```bash
sudo bash ./wg-peers.sh add phone1 \
  --iface wg0 \
  --ip4 10.1.1.100 \
  --pubkey 'CLIENT_PUBLIC_KEY_BASE64' \
  --endpoint vpn.example.com:51820
```

Result
. Peer is added to the server
. A template config is generated because PrivateKey is unknown on the server 

### 3.3 Import an existing client private key, then you can QR

```bash
sudo bash ./wg-peers.sh add dev1 \
  --iface wg0 \
  --ip4 10.1.1.110 \
  --privkey-file ./dev1.key \
  --endpoint vpn.example.com:51820 \
  --qr
```

## 4. Split tunnel clients

By default, client AllowedIPs is typically full-tunnel `0.0.0.0/0,::/0` via defaults. Override per peer:

```bash
sudo bash ./wg-peers.sh add bob \
  --iface wg0 \
  --ip4 10.1.1.120 \
  --endpoint vpn.example.com:51820 \
  --client-allowed "10.1.1.0/24, 192.168.88.0/24" \
  --dns "1.1.1.1"
```

Client AllowedIPs only affects the client routing. Server-side AllowedIPs still contains the peer `/32` plus optional routed networks behind the peer. 

## 5. Route networks behind a peer

If a peer is a router and you want the server to route additional subnets to it:

```bash
sudo bash ./wg-peers.sh add branch-router \
  --iface wg0 \
  --ip4 10.1.1.200 \
  --endpoint vpn.example.com:51820 \
  --server-extra-allowed "192.168.50.0/24, 192.168.60.0/24"
```

This appends those routes to the peer AllowedIPs on the server side. 

## 6. List, show, and QR peers

List peers and runtime up/down state

```bash
sudo bash ./wg-peers.sh list --iface wg0
```

Show a peer’s generated config or template

```bash
sudo bash ./wg-peers.sh show alice --iface wg0
```

Print QR for a peer config

```bash
sudo bash ./wg-peers.sh qr alice --iface wg0
```

QR requires a full client config file, which requires the client PrivateKey to be present in the peer artifacts. 

## 7. Disable, enable, revoke

Disable a peer without deleting artifacts

```bash
sudo bash ./wg-peers.sh disable alice --iface wg0
```

Enable it again

```bash
sudo bash ./wg-peers.sh enable alice --iface wg0
```

Revoke peer from the server config

```bash
sudo bash ./wg-peers.sh revoke alice --iface wg0
```

Revoke and purge peer artifacts directory

```bash
sudo bash ./wg-peers.sh revoke alice --iface wg0 --purge
```

Disable/enable is implemented by commenting the peer block lines inside the BEGIN/END marker region and then applying the runtime config. 

## 8. Defaults files you can set once

These are written by `wg-deploy.sh` and used by `wg-peers.sh` when you do not specify flags.

. `/etc/wireguard/wg0.endpoint`
. `/etc/wireguard/wg0.dns`
. `/etc/wireguard/wg0.client-allowedips`

```

