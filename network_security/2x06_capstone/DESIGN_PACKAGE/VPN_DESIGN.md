# VPN Design

## Why WireGuard

- Simple: ~10 lines of config per peer.
- Fast: kernel-native, ChaCha20 encryption.
- Secure: ~4,000 lines of code (small attack surface).
- Zero Trust: unknown peers are silently ignored.

## Topology


wg0: 10.99.0.1/24 <- WireGuard -> Admin (10.99.0.2)  
UDP :51820        <- WireGuard -> Finance (10.99.0.3)


## IP Addressing

- Gateway: VPN IP 10.99.0.1 — All (itself)
- Admin Laptop: VPN IP 10.99.0.2 — SSH :22, DB :3306
- Finance Remote: VPN IP 10.99.0.3 — FTPS :21 only

## Server Config (/etc/wireguard/wg0.conf)

```ini
[Interface]
Address = 10.99.0.1/24
ListenPort = 51820
PrivateKey = <server-private-key>

# Admin — full access
[Peer]
PublicKey = <admin-pubkey>
AllowedIPs = 10.99.0.2/32

# Finance — FTPS only
[Peer]
PublicKey = <finance-pubkey>
AllowedIPs = 10.99.0.3/32
```

## Admin Client Config

```ini
[Interface]
Address = 10.99.0.2/32
PrivateKey = <admin-private-key>

[Peer]
PublicKey = <server-pubkey>
Endpoint = 10.42.66.225:51820
AllowedIPs = 10.99.0.0/24
PersistentKeepalive = 25
```

## Finance Client Config

```ini
[Interface]
Address = 10.99.0.3/32
PrivateKey = <finance-private-key>

[Peer]
PublicKey = <server-pubkey>
Endpoint = 10.42.66.225:51820
AllowedIPs = 10.99.0.1/32
PersistentKeepalive = 25
```

## Access Control

Finance can only reach the gateway. Admin can reach everything.

Firewall adds these rules via PostUp:
```
nft add rule inet logcorp_firewall INPUT iif wg0 accept
```

## Key Generation

```bash
wg genkey | tee private.key | wg pubkey > public.key
chmod 600 private.key
```

## Rollback

```bash
wg-quick down wg0
```
