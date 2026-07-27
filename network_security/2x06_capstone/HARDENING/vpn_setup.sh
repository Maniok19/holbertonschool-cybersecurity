#!/bin/bash
command -v wg &>/dev/null || { apt-get update -qq && apt-get install -y wireguard-tools; }
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

if [ ! -f /etc/wireguard/server-private.key ]; then
    wg genkey | tee /etc/wireguard/server-private.key | wg pubkey > /etc/wireguard/server-public.key
    chmod 600 /etc/wireguard/server-private.key
    chmod 644 /etc/wireguard/server-public.key
fi

SERVER_PRIV=$(cat /etc/wireguard/server-private.key)
SERVER_PUB=$(cat /etc/wireguard/server-public.key)

wg genkey | tee /etc/wireguard/admin-private.key | wg pubkey > /etc/wireguard/admin-public.key
chmod 600 /etc/wireguard/admin-private.key
ADMIN_PUB=$(cat /etc/wireguard/admin-public.key)
ADMIN_PRIV=$(cat /etc/wireguard/admin-private.key)

wg genkey | tee /etc/wireguard/finance-private.key | wg pubkey > /etc/wireguard/finance-public.key
chmod 600 /etc/wireguard/finance-private.key
FINANCE_PUB=$(cat /etc/wireguard/finance-public.key)
FINANCE_PRIV=$(cat /etc/wireguard/finance-private.key)

cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address = 10.99.0.1/24
ListenPort = 51820
PrivateKey = ${SERVER_PRIV}

[Peer]
PublicKey = ${ADMIN_PUB}
AllowedIPs = 10.99.0.2/32

[Peer]
PublicKey = ${FINANCE_PUB}
AllowedIPs = 10.99.0.3/32
EOF
chmod 600 /etc/wireguard/wg0.conf

mkdir -p /etc/wireguard/clients

cat > /etc/wireguard/clients/admin.conf << EOF
[Interface]
Address = 10.99.0.2/32
PrivateKey = ${ADMIN_PRIV}
DNS = 10.99.0.1

[Peer]
PublicKey = ${SERVER_PUB}
Endpoint = 10.42.66.225:51820
AllowedIPs = 10.99.0.0/24
PersistentKeepalive = 25
EOF

cat > /etc/wireguard/clients/finance.conf << EOF
[Interface]
Address = 10.99.0.3/32
PrivateKey = ${FINANCE_PRIV}
DNS = 10.99.0.1

[Peer]
PublicKey = ${SERVER_PUB}
Endpoint = 10.42.66.225:51820
AllowedIPs = 10.99.0.1/32
PersistentKeepalive = 25
EOF
chmod 600 /etc/wireguard/clients/*.conf

ip link show wg0 &>/dev/null && wg-quick down wg0 2>/dev/null || true
wg-quick up wg0

echo "Server pubkey: ${SERVER_PUB}"
echo "Admin config: /etc/wireguard/clients/admin.conf"
echo "Finance config: /etc/wireguard/clients/finance.conf"
