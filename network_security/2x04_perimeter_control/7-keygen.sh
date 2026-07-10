#!/bin/bash
set -e

echo "Generating WireGuard keypairs..."
server_private=$(wg genkey)
server_public=$(echo "$server_private" | wg pubkey)

client_private=$(wg genkey)
client_public=$(echo "$client_private" | wg pubkey)

echo "Server Keypair:"
echo "  Private key: $server_private"
echo "  Public key:  $server_public"

echo "Client Keypair:"
echo "  Private key: $client_private"
echo "  Public key:  $client_public"