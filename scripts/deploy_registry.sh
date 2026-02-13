#!/usr/bin/env bash
set -euo pipefail

# Deploy exploit-registry and security_shield to Solana devnet
# Prerequisites: solana CLI configured for devnet, anchor CLI installed

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

echo "=== Solana Security Swarm — Devnet Deployment ==="
echo ""

# Check cluster
CLUSTER=$(solana config get | grep "RPC URL" | awk '{print $3}')
if [[ "$CLUSTER" != *"devnet"* ]]; then
  echo "ERROR: Solana CLI is not configured for devnet. Run:"
  echo "  solana config set --url devnet"
  exit 1
fi

WALLET=$(solana address)
BALANCE=$(solana balance | awk '{print $1}')
echo "Wallet:  $WALLET"
echo "Balance: $BALANCE SOL"
echo ""

# Check if we have enough SOL (need ~6 SOL for both programs)
NEEDED=6
if awk "BEGIN {exit !($BALANCE < $NEEDED)}"; then
  echo "Insufficient SOL. Need ~${NEEDED} SOL, have ${BALANCE} SOL."
  echo ""
  echo "Get devnet SOL from:"
  echo "  1. https://faucet.solana.com (2 SOL per request, 2 requests/8hr)"
  echo "  2. https://faucet.quicknode.com/solana/devnet"
  echo ""
  echo "Or try CLI airdrop:"
  echo "  solana airdrop 2 --url devnet"
  echo ""

  read -p "Try airdrop now? [y/N] " -n 1 -r
  echo ""
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    for i in 1 2 3; do
      echo "Airdrop attempt $i..."
      solana airdrop 2 --url devnet || true
      sleep 5
    done
    BALANCE=$(solana balance | awk '{print $1}')
    echo "New balance: $BALANCE SOL"
  fi
fi

# Copy .so files from sbpf build directory to target/deploy
echo ""
echo "--- Preparing build artifacts ---"
if [ -f "target/sbpf-solana-solana/release/exploit_registry.so" ]; then
  cp target/sbpf-solana-solana/release/exploit_registry.so target/deploy/
  echo "Copied exploit_registry.so to target/deploy/"
fi
if [ -f "target/sbpf-solana-solana/release/security_shield.so" ]; then
  cp target/sbpf-solana-solana/release/security_shield.so target/deploy/
  echo "Copied security_shield.so to target/deploy/"
fi

# Deploy exploit-registry
echo ""
echo "--- Deploying exploit-registry ---"
EXPLOIT_REGISTRY_KEYPAIR="target/deploy/exploit_registry-keypair.json"
EXPLOIT_REGISTRY_SO="target/deploy/exploit_registry.so"

if [ ! -f "$EXPLOIT_REGISTRY_SO" ]; then
  echo "Building exploit-registry..."
  anchor build -p exploit_registry
  cp target/sbpf-solana-solana/release/exploit_registry.so target/deploy/
fi

solana program deploy "$EXPLOIT_REGISTRY_SO" \
  --program-id "$EXPLOIT_REGISTRY_KEYPAIR" \
  --url devnet \
  --with-compute-unit-price 1

EXPLOIT_ID=$(solana address -k "$EXPLOIT_REGISTRY_KEYPAIR")
echo "exploit-registry deployed: $EXPLOIT_ID"

# Deploy security_shield
echo ""
echo "--- Deploying security_shield ---"
SHIELD_KEYPAIR="target/deploy/security_shield-keypair.json"
SHIELD_SO="target/deploy/security_shield.so"

if [ ! -f "$SHIELD_SO" ]; then
  echo "Building security_shield..."
  anchor build -p security_shield
  cp target/sbpf-solana-solana/release/security_shield.so target/deploy/
fi

solana program deploy "$SHIELD_SO" \
  --program-id "$SHIELD_KEYPAIR" \
  --url devnet \
  --with-compute-unit-price 1

SHIELD_ID=$(solana address -k "$SHIELD_KEYPAIR")
echo "security_shield deployed: $SHIELD_ID"

# Update deployed_programs.json
echo ""
echo "--- Updating deployed_programs.json ---"
cat > deployed_programs.json <<EOF
{
    "exploit_registry": "$EXPLOIT_ID",
    "security_shield": "$SHIELD_ID",
    "vulnerable_vault": "47poGSxjXsErkcCrZqEJtomHrdxHtfAbpfYmx3xRndVJ",
    "network": "devnet",
    "deployed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
echo "Updated deployed_programs.json"

# Summary
echo ""
echo "=== Deployment Complete ==="
echo "exploit-registry:  $EXPLOIT_ID"
echo "security_shield:   $SHIELD_ID"
echo "Network:           devnet"
echo ""
echo "Verify on Solana Explorer:"
echo "  https://explorer.solana.com/address/$EXPLOIT_ID?cluster=devnet"
echo "  https://explorer.solana.com/address/$SHIELD_ID?cluster=devnet"
echo ""
echo "Run tests: anchor test --skip-local-validator"
