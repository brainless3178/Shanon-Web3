# Integration Tests

This directory contains TypeScript integration tests for the Solana programs.

## Prerequisites

These tests require:

1. **Solana CLI** — Install via `sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"`
2. **Anchor CLI** — Install via `cargo install --git https://github.com/coral-xyz/anchor avm && avm install latest && avm use latest`
3. **Node.js dependencies** — Run `yarn install` or `npm install` in the project root
4. **A running Solana test validator** — Anchor starts one automatically during `anchor test`

## Running Tests

```bash
# Run all Anchor integration tests (starts a local validator automatically)
anchor test

# If you already have a validator running:
anchor test --skip-local-validator

# Run a specific test file:
anchor test -- --grep "vault-security"
```

## Test Files

| File | Description |
|------|-------------|
| `vault_security.ts` | Tests vault deposit/withdrawal security, share inflation attack prevention |
| `exploit_registry.ts` | Tests the on-chain exploit registry program |
| `enterprise/brutal_audit_tests.ts` | Comprehensive enterprise audit test suite |
| `vulnerability_tests/vault_security.ts` | Additional vault vulnerability scenario tests |

## Important Notes

- These tests **cannot** run standalone with `ts-mocha` — they require the Anchor test
  framework which manages validator lifecycle, program deployment, and IDL generation.
- The `target/types/` directory must contain generated TypeScript IDL types. Run `anchor build`
  first if the types are missing.
- Tests are configured via `Anchor.toml` in the project root.
