# Shanon-Web3

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Solana](https://img.shields.io/badge/solana-devnet-9945FF.svg)](https://solana.com/)
[![Anchor](https://img.shields.io/badge/anchor-0.30.1-blue.svg)](https://www.anchor-lang.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

### Autonomous security agent that finds, proves, and registers Solana vulnerabilities on-chain.

**52 vulnerability detectors** · **Z3 formal verification** · **Multi-LLM consensus** · **On-chain audit registry (devnet)**

> Built for the [Colosseum Agent Hackathon](https://www.colosseum.org/)

---

## The Problem

Solana processes billions in daily DeFi volume, but smart contract exploits have cost users over **$400M in 2024 alone**. The Wormhole bridge hack ($320M), Mango Markets manipulation ($114M), and Crema Finance exploit ($8.8M) all stemmed from vulnerabilities that automated tooling could have caught — missing signer checks, unconstrained oracle reads, arithmetic precision errors. These aren't exotic zero-days. They're known anti-patterns that keep getting shipped to mainnet.

Professional audits from firms like OtterSec or Neodyme cost **$50,000–$200,000** and take weeks to schedule. That puts them out of reach for the long tail of Solana teams — the two-person lending protocol, the weekend hackathon DEX, the DAO treasury manager. These teams run `cargo clippy` and Anchor's built-in checks, deploy to mainnet, and hope for the best.

Existing tooling doesn't fill the gap. **cargo-geiger** catches `unsafe` blocks but ignores Solana-specific logic bugs. **Soteria (Sec3)** provides static analysis but hasn't been updated since 2023 and misses modern Anchor patterns. **Trident** does stateful fuzzing but requires manual test harness writing. **Certora** focuses on EVM, not Solana. No tool today combines static analysis, formal verification, fuzzing, and AI-powered exploit synthesis into a single pipeline that understands the Sealevel runtime, Anchor's constraint system, and real exploit patterns from production incidents.

---

## The Solution

A single Rust binary — **36 specialized crates** — that runs a full security audit pipeline against any Anchor or native Solana program. Point it at a directory, get a structured report with severity classifications, attack scenarios, compilable PoC code, and Anchor-idiomatic fixes. Optionally register findings as immutable on-chain records on Solana devnet.

### Architecture

```
                        +---------------------------+
                        |      orchestrator         |
                        |  (CLI, pipeline, report)  |
                        +-----+--------+--------+---+
                              |        |        |
              +---------------+    +---+---+    +---------------+
              |                    |       |                    |
    +---------v--------+  +-------v---+  +v---------+  +-------v--------+
    | Static Analysis  |  |  Formal   |  | Dynamic  |  | AI / LLM      |
    +------------------+  +-----------+  +----------+  +----------------+
    | program-analyzer |  | symbolic  |  | trident  |  | ai-enhancer    |
    |   (52 patterns)  |  |  -engine  |  | -fuzzer  |  | llm-strategist |
    | anchor-security  |  |  (Z3 SMT) |  | fuzzdel  |  | consensus      |
    | sec3-analyzer    |  | certora   |  |  sol     |  |  -engine       |
    | taint-analyzer   |  | kani      |  | wacana   |  | l3x-analyzer   |
    +------------------+  +-----------+  +----------+  +----------------+
              |                |              |                |
              +-------+--------+--------------+--------+-------+
                      |                                |
              +-------v--------+              +--------v-------+
              | transaction    |              | on-chain       |
              |  -forge        |              |  registry      |
              | (PoC builder)  |              | (devnet)       |
              +----------------+              +----------------+
```

### Four Analysis Layers

| Layer | What it does | How |
|---|---|---|
| **Static** | Parses Rust into full ASTs via the `syn` crate. Runs 52 pattern-matching detectors with context gating (e.g., overflow detection only fires on financial values, not loop counters). Inter-procedural taint analysis on `AccountInfo` flows via `petgraph` call graphs. | `program-analyzer`, `anchor-security-analyzer`, `sec3-analyzer`, `taint-analyzer`, `cpi-analyzer`, `dataflow-analyzer` |
| **Formal** | Encodes arithmetic invariants, balance conservation, and access control as Z3 SMT constraints. Checks satisfiability to generate mathematical proofs of exploitability or safety. | `symbolic-engine`, `certora-prover`, `kani-verifier`, `concolic-executor` |
| **Dynamic** | Stateful fuzzing of Anchor programs (Trident), binary-level SBF bytecode fuzzing (FuzzDelSol), and concolic path exploration (WACANA). | `trident-fuzzer`, `fuzzdelsol`, `wacana-analyzer`, `security-fuzzer` |
| **AI** | Feeds findings through LLM APIs (OpenRouter/OpenAI/NVIDIA) with Solana-specific prompts grounded in Sealevel runtime internals. Multi-LLM consensus voting reduces false positives. Generates executable PoC code and fix suggestions. | `ai-enhancer`, `llm-strategist`, `consensus-engine`, `l3x-analyzer` |

---

## Built on Solana

> This section is for hackathon judges. Shanon-Web3 doesn't just *analyze* Solana programs — it **builds on Solana** with an on-chain audit registry.

### On-Chain Exploit Registry (Devnet)

**Program ID:** `HG1LKfUipjq5d1WdXLpxNqtv2ZbgFHqJZvvmFZoXNhbz`

A custom **Anchor 0.30.1** program deployed to **Solana devnet** that stores audit findings as immutable PDA records.

```rust
// PDA seeds: ["exploit", target_program_id, vulnerability_type]
#[account]
pub struct ExploitProfile {
    pub program_id: Pubkey,        // Program that was audited
    pub reporter: Pubkey,          // Who ran the audit
    pub timestamp: i64,            // When the finding was registered
    pub severity: u8,              // 1-5 severity scale
    pub vulnerability_type: String,// e.g. "missing_signer_check"
    pub proof_hash: [u8; 32],      // SHA-256 of the full proof data
    pub metadata_url: String,      // IPFS/Arweave link to full report
    pub bump: u8,
}
```

**Why this matters:**

| Feature | Detail |
|---|---|
| **Immutable audit trail** | Once a finding is registered, it can't be altered or deleted. The Solana blockchain is the audit log. |
| **Queryable by program ID** | Any protocol, wallet, or frontend can check if a given program has known vulnerabilities — just derive the PDA. |
| **Verifiable proofs** | Each finding includes a SHA-256 proof hash. Anyone can verify the full proof data matches what's on-chain. |
| **PDA-keyed by (program_id, vulnerability_type)** | One record per vulnerability type per program. No duplicates, deterministic addresses. |
| **Permissionless** | Anyone can register findings. The reporter's public key is stored — reputation is on-chain. |

```bash
# Register audit findings on-chain after running analysis
solana-security-swarm audit --repo ./my-program --register
```

> [Important] All on-chain operations use **Solana devnet**. The developer has no mainnet SOL. This is a hackathon prototype — mainnet deployment is a future milestone.

---

## Quick Start

```bash
# Build (36 crates, ~7 min first time)
cargo build --release

# Audit a local Anchor project
cargo run --release --bin solana-security-swarm -- audit --repo ./programs/vulnerable-vault

# Setup environment for AI features
cp .env.example .env
# Edit .env and add your OPENROUTER_API_KEY

# Setup TypeScript environment for exploits and tests
npm install

# Interactive mode (guided walkthrough)
cargo run --release --bin solana-security-swarm -- interactive
```

Reports land in `audit_reports/` as structured JSON with severity classifications, attack scenarios, fix code, and CWE identifiers.

---

## CLI Commands

| Command | Description |
|---|---|
| `audit --repo <PATH>` | Full security audit of a local program directory |
| `scan <URL>` | Clone and audit a GitHub repository |
| `watch [--dashboard]` | Live monitoring of deployed programs |
| `dashboard --report <FILE>` | Open TUI to browse past audit reports |
| `explorer --transaction <SIG>` | Transaction forensics and replay |
| `interactive` | Guided audit walkthrough |
| `completions --shell <SHELL>` | Generate shell completions |

### Key Flags

| Flag | Description |
|---|---|
| `--prove` | Generate Z3 formal proofs (requires libz3) |
| `--register` | Write findings to on-chain registry on devnet |
| `--consensus` | Multi-LLM confidence voting to reduce false positives |
| `--dashboard` | Open TUI dashboard after audit completes |
| `--bug-bounty` | Format output for bug bounty submission |
| `--branch <NAME>` | Target a specific git branch when using `scan` |

---

## Vulnerability Coverage

52 detectors organized by attack surface. Each uses multi-signal heuristics with false-positive suppression (test code exclusion, financial context gating, CPI pattern confirmation).

| Category | # | Patterns |
|---|---|---|
| **Authentication** | 5 | Missing signer, owner check, privilege escalation, access control, account hijacking |
| **Arithmetic** | 8 | Integer overflow (financial context only), precision loss, division-before-multiply, rounding direction, unsafe exponentiation, zero-division, decimal handling |
| **Account Validation** | 5 | Type cosplay, duplicate mutable accounts, data mismatch, rent exemption, oracle staleness |
| **PDA Security** | 5 | Arbitrary CPI, bump seed canonicalization, PDA sharing, closing issues, seed validation |
| **Token Security** | 5 | Unprotected mint, freeze authority, token account confusion, program validation, unlimited mint |
| **CPI Security** | 2 | Deep CPI chains, unvalidated CPI targets |
| **DeFi Attacks** | 10 | Flash loans, slippage, sandwich, front-running, unrestricted transfer, LP manipulation, reward errors, deadline, governance |
| **Protocol Safety** | 5 | Missing pause mechanism, event emission, time manipulation, hardcoded addresses, lamport drain |
| **MEV Protection** | 2 | Sandwich attacks, front-running without commit-reveal |
| **Governance** | 1 | Flash loan governance attacks |
| **Code Quality** | 4 | Account resurrection, close authority, amount validation, unsafe math |

Each finding includes: CWE identifier, severity (1–5), confidence score, vulnerable code with line numbers, concrete attack scenario, Anchor-idiomatic fix code, and references to real Solana exploits where the same pattern was exploited.

---

## Demo Output

```
$ solana-security-swarm audit --repo ./programs/vulnerable-vault

  +---------------------------------------------------------------+
  |            Shanon-Web3 v0.1.0                       |
  |            Autonomous Solana Security Auditor                  |
  +---------------------------------------------------------------+

  [▸] Parsing source files ........................... 12 files
  [▸] Running 52 vulnerability detectors ............. done (2.1s)
  [▸] Inter-procedural taint analysis ................ done (0.8s)
  [▸] Z3 constraint solving .......................... 4 proofs
  [▸] AI enrichment (claude-3.5-sonnet) .............. done (6.2s)

  ┌─────────────────────────────────────────────────────────────┐
  │  RESULTS: 3 critical · 5 high · 2 medium · 1 low           │
  └─────────────────────────────────────────────────────────────┘

  [CRITICAL]  Missing Signer Check                    [CWE-862]
  ├─ File: src/lib.rs:142
  ├─ The withdraw instruction does not verify that the
  │  authority account is a signer. Any account can drain funds.
  ├─ Confidence: 0.95
  ├─ Proof: Z3 SAT — exploitable input exists
  └─ Fix: Add `#[account(signer)]` to authority in Withdraw ctx

  [HIGH]  Integer Overflow in Fee Calculation         [CWE-190]
  ├─ File: src/lib.rs:87
  ├─ fee_amount = amount * fee_rate / 10000
  │  Overflows when amount > u64::MAX / fee_rate
  ├─ Confidence: 0.88
  ├─ Proof: Z3 SAT — overflow at amount = 18446744073709551
  └─ Fix: Use checked_mul().checked_div() or u128 intermediate

  [MEDIUM]  PDA Bump Seed Not Canonicalized           [CWE-330]
  ├─ File: src/lib.rs:203
  ├─ PDA derived without storing canonical bump. Attacker
  │  can use non-canonical bump to create duplicate accounts.
  ├─ Confidence: 0.82
  └─ Fix: Store bump in account data, use seeds constraint

  ──────────────────────────────────────────────────────────────
  Report saved: audit_reports/vulnerable-vault_2025-01-15_report.json
  Bug bounty report: audit_reports/vulnerable-vault_bounty.md
```

---

## Hackathon Submission

### Problem Statement

Solana processes billions in DeFi volume, but smart contract exploits have cost users $400M+ in 2024 alone (Wormhole, Mango, Crema). Audits cost $50–200k and take weeks, putting them out of reach for small teams. Existing tools like cargo-geiger catch `unsafe` usage but miss Solana-specific bugs: PDA seed collisions, missing signer checks, CPI target validation failures. Anchor's type system helps but doesn't prevent logic bugs in financial calculations. There's no automated security layer that understands Sealevel's parallel execution model, Anchor's constraint system, and real exploit patterns from production incidents. This leaves a gap: teams ship vulnerable programs, security researchers find issues too late, and users lose funds.

### Technical Approach

Parses Rust source into full ASTs via the `syn` crate (not regex). Runs 52 pattern-matching detectors against token streams, each using multi-signal heuristics with context gating (e.g., integer overflow detection only fires on financial values, not loop counters). Performs inter-procedural taint analysis on `AccountInfo` flows using petgraph-based call graphs. Integrates Z3 SMT solver to prove arithmetic invariants — encodes balance conservation and access control as constraints, checks satisfiability. Feeds findings through LLM APIs (OpenRouter/OpenAI/NVIDIA) with Solana-specific prompts grounded in Sealevel runtime internals. Generates executable PoCs using `@solana/web3.js` with correct `AccountMeta` flags. Stores findings on-chain via custom Anchor program (`exploit-registry`) using PDAs keyed by (program_id, finding_hash). All analysis runs locally — no code leaves the developer's machine except optional on-chain registration.

### Target Audience

A Solana protocol developer who just finished building a lending protocol or DEX. They know audits are necessary but can't afford $100k+ for a professional firm. They've run `cargo clippy` and Anchor's built-in checks, but those don't catch Solana-specific bugs like PDA collisions or CPI privilege escalation. They need immediate feedback on whether their program has critical vulnerabilities before deploying to mainnet. Secondary audience: security researchers who analyze new Solana programs for bounties but spend hours manually reviewing code for known patterns.

### Business Model

Open-source core with premium features. Free tier: CLI tool, 52 detectors, local analysis. Pro ($99/mo): continuous mainnet monitoring, Slack/Discord alerts, priority LLM model access, team collaboration dashboard. Enterprise ($499/mo): private deployment, custom detectors, SLA guarantees. Revenue model: subscriptions + protocol partnerships (e.g., Jupiter/Kamino pay for continuous monitoring of their programs). At 200 teams on Pro and 10 on Enterprise, that's ~$25k MRR. Long-term: ecosystem grants from Solana Foundation for maintaining the open-source tooling.

### Competitive Landscape

Soteria (Sec3) provides static analysis but hasn't been updated since 2023 and misses modern Anchor patterns. Ackee's Trident does fuzzing but requires manual test writing. cargo-geiger catches `unsafe` but not logic bugs. Certora focuses on EVM, not Solana. Professional audits (OtterSec, Neodyme) are high-quality but slow and expensive. No tool combines static analysis, formal verification, fuzzing, and AI-powered exploit synthesis in one pipeline. We're the first to encode real Solana exploit patterns (Wormhole, Cashio, Mango) into automated detectors with Z3 proofs of exploitability.

### Future Vision

V2: Browser extension that analyzes programs before users interact (think MetaMask Snaps for Solana security). V3: Collaborative security marketplace where researchers stake reputation on findings, protocols pay bounties via on-chain escrow. Six-month roadmap: SBF bytecode-level fuzzing (catch compiler bugs), integration with Jito's MEV tooling (detect sandwich attack vulnerabilities), support for non-Anchor native programs. We intend to raise a seed round and build this full-time — our team has contributed to Anchor's security docs and found vulnerabilities in production Solana programs.

---

## Tech Stack

| Layer | Key Dependencies |
|---|---|
| **Solana Runtime** | `solana-sdk` 1.18, `solana-client` 1.18, `anchor-lang` 0.30.1, `anchor-spl` 0.30.1, `solana_rbpf` 0.8 |
| **Static Analysis** | `syn` 2.0 (full AST), `petgraph` 0.6 (call graphs), `goblin` 0.9 (ELF parsing), `proc-macro2` 1.0 |
| **Formal Verification** | Z3 SMT solver 0.12, Kani (CBMC), Certora CVL |
| **Dynamic Analysis** | Trident (Ackee), custom SBF fuzzer, `rand`, `tempfile` |
| **AI / ML** | `reqwest` 0.11 (LLM APIs), `ndarray` 0.15 (embeddings), OpenRouter / OpenAI / NVIDIA NIM |
| **Interfaces** | `ratatui` 0.28 (TUI), `axum` 0.7 (web API), `clap` 4.4 (CLI), `colored` 2.1 |
| **Serialization** | `serde` / `serde_json`, `borsh` 0.10, `bs58` 0.5, `sha2` 0.10 |

---

## Project Structure

```
crates/                            36 analysis crates
  orchestrator/                    CLI, audit pipeline, report engine
  program-analyzer/                Core scanner (52 patterns, syn AST)
  taint-analyzer/                  Inter-procedural taint tracking
  symbolic-engine/                 Z3 SMT integration
  ai-enhancer/                     LLM-powered finding enrichment
  llm-strategist/                  Exploit strategy generation
  consensus-engine/                Multi-LLM voting
  trident-fuzzer/                  Stateful Anchor fuzzing
  fuzzdelsol/                      SBF bytecode fuzzing
  wacana-analyzer/                 Concolic execution
  anchor-security-analyzer/        Anchor constraint validation
  sec3-analyzer/                   Soteria-style rule engine
  transaction-forge/               PoC transaction builder
  ...                              + 23 more specialized crates

programs/                          On-chain Solana programs
  exploit-registry/                Audit registry (devnet) ← the on-chain component
  vulnerable-vault/                Intentionally vulnerable test target
  vulnerable-token/                Intentionally vulnerable test target
  vulnerable-staking/              Intentionally vulnerable test target
```

---

## Requirements

| Requirement | Version | Notes |
|---|---|---|
| Rust | 1.75+ | Edition 2021 |
| Solana CLI | 1.18+ | For on-chain registry interaction |
| Node.js | 20+ | Required for running PoC exploits and integration tests |
| Z3 (optional) | any | Required for formal proof generation (`--prove`) |
| Honggfuzz (optional) | any | Required for SBF bytecode fuzzing |

### OS Dependencies

- Linux: `apt install libz3-dev libssl-dev pkg-config libclang-dev`
- macOS: `brew install z3 openssl`

Without Z3 or Honggfuzz installed, all 52 detectors, taint analysis, and AI enhancement still work. You only lose formal proof and deep bytecode fuzzing.

### Environment Setup

The AI-powered consensus and exploit synthesis require API keys.

1. `cp .env.example .env`
2. Define `OPENROUTER_API_KEY` or `OPENAI_API_KEY` in the file.

---

## License

MIT

---

**Shanon-Web3** · v0.1.0 · [github.com/brainless3178/Shanon-Web3](https://github.com/brainless3178/Shanon-Web3)
