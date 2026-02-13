//! Transparent Security Receipts Demo
//!
//! Showcases real proofs, consensus transparency, and economic risk.

use orchestrator::terminal_ui::*;
use std::time::Duration;

fn main() {
    print_banner();

    print_config_pro(
        "https://api.mainnet-beta.solana.com",
        &[
            (
                "Claude 3.5 Sonnet".into(),
                true,
                "Pattern matched known exploit vector".into(),
            ),
            (
                "GPT-4o".into(),
                true,
                "Mathematical anomaly detected in state transition".into(),
            ),
            (
                "Gemini 1.5 Pro".into(),
                true,
                "Identified historical precedent in Mango Markets".into(),
            ),
            (
                "Llama 3.1".into(),
                false,
                "Flagged as false positive (insufficient context)".into(),
            ),
            (
                "Mixtral 8x7B".into(),
                false,
                "Confidence below 60% threshold".into(),
            ),
        ],
    );

    let spinner = Spinner::new("Probing program invariants via concolic execution...");
    std::thread::sleep(Duration::from_millis(800));
    spinner.success("Invariants verified: 124 safe, 2 compromised");

    let mut progress = ProgressBar::new(50, "Simulating Exploit Payload Generation");
    for _ in 0..50 {
        progress.increment();
        std::thread::sleep(Duration::from_millis(15));
    }
    progress.finish();

    // Finding #01 (Critical with Proof Receipt)
    print_vulnerability_high_fid(
        1,
        "SOL-001",
        "Administrative Authority Bypass in dex_core::withdraw_fees",
        5,
        "Access Control",
        "programs/dex-core/src/lib.rs:142",
        98,
        &[
            "Administrative instruction missing .is_signer check (+40%)".into(),
            "Consensus: 3/5 major models verified (+30%)".into(),
            "Exploit payload successfully simulated on devnet fork (+28%)".into(),
        ],
        5000000,
        "LOW (Single TX)",
        &[
            "Identify dex_core deployment address".into(),
            "Craft instruction data for withdraw_fees with arbitrary recipient".into(),
            "Execute transaction without administrative signature".into(),
        ],
        4.2, // $4.2M
        Some("Directly mirrors the Wormhole $320M hack. Any user can trigger the withdrawal of protocol-owned assets to their own wallet."),
        Some("- pub fn withdraw_fees(ctx: Context<WithdrawFees>) {\n+ pub fn withdraw_fees(ctx: Context<WithdrawFees>) {\n+     require!(ctx.accounts.admin.is_signer, ErrorCode::Unauthorized);"),
        Some(("5Kj7xSvnWd...9Pmz4f".into(), 42000000000000, 5100000))
    );

    // Finding #02 (High with Multi-step breakdown)
    print_vulnerability_high_fid(
        2,
        "LEND-012",
        "Price Oracle Manipulation via LP Token Skew",
        4,
        "Market Logic",
        "programs/lending/src/state.rs:89",
        82,
        &[
            "Logic relies on spot-price of low-liquidity pool (+50%)".into(),
            "Historical precedent: Mango Markets exploit (+20%)".into(),
            "Insolvent state reached in concolic simulation (+12%)".into(),
        ],
        25000000,
        "MEDIUM (Three-Step Attack)",
        &[
            "Acquire flash loan from external provider (1,000,000 USDC)".into(),
            "Skew price of AMM pool by dumping USDC for LP tokens".into(),
            "Execute borrow instruction from lending program using skewed value".into(),
        ],
        1.8, // $1.8M
        Some("Similar to the Cream Finance exploit. An attacker uses massive capital (flash loan) to temporarily distort pricing logic."),
        Some("- let price = get_spot_price(amm_pool)?;\n+ let price = get_pyth_price_with_staleness_check(config.oracle_id)?;"),
        None
    );

    print_priority_queue(&[
        (
            "SOL-001".into(),
            "Admin Authority Bypass".into(),
            9.8,
            "15m",
        ),
        (
            "LEND-012".into(),
            "Oracle Price Manipulation".into(),
            8.2,
            "2h",
        ),
    ]);

    print_standards_detailed(vec![
        (
            "Neodyme Checklist".into(),
            vec![
                ("Signer verification on state changes".into(), false),
                ("Account ownership validation".into(), true),
                ("PDA derivation correctness".into(), true),
            ],
        ),
        (
            "Sec3 Best Practices".into(),
            vec![
                ("Oracle staleness checks".into(), false),
                ("Flash loan resistance".into(), false),
            ],
        ),
    ]);

    print_tvr_summary(
        6.0,
        "✓ INTEGRITY VERIFIED (mainnet-fork)",
        &["dex-core", "lending-v2", "spl-token"],
    );

    print_report_saved(&[
        "reports/swarm_audit_20240209.json",
        "reports/swarm_audit_20240209.html",
        "reports/swarm_audit_20240209.sarif",
    ]);

    print_tips();
}
