//! Secure Code Generator
//!
//! Generates secure Solana program code patterns and fixes
//! based on detected vulnerabilities.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Generated secure code fix
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureFix {
    pub vulnerability_id: String,
    pub original_code: String,
    pub fixed_code: String,
    pub explanation: String,
    pub diff: String,
}

/// Secure pattern template
#[derive(Debug, Clone)]
pub struct SecurePattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub template: String,
    pub requires: Vec<String>,
}

/// Main secure code generator
pub struct SecureCodeGen {
    patterns: HashMap<String, SecurePattern>,
}

impl SecureCodeGen {
    /// Create a new secure code generator with default patterns
    pub fn new() -> Self {
        let mut patterns = HashMap::new();

        // Add secure patterns
        patterns.insert(
            "signer-check".to_string(),
            SecurePattern {
                id: "signer-check".to_string(),
                name: "Signer Validation".to_string(),
                description: "Validates account is a signer".to_string(),
                template: r#"
#[derive(Accounts)]
pub struct SecureAccounts<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    // ... other accounts
}
"#
                .to_string(),
                requires: vec!["anchor-lang".to_string()],
            },
        );

        patterns.insert(
            "owner-check".to_string(),
            SecurePattern {
                id: "owner-check".to_string(),
                name: "Owner Validation".to_string(),
                description: "Validates account owner".to_string(),
                template: r#"
#[derive(Accounts)]
pub struct SecureAccounts<'info> {
    #[account(
        constraint = my_account.owner == expected_program_id @ ErrorCode::InvalidOwner
    )]
    pub my_account: Account<'info, MyData>,
}
"#
                .to_string(),
                requires: vec!["anchor-lang".to_string()],
            },
        );

        patterns.insert(
            "checked-arithmetic".to_string(),
            SecurePattern {
                id: "checked-arithmetic".to_string(),
                name: "Checked Arithmetic".to_string(),
                description: "Uses checked arithmetic to prevent overflow".to_string(),
                template: r#"
let result = amount_a
    .checked_add(amount_b)
    .ok_or(ErrorCode::Overflow)?;

let product = factor_a
    .checked_mul(factor_b)
    .ok_or(ErrorCode::Overflow)?;

let quotient = dividend
    .checked_div(divisor)
    .ok_or(ErrorCode::DivisionByZero)?;
"#
                .to_string(),
                requires: vec![],
            },
        );

        patterns.insert(
            "pda-validation".to_string(),
            SecurePattern {
                id: "pda-validation".to_string(),
                name: "PDA Validation".to_string(),
                description: "Properly validates PDA derivation".to_string(),
                template: r#"
#[derive(Accounts)]
pub struct SecureAccounts<'info> {
    #[account(
        seeds = [b"vault", user.key().as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,
    pub user: Signer<'info>,
}
"#
                .to_string(),
                requires: vec!["anchor-lang".to_string()],
            },
        );

        patterns.insert(
            "reentrancy-guard".to_string(),
            SecurePattern {
                id: "reentrancy-guard".to_string(),
                name: "Reentrancy Guard".to_string(),
                description: "Prevents reentrancy attacks".to_string(),
                template: r#"
#[account]
pub struct State {
    pub is_locked: bool,
    // ... other fields
}

pub fn secure_instruction(ctx: Context<SecureInstruction>) -> Result<()> {
    let state = &mut ctx.accounts.state;
    
    // Check and set lock
    require!(!state.is_locked, ErrorCode::ReentrancyDetected);
    state.is_locked = true;
    
    // Do work here (including any CPI)
    // ...
    
    // Release lock
    state.is_locked = false;
    
    Ok(())
}
"#
                .to_string(),
                requires: vec!["anchor-lang".to_string()],
            },
        );

        patterns.insert(
            "token-validation".to_string(),
            SecurePattern {
                id: "token-validation".to_string(),
                name: "Token Account Validation".to_string(),
                description: "Validates token account ownership and mint".to_string(),
                template: r#"
#[derive(Accounts)]
pub struct TokenTransfer<'info> {
    #[account(
        mut,
        constraint = source.owner == authority.key() @ ErrorCode::InvalidOwner,
        constraint = source.mint == expected_mint.key() @ ErrorCode::InvalidMint,
    )]
    pub source: Account<'info, TokenAccount>,
    
    #[account(
        mut,
        constraint = destination.mint == expected_mint.key() @ ErrorCode::InvalidMint,
    )]
    pub destination: Account<'info, TokenAccount>,
    
    pub authority: Signer<'info>,
    pub expected_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
}
"#
                .to_string(),
                requires: vec!["anchor-lang".to_string(), "anchor-spl".to_string()],
            },
        );

        patterns.insert(
            "slippage-protection".to_string(),
            SecurePattern {
                id: "slippage-protection".to_string(),
                name: "Slippage Protection".to_string(),
                description: "Protects against slippage and sandwich attacks".to_string(),
                template: r#"
pub fn swap(
    ctx: Context<Swap>,
    amount_in: u64,
    minimum_amount_out: u64,  // Slippage protection
    deadline: i64,            // Deadline protection
) -> Result<()> {
    // Check deadline
    let clock = Clock::get()?;
    require!(clock.unix_timestamp <= deadline, ErrorCode::DeadlineExceeded);
    
    // Calculate output
    let amount_out = calculate_output(amount_in, &ctx.accounts.pool)?;
    
    // Check slippage
    require!(amount_out >= minimum_amount_out, ErrorCode::SlippageExceeded);
    
    // Execute swap
    // ...
    
    Ok(())
}
"#
                .to_string(),
                requires: vec!["anchor-lang".to_string()],
            },
        );

        patterns.insert(
            "account-close".to_string(),
            SecurePattern {
                id: "account-close".to_string(),
                name: "Safe Account Close".to_string(),
                description: "Safely closes an account to prevent resurrection".to_string(),
                template: r#"
#[derive(Accounts)]
pub struct CloseAccount<'info> {
    #[account(
        mut,
        close = recipient,
        has_one = authority,
    )]
    pub account_to_close: Account<'info, MyAccount>,
    
    pub authority: Signer<'info>,
    
    /// CHECK: Recipient of lamports
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
}
"#
                .to_string(),
                requires: vec!["anchor-lang".to_string()],
            },
        );

        Self { patterns }
    }

    /// Get a secure pattern by ID
    pub fn get_pattern(&self, id: &str) -> Option<&SecurePattern> {
        self.patterns.get(id)
    }

    /// List all available patterns
    pub fn list_patterns(&self) -> Vec<&str> {
        self.patterns.keys().map(|s| s.as_str()).collect()
    }

    /// Generate a fix for a vulnerability
    pub fn generate_fix(&self, vulnerability_id: &str, vulnerable_code: &str) -> Option<SecureFix> {
        let pattern_id = self.map_vuln_to_pattern(vulnerability_id)?;
        let pattern = self.patterns.get(pattern_id)?;

        Some(SecureFix {
            vulnerability_id: vulnerability_id.to_string(),
            original_code: vulnerable_code.to_string(),
            fixed_code: pattern.template.clone(),
            explanation: format!(
                "Apply the '{}' pattern: {}",
                pattern.name, pattern.description
            ),
            diff: format!(
                "- {}\n+ {}",
                vulnerable_code.lines().next().unwrap_or(""),
                pattern.template.lines().nth(1).unwrap_or("")
            ),
        })
    }

    /// Map vulnerability ID to appropriate pattern
    fn map_vuln_to_pattern(&self, vuln_id: &str) -> Option<&str> {
        match vuln_id {
            "SOL-001" | "SOL-047" => Some("signer-check"),
            "SOL-002" | "SOL-037" | "SOL-038" | "SOL-045" => Some("checked-arithmetic"),
            "SOL-003" | "SOL-015" => Some("owner-check"),
            "SOL-007" | "SOL-008" | "SOL-027" => Some("pda-validation"),
            "SOL-017" | "SOL-018" => Some("reentrancy-guard"),
            "SOL-021" | "SOL-023" | "SOL-024" => Some("token-validation"),
            "SOL-033" | "SOL-034" | "SOL-051" => Some("slippage-protection"),
            "SOL-009" | "SOL-028" | "SOL-029" => Some("account-close"),
            _ => None,
        }
    }

    /// Generate multiple fixes for a list of vulnerabilities
    pub fn generate_fixes(&self, vulnerabilities: &[(String, String)]) -> Vec<SecureFix> {
        vulnerabilities
            .iter()
            .filter_map(|(id, code)| self.generate_fix(id, code))
            .collect()
    }
}

impl Default for SecureCodeGen {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codegen_creation() {
        let gen = SecureCodeGen::new();
        assert!(!gen.patterns.is_empty());
    }

    #[test]
    fn test_pattern_lookup() {
        let gen = SecureCodeGen::new();
        let pattern = gen.get_pattern("signer-check");
        assert!(pattern.is_some());
        assert_eq!(pattern.unwrap().id, "signer-check");
    }

    #[test]
    fn test_fix_generation() {
        let gen = SecureCodeGen::new();
        let fix = gen.generate_fix("SOL-001", "pub authority: AccountInfo<'info>");
        assert!(fix.is_some());
    }

    #[test]
    fn test_vuln_mapping() {
        let gen = SecureCodeGen::new();
        assert_eq!(gen.map_vuln_to_pattern("SOL-001"), Some("signer-check"));
        assert_eq!(
            gen.map_vuln_to_pattern("SOL-002"),
            Some("checked-arithmetic")
        );
    }
}
