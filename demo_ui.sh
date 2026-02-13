#!/bin/bash
# Demo script to showcase the enhanced terminal UI

set -e

echo "Building the project..."
cargo build -p orchestrator --release

echo ""
echo "Running demo with test Rust file..."

# Create a test vulnerable file
mkdir -p /tmp/demo_program/src
cat > /tmp/demo_program/src/lib.rs << 'EOF'
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    program::invoke,
    pubkey::Pubkey,
};

// VULNERABILITY: Missing signer check
pub fn transfer_funds(
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let source = &accounts[0];
    let destination = &accounts[1];
    
    // Missing: if !source.is_signer { return Err(...) }
    
    **source.lamports.borrow_mut() -= amount;
    **destination.lamports.borrow_mut() += amount;
    
    Ok(())
}

// VULNERABILITY: Integer overflow
pub fn calculate_reward(base: u64, multiplier: u64) -> u64 {
    base * multiplier  // Can overflow!
}

// VULNERABILITY: Arbitrary CPI
pub fn call_external_program(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    // No validation of program_id
    invoke(
        &solana_program::instruction::Instruction {
            program_id: *program_id,
            accounts: vec![],
            data: vec![],
        },
        accounts,
    )?;
    Ok(())
}
EOF

# Create a Cargo.toml for the demo
cat > /tmp/demo_program/Cargo.toml << 'EOF'
[package]
name = "demo_program"
version = "0.1.0"
edition = "2021"

[dependencies]
solana-program = "1.18"
EOF

echo ""
echo "Running security scan with enhanced UI..."
echo ""

# Note: Running the actual scan would require API keys
# This shows the help/usage with enhanced formatting
./target/release/solana-security-swarm --help
