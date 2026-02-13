//! Benchmarks for the program analyzer
//!
//! Run with: cargo bench -p program-analyzer

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use program_analyzer::ProgramAnalyzer;

/// Sample Anchor program for benchmarking
const SAMPLE_PROGRAM: &str = r#"
use anchor_lang::prelude::*;

declare_id!("Benchmark111111111111111111111111111111111");

#[program]
pub mod benchmark_program {
    use super::*;
    
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.bump = ctx.bumps.vault;
        Ok(())
    }
    
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance.checked_add(amount).ok_or(ErrorCode::Overflow)?;
        Ok(())
    }
    
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        require!(vault.balance >= amount, ErrorCode::InsufficientFunds);
        vault.balance = vault.balance.checked_sub(amount).ok_or(ErrorCode::Underflow)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Vault::LEN,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut, seeds = [b"vault", vault.authority.as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, seeds = [b"vault", vault.authority.as_ref()], bump = vault.bump, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    pub bump: u8,
}

impl Vault {
    pub const LEN: usize = 32 + 8 + 1;
}

#[error_code]
pub enum ErrorCode {
    #[msg("Overflow")]
    Overflow,
    #[msg("Underflow")]
    Underflow,
    #[msg("Insufficient funds")]
    InsufficientFunds,
}
"#;

fn generate_large_program(num_functions: usize) -> String {
    let mut code = String::from("use anchor_lang::prelude::*;\n\n");

    for i in 0..num_functions {
        code.push_str(&format!(
            r#"
pub fn function_{i}(ctx: Context<Ctx{i}>, amount: u64) -> Result<()> {{
    let vault = &mut ctx.accounts.vault;
    vault.balance = vault.balance.checked_add(amount).ok_or(ErrorCode::Overflow)?;
    msg!("Function {i} executed");
    Ok(())
}}
"#,
            i = i
        ));
    }

    code
}

fn bench_parse_source(c: &mut Criterion) {
    c.bench_function("parse_source", |b| {
        b.iter(|| {
            let _ = ProgramAnalyzer::from_source(black_box(SAMPLE_PROGRAM));
        })
    });
}

fn bench_scan_vulnerabilities(c: &mut Criterion) {
    let analyzer = ProgramAnalyzer::from_source(SAMPLE_PROGRAM).unwrap();

    c.bench_function("scan_vulnerabilities", |b| {
        b.iter(|| {
            let _ = analyzer.scan_for_vulnerabilities();
        })
    });
}

fn bench_extract_schemas(c: &mut Criterion) {
    let analyzer = ProgramAnalyzer::from_source(SAMPLE_PROGRAM).unwrap();

    c.bench_function("extract_account_schemas", |b| {
        b.iter(|| {
            let _ = analyzer.extract_account_schemas();
        })
    });
}

fn bench_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("scaling_by_functions");

    for num_functions in [10, 50, 100, 200].iter() {
        let code = generate_large_program(*num_functions);

        group.bench_with_input(BenchmarkId::new("scan", num_functions), &code, |b, code| {
            if let Ok(analyzer) = ProgramAnalyzer::from_source(code) {
                b.iter(|| {
                    let _ = analyzer.scan_for_vulnerabilities();
                })
            }
        });
    }

    group.finish();
}

/// Benchmark scanning vulnerable code with known issues
fn bench_scan_vulnerable_program(c: &mut Criterion) {
    let vulnerable_code = r#"
use anchor_lang::prelude::*;

#[program]
pub mod vulnerable {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        // Missing signer check, unchecked arithmetic, no balance validation
        vault.balance = vault.balance - amount;
        **ctx.accounts.vault_account.try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.user.try_borrow_mut_lamports()? += amount;
        Ok(())
    }

    pub fn swap(ctx: Context<Swap>, amount_in: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let amount_out = amount_in * pool.reserve_b / pool.reserve_a;
        pool.reserve_a += amount_in;
        pool.reserve_b -= amount_out;
        Ok(())
    }
}
"#;

    let analyzer = ProgramAnalyzer::from_source(vulnerable_code).unwrap();
    c.bench_function("scan_vulnerable_program", |b| {
        b.iter(|| {
            let _ = analyzer.scan_for_vulnerabilities();
        })
    });
}

/// Benchmark parallel vs sequential scanning
fn bench_parallel_scan(c: &mut Criterion) {
    let analyzer = ProgramAnalyzer::from_source(SAMPLE_PROGRAM).unwrap();

    let mut group = c.benchmark_group("scan_method");

    group.bench_function("sequential", |b| {
        b.iter(|| {
            let _ = analyzer.scan_for_vulnerabilities();
        })
    });

    group.bench_function("parallel", |b| {
        b.iter(|| {
            let _ = analyzer.scan_for_vulnerabilities_parallel();
        })
    });

    group.finish();
}

/// Benchmark schema extraction at different program sizes
fn bench_schema_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("schema_extraction");

    for num_structs in [1, 5, 10, 25].iter() {
        let mut code = String::from("use anchor_lang::prelude::*;\n\n");
        for i in 0..*num_structs {
            code.push_str(&format!(
                "#[account]\npub struct State{} {{\n    pub authority: Pubkey,\n    pub balance: u64,\n    pub bump: u8,\n}}\n\n",
                i
            ));
        }

        group.bench_with_input(
            BenchmarkId::new("extract", num_structs),
            &code,
            |b, code| {
                if let Ok(analyzer) = ProgramAnalyzer::from_source(code) {
                    b.iter(|| {
                        let _ = analyzer.extract_account_schemas();
                    })
                }
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_parse_source,
    bench_scan_vulnerabilities,
    bench_extract_schemas,
    bench_scaling,
    bench_scan_vulnerable_program,
    bench_parallel_scan,
    bench_schema_scaling,
);

criterion_main!(benches);
