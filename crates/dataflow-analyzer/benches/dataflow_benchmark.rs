//! Benchmarks for the dataflow analyzer
//!
//! Run with: cargo bench -p dataflow-analyzer

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dataflow_analyzer::DataflowAnalyzer;

const SAMPLE_SOURCE: &str = r#"
use anchor_lang::prelude::*;

pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    let vault = ctx.accounts.vault;
    let balance = vault.balance;
    let new_balance = balance - amount;
    vault.balance = new_balance;
    Ok(())
}

pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let vault = ctx.accounts.vault;
    let fee = amount * 3 / 100;
    let net_amount = amount - fee;
    vault.balance = vault.balance + net_amount;
    vault.total_deposits = vault.total_deposits + 1;
    Ok(())
}
"#;

fn bench_analyze_source(c: &mut Criterion) {
    c.bench_function("analyze_source", |bencher| {
        bencher.iter(|| {
            let mut analyzer = DataflowAnalyzer::new();
            let _ = analyzer.analyze_source(black_box(SAMPLE_SOURCE), "bench.rs");
        })
    });
}

fn bench_query_after_analysis(c: &mut Criterion) {
    let mut analyzer = DataflowAnalyzer::new();
    let _ = analyzer.analyze_source(SAMPLE_SOURCE, "bench.rs");

    let mut group = c.benchmark_group("query");

    group.bench_function("get_definitions", |bencher| {
        bencher.iter(|| {
            let _ = analyzer.get_definitions(black_box("amount"));
        })
    });

    group.bench_function("get_uses", |bencher| {
        bencher.iter(|| {
            let _ = analyzer.get_uses(black_box("amount"));
        })
    });

    group.bench_function("find_uninitialized_uses", |bencher| {
        bencher.iter(|| {
            let _ = analyzer.find_uninitialized_uses();
        })
    });

    group.bench_function("find_dead_definitions", |bencher| {
        bencher.iter(|| {
            let _ = analyzer.find_dead_definitions();
        })
    });

    group.finish();
}

fn bench_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("dataflow_scaling");

    for num_functions in [5, 10, 25, 50] {
        let mut source = String::new();
        for i in 0..num_functions {
            source.push_str(&format!(
                "pub fn func_{}(amount: u64, balance: u64) -> u64 {{
    let fee = amount * 3 / 100;
    let net = amount - fee;
    let new_balance = balance + net;
    new_balance
}}\n\n",
                i
            ));
        }

        group.bench_with_input(
            BenchmarkId::new("analyze", num_functions),
            &source,
            |bencher, code| {
                bencher.iter(|| {
                    let mut analyzer = DataflowAnalyzer::new();
                    let _ = analyzer.analyze_source(black_box(code), "bench.rs");
                })
            },
        );
    }

    group.finish();
}

fn bench_complex_dataflow(c: &mut Criterion) {
    let complex_source = r#"
pub fn complex_flow(a: u64, b: u64, c: u64) -> u64 {
    let x = a + b;
    let y = b + c;
    let z = x * y;
    let w = z - a;
    let v = w / c;
    let result = v + x;
    result
}

pub fn branching_flow(amount: u64, threshold: u64) -> u64 {
    let fee = amount * 5 / 1000;
    let net = amount - fee;
    let bonus = net / 10;
    let total = net + bonus;
    total
}
"#;

    c.bench_function("complex_dataflow", |bencher| {
        bencher.iter(|| {
            let mut analyzer = DataflowAnalyzer::new();
            let _ = analyzer.analyze_source(black_box(complex_source), "bench.rs");
        })
    });
}

criterion_group!(
    benches,
    bench_analyze_source,
    bench_query_after_analysis,
    bench_scaling,
    bench_complex_dataflow,
);

criterion_main!(benches);
