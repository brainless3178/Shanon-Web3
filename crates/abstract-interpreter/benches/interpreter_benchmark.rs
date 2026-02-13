//! Benchmarks for the abstract interpreter
//!
//! Run with: cargo bench -p abstract-interpreter

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use abstract_interpreter::{AbstractInterpreter, AbstractState, Interval};
use std::collections::HashMap;

fn bench_interval_arithmetic(c: &mut Criterion) {
    let a = Interval::new(0, u64::MAX as i128);
    let b = Interval::new(1, 1000);

    let mut group = c.benchmark_group("interval_arithmetic");

    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(a) + black_box(b))
    });

    group.bench_function("sub", |bencher| {
        bencher.iter(|| black_box(a) - black_box(b))
    });

    group.bench_function("mul", |bencher| {
        bencher.iter(|| black_box(a) * black_box(b))
    });

    group.bench_function("div", |bencher| {
        bencher.iter(|| black_box(a) / black_box(b))
    });

    group.finish();
}

fn bench_interval_lattice_ops(c: &mut Criterion) {
    let a = Interval::new(10, 100);
    let b = Interval::new(50, 200);

    let mut group = c.benchmark_group("interval_lattice");

    group.bench_function("join", |bencher| {
        bencher.iter(|| black_box(a).join(black_box(&b)))
    });

    group.bench_function("meet", |bencher| {
        bencher.iter(|| black_box(a).meet(black_box(&b)))
    });

    group.bench_function("widen", |bencher| {
        bencher.iter(|| black_box(a).widen(black_box(&b)))
    });

    group.bench_function("narrow", |bencher| {
        bencher.iter(|| black_box(a).narrow(black_box(&b)))
    });

    group.finish();
}

fn bench_abstract_state(c: &mut Criterion) {
    let mut group = c.benchmark_group("abstract_state");

    for num_vars in [10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::new("join", num_vars),
            &num_vars,
            |bencher, &n| {
                let mut state_a = AbstractState::new();
                let mut state_b = AbstractState::new();
                for i in 0..n {
                    state_a.set(format!("var_{}", i), Interval::new(0, i as i128 * 100));
                    state_b.set(format!("var_{}", i), Interval::new(i as i128 * 50, i as i128 * 200));
                }
                bencher.iter(|| black_box(&state_a).join(black_box(&state_b)))
            },
        );
    }

    group.finish();
}

fn bench_analyze_source(c: &mut Criterion) {
    let source = r#"
use anchor_lang::prelude::*;

pub fn deposit(amount: u64, balance: u64) -> u64 {
    let new_balance = balance + amount;
    let fee = amount * 3 / 100;
    let net = amount - fee;
    new_balance + net
}

pub fn withdraw(amount: u64, balance: u64) -> u64 {
    let result = balance - amount;
    result
}

pub fn swap(amount_in: u64, reserve_a: u64, reserve_b: u64) -> u64 {
    let amount_out = amount_in * reserve_b / reserve_a;
    amount_out
}
"#;

    c.bench_function("analyze_source", |bencher| {
        bencher.iter(|| {
            let mut interpreter = AbstractInterpreter::new();
            let _ = interpreter.analyze_source(black_box(source), "bench.rs");
        })
    });
}

fn bench_eval_with_bounds(c: &mut Criterion) {
    let mut group = c.benchmark_group("eval_with_bounds");

    group.bench_function("simple_add", |bencher| {
        bencher.iter(|| {
            let mut interpreter = AbstractInterpreter::new();
            let mut bounds = HashMap::new();
            bounds.insert("x".to_string(), (0, 1000));
            bounds.insert("y".to_string(), (0, 500));
            let _ = interpreter.analyze_with_bounds(black_box("x + y"), bounds);
        })
    });

    group.bench_function("complex_expr", |bencher| {
        bencher.iter(|| {
            let mut interpreter = AbstractInterpreter::new();
            let mut bounds = HashMap::new();
            bounds.insert("amount".to_string(), (0, u64::MAX as i128));
            bounds.insert("fee_bps".to_string(), (0, 10000));
            let _ = interpreter.analyze_with_bounds(black_box("amount * fee_bps / 10000"), bounds);
        })
    });

    group.finish();
}

fn bench_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("interpreter_scaling");

    for num_functions in [5, 10, 25, 50] {
        let mut source = String::new();
        for i in 0..num_functions {
            source.push_str(&format!(
                "pub fn func_{}(a: u64, b: u64) -> u64 {{
    let x = a + b;
    let y = x * 2;
    let z = y - a;
    z / b
}}\n\n",
                i
            ));
        }

        group.bench_with_input(
            BenchmarkId::new("analyze", num_functions),
            &source,
            |bencher, code| {
                bencher.iter(|| {
                    let mut interpreter = AbstractInterpreter::new();
                    let _ = interpreter.analyze_source(black_box(code), "bench.rs");
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_interval_arithmetic,
    bench_interval_lattice_ops,
    bench_abstract_state,
    bench_analyze_source,
    bench_eval_with_bounds,
    bench_scaling,
);

criterion_main!(benches);
