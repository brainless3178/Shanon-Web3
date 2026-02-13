//! Benchmarks for the security fuzzer
//!
//! Run with: cargo bench -p security-fuzzer

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use security_fuzzer::{
    CoverageTracker, FieldSchema, FieldType, FuzzInput, FuzzInputSchema, FuzzResult, FuzzValue,
    FuzzerConfig, SecurityFuzzer,
};
use std::collections::HashMap;

fn make_sample_input() -> FuzzInput {
    let mut fields = HashMap::new();
    fields.insert("amount".to_string(), FuzzValue::U64(1_000_000));
    fields.insert("fee_bps".to_string(), FuzzValue::U16(30));
    fields.insert("recipient".to_string(), FuzzValue::Pubkey([0xAB; 32]));
    fields.insert("data".to_string(), FuzzValue::Bytes(vec![1, 2, 3, 4, 5]));

    FuzzInput {
        data: vec![0; 64],
        fields,
        accounts: Vec::new(),
        generation: 0,
        coverage_hash: String::new(),
    }
}

fn bench_fuzz_value_mutation(c: &mut Criterion) {
    use rand::{rngs::StdRng, SeedableRng};

    let mut group = c.benchmark_group("fuzz_value_mutate");

    let mut rng = StdRng::seed_from_u64(42);

    group.bench_function("u64", |bencher| {
        let val = FuzzValue::U64(1_000_000);
        bencher.iter(|| black_box(&val).mutate(&mut rng))
    });

    group.bench_function("bytes", |bencher| {
        let val = FuzzValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03]);
        bencher.iter(|| black_box(&val).mutate(&mut rng))
    });

    group.bench_function("pubkey", |bencher| {
        let val = FuzzValue::Pubkey([0xAB; 32]);
        bencher.iter(|| black_box(&val).mutate(&mut rng))
    });

    group.bench_function("string", |bencher| {
        let val = FuzzValue::String("hello_world_test".to_string());
        bencher.iter(|| black_box(&val).mutate(&mut rng))
    });

    group.finish();
}

fn bench_coverage_tracker(c: &mut Criterion) {
    let mut group = c.benchmark_group("coverage_tracker");

    for size in [1024, 4096, 65536] {
        group.bench_with_input(
            BenchmarkId::new("update", size),
            &size,
            |bencher, &sz| {
                let mut tracker = CoverageTracker::new(sz);
                let bitmap: Vec<u8> = (0..sz).map(|i| if i % 7 == 0 { 1 } else { 0 }).collect();
                bencher.iter(|| tracker.update(black_box(&bitmap)))
            },
        );

        group.bench_with_input(
            BenchmarkId::new("hash_coverage", size),
            &size,
            |bencher, &sz| {
                let bitmap: Vec<u8> = (0..sz).map(|i| (i % 256) as u8).collect();
                bencher.iter(|| CoverageTracker::hash_coverage(black_box(&bitmap)))
            },
        );

        group.bench_with_input(
            BenchmarkId::new("is_new_coverage", size),
            &size,
            |bencher, &sz| {
                let mut tracker = CoverageTracker::new(sz);
                let mut counter = 0u64;
                bencher.iter(|| {
                    counter += 1;
                    let bitmap: Vec<u8> = (0..sz)
                        .map(|i| if (i as u64 + counter) % 13 == 0 { 1 } else { 0 })
                        .collect();
                    tracker.is_new_coverage(black_box(&bitmap))
                })
            },
        );
    }

    group.finish();
}

fn bench_input_generation(c: &mut Criterion) {
    let schema = FuzzInputSchema {
        fields: vec![
            FieldSchema {
                name: "amount".to_string(),
                field_type: FieldType::U64,
            },
            FieldSchema {
                name: "fee".to_string(),
                field_type: FieldType::U16,
            },
            FieldSchema {
                name: "recipient".to_string(),
                field_type: FieldType::Pubkey,
            },
            FieldSchema {
                name: "memo".to_string(),
                field_type: FieldType::String(64),
            },
            FieldSchema {
                name: "data".to_string(),
                field_type: FieldType::Bytes(128),
            },
        ],
    };

    c.bench_function("generate_random_input", |bencher| {
        let config = FuzzerConfig::default();
        let mut fuzzer = SecurityFuzzer::new(config);
        bencher.iter(|| fuzzer.generate_random_input(black_box(&schema)))
    });
}

fn bench_input_mutation(c: &mut Criterion) {
    let input = make_sample_input();

    c.bench_function("mutate_input", |bencher| {
        let config = FuzzerConfig::default();
        let mut fuzzer = SecurityFuzzer::new(config);
        bencher.iter(|| fuzzer.mutate_input(black_box(&input)))
    });
}

fn bench_process_result(c: &mut Criterion) {
    c.bench_function("process_result", |bencher| {
        let config = FuzzerConfig {
            coverage_size: 4096,
            ..FuzzerConfig::default()
        };
        let mut fuzzer = SecurityFuzzer::new(config);

        let input = make_sample_input();
        fuzzer.add_seed(input.clone());

        let mut counter = 0u64;
        bencher.iter(|| {
            counter += 1;
            let bitmap: Vec<u8> = (0..4096)
                .map(|i| if (i as u64 + counter) % 19 == 0 { 1 } else { 0 })
                .collect();
            let result = FuzzResult {
                input: input.clone(),
                success: true,
                error: None,
                error_code: None,
                coverage_bitmap: bitmap,
                interesting: false,
                is_crash: false,
                execution_time_us: 100,
            };
            fuzzer.process_result(black_box(result));
        })
    });
}

fn bench_fuzz_loop(c: &mut Criterion) {
    c.bench_function("fuzz_100_iterations", |bencher| {
        let schema = FuzzInputSchema {
            fields: vec![
                FieldSchema {
                    name: "amount".to_string(),
                    field_type: FieldType::U64,
                },
                FieldSchema {
                    name: "flag".to_string(),
                    field_type: FieldType::Bool,
                },
            ],
        };

        bencher.iter(|| {
            let config = FuzzerConfig {
                max_iterations: 100,
                coverage_size: 1024,
                ..FuzzerConfig::default()
            };
            let mut fuzzer = SecurityFuzzer::new(config);

            let seed = fuzzer.generate_random_input(&schema);
            fuzzer.add_seed(seed);

            fuzzer.fuzz(|input| FuzzResult {
                input: input.clone(),
                success: true,
                error: None,
                error_code: None,
                coverage_bitmap: vec![0; 1024],
                interesting: false,
                is_crash: false,
                execution_time_us: 10,
            })
        })
    });
}

criterion_group!(
    benches,
    bench_fuzz_value_mutation,
    bench_coverage_tracker,
    bench_input_generation,
    bench_input_mutation,
    bench_process_result,
    bench_fuzz_loop,
);

criterion_main!(benches);
