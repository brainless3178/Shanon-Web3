//! Benchmark Suite for Solana Security Swarm
//!
//! Provides benchmarking utilities for measuring analysis performance
//! and comparing results across different analyzers.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Result of a benchmark run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub name: String,
    pub duration: Duration,
    pub files_analyzed: usize,
    pub findings_count: usize,
    pub memory_usage_bytes: Option<u64>,
    pub throughput_files_per_sec: f64,
}

/// Benchmark configuration
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    pub iterations: usize,
    pub warmup_iterations: usize,
    pub measure_memory: bool,
    pub verbose: bool,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            iterations: 5,
            warmup_iterations: 2,
            measure_memory: false,
            verbose: true,
        }
    }
}

/// Main benchmark suite
pub struct BenchmarkSuite {
    config: BenchmarkConfig,
    results: HashMap<String, Vec<BenchmarkResult>>,
}

impl BenchmarkSuite {
    /// Create a new benchmark suite
    pub fn new(config: BenchmarkConfig) -> Self {
        Self {
            config,
            results: HashMap::new(),
        }
    }

    /// Create with default configuration
    pub fn default_suite() -> Self {
        Self::new(BenchmarkConfig::default())
    }

    /// Run a benchmark with the given name and function
    pub fn benchmark<F>(&mut self, name: &str, mut func: F) -> BenchmarkResult
    where
        F: FnMut() -> (usize, usize), // Returns (files_analyzed, findings_count)
    {
        // Warmup
        for _ in 0..self.config.warmup_iterations {
            let _ = func();
        }

        let mut durations = Vec::with_capacity(self.config.iterations);
        let mut last_result = (0, 0);

        // Actual benchmark runs
        for i in 0..self.config.iterations {
            let start = Instant::now();
            last_result = func();
            let duration = start.elapsed();
            durations.push(duration);

            if self.config.verbose {
                println!("  Run {}/{}: {:?}", i + 1, self.config.iterations, duration);
            }
        }

        // Calculate average
        let total: Duration = durations.iter().sum();
        let avg_duration = total / self.config.iterations as u32;
        let throughput = if avg_duration.as_secs_f64() > 0.0 {
            last_result.0 as f64 / avg_duration.as_secs_f64()
        } else {
            f64::INFINITY
        };

        let result = BenchmarkResult {
            name: name.to_string(),
            duration: avg_duration,
            files_analyzed: last_result.0,
            findings_count: last_result.1,
            memory_usage_bytes: None,
            throughput_files_per_sec: throughput,
        };

        // Store result
        self.results
            .entry(name.to_string())
            .or_default()
            .push(result.clone());

        result
    }

    /// Get all results for a benchmark
    pub fn get_results(&self, name: &str) -> Option<&Vec<BenchmarkResult>> {
        self.results.get(name)
    }

    /// Print a summary of all benchmarks
    pub fn print_summary(&self) {
        println!("\n{:=<60}", "");
        println!("BENCHMARK SUMMARY");
        println!("{:=<60}", "");

        for (name, results) in &self.results {
            if let Some(latest) = results.last() {
                println!("\n{}", name);
                println!("  Duration: {:?}", latest.duration);
                println!("  Files analyzed: {}", latest.files_analyzed);
                println!("  Findings: {}", latest.findings_count);
                println!(
                    "  Throughput: {:.2} files/sec",
                    latest.throughput_files_per_sec
                );
            }
        }

        println!("\n{:=<60}", "");
    }

    /// Compare two benchmarks
    pub fn compare(&self, name1: &str, name2: &str) -> Option<ComparisonResult> {
        let r1 = self.results.get(name1)?.last()?;
        let r2 = self.results.get(name2)?.last()?;

        let speedup = if r2.duration.as_nanos() > 0 {
            r1.duration.as_nanos() as f64 / r2.duration.as_nanos() as f64
        } else {
            1.0
        };

        Some(ComparisonResult {
            baseline: r1.clone(),
            comparison: r2.clone(),
            speedup,
            findings_diff: r2.findings_count as i64 - r1.findings_count as i64,
        })
    }
}

/// Result of comparing two benchmarks
#[derive(Debug, Clone)]
pub struct ComparisonResult {
    pub baseline: BenchmarkResult,
    pub comparison: BenchmarkResult,
    pub speedup: f64,
    pub findings_diff: i64,
}

impl ComparisonResult {
    /// Print comparison in human-readable format
    pub fn print(&self) {
        println!(
            "\nComparison: {} vs {}",
            self.baseline.name, self.comparison.name
        );
        println!("  Speedup: {:.2}x", self.speedup);
        println!("  Findings difference: {:+}", self.findings_diff);
    }
}

/// Timer helper for ad-hoc timing
pub struct Timer {
    start: Instant,
    name: String,
}

impl Timer {
    pub fn start(name: &str) -> Self {
        Self {
            start: Instant::now(),
            name: name.to_string(),
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn stop(self) -> Duration {
        let elapsed = self.start.elapsed();
        println!("[{}] completed in {:?}", self.name, elapsed);
        elapsed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_suite() {
        let mut suite = BenchmarkSuite::new(BenchmarkConfig {
            iterations: 2,
            warmup_iterations: 1,
            measure_memory: false,
            verbose: false,
        });

        let result = suite.benchmark("test_bench", || {
            std::thread::sleep(Duration::from_millis(10));
            (5, 10)
        });

        assert!(result.duration >= Duration::from_millis(10));
        assert_eq!(result.files_analyzed, 5);
        assert_eq!(result.findings_count, 10);
    }

    #[test]
    fn test_timer() {
        let timer = Timer::start("test");
        std::thread::sleep(Duration::from_millis(5));
        let elapsed = timer.elapsed();
        assert!(elapsed >= Duration::from_millis(5));
    }
}
