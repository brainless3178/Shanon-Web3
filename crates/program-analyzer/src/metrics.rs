//! Metrics and observability module
//!
//! Provides instrumentation for monitoring analysis performance and health.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Global metrics registry
pub static METRICS: once_cell::sync::Lazy<MetricsRegistry> =
    once_cell::sync::Lazy::new(MetricsRegistry::new);

/// Registry for all metrics
pub struct MetricsRegistry {
    counters: RwLock<HashMap<String, AtomicU64>>,
    histograms: RwLock<HashMap<String, HistogramData>>,
    start_time: Instant,
}

/// Histogram data for latency tracking
#[derive(Default)]
pub struct HistogramData {
    count: AtomicU64,
    sum_ms: AtomicU64,
    min_ms: AtomicU64,
    max_ms: AtomicU64,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            histograms: RwLock::new(HashMap::new()),
            start_time: Instant::now(),
        }
    }

    /// Increment a counter
    pub fn inc(&self, name: &str) {
        self.inc_by(name, 1);
    }

    /// Increment a counter by a specific amount
    pub fn inc_by(&self, name: &str, amount: u64) {
        let counters = self.counters.read().unwrap();
        if let Some(counter) = counters.get(name) {
            counter.fetch_add(amount, Ordering::Relaxed);
            return;
        }
        drop(counters);

        let mut counters = self.counters.write().unwrap();
        counters
            .entry(name.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(amount, Ordering::Relaxed);
    }

    /// Record a duration observation
    pub fn observe(&self, name: &str, duration: Duration) {
        let ms = duration.as_millis() as u64;

        let histograms = self.histograms.read().unwrap();
        if let Some(hist) = histograms.get(name) {
            hist.count.fetch_add(1, Ordering::Relaxed);
            hist.sum_ms.fetch_add(ms, Ordering::Relaxed);
            // Note: min/max are approximate due to race conditions
            hist.min_ms.fetch_min(ms, Ordering::Relaxed);
            hist.max_ms.fetch_max(ms, Ordering::Relaxed);
            return;
        }
        drop(histograms);

        let mut histograms = self.histograms.write().unwrap();
        let hist = histograms
            .entry(name.to_string())
            .or_insert_with(|| HistogramData {
                count: AtomicU64::new(0),
                sum_ms: AtomicU64::new(0),
                min_ms: AtomicU64::new(u64::MAX),
                max_ms: AtomicU64::new(0),
            });
        hist.count.fetch_add(1, Ordering::Relaxed);
        hist.sum_ms.fetch_add(ms, Ordering::Relaxed);
        hist.min_ms.fetch_min(ms, Ordering::Relaxed);
        hist.max_ms.fetch_max(ms, Ordering::Relaxed);
    }

    /// Time a closure and record the duration
    pub fn time<F, T>(&self, name: &str, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        let start = Instant::now();
        let result = f();
        self.observe(name, start.elapsed());
        result
    }

    /// Get current counter value
    pub fn get_counter(&self, name: &str) -> u64 {
        self.counters
            .read()
            .unwrap()
            .get(name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Get histogram statistics
    pub fn get_histogram_stats(&self, name: &str) -> Option<HistogramStats> {
        self.histograms.read().unwrap().get(name).map(|h| {
            let count = h.count.load(Ordering::Relaxed);
            let sum = h.sum_ms.load(Ordering::Relaxed);
            HistogramStats {
                count,
                sum_ms: sum,
                avg_ms: if count > 0 { sum / count } else { 0 },
                min_ms: h.min_ms.load(Ordering::Relaxed),
                max_ms: h.max_ms.load(Ordering::Relaxed),
            }
        })
    }

    /// Get uptime
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Export all metrics as JSON
    pub fn export_json(&self) -> serde_json::Value {
        let counters: HashMap<String, u64> = self
            .counters
            .read()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect();

        let histograms: HashMap<String, serde_json::Value> = self
            .histograms
            .read()
            .unwrap()
            .iter()
            .map(|(k, h)| {
                let count = h.count.load(Ordering::Relaxed);
                let sum = h.sum_ms.load(Ordering::Relaxed);
                (
                    k.clone(),
                    serde_json::json!({
                        "count": count,
                        "sum_ms": sum,
                        "avg_ms": if count > 0 { sum / count } else { 0 },
                        "min_ms": h.min_ms.load(Ordering::Relaxed),
                        "max_ms": h.max_ms.load(Ordering::Relaxed),
                    }),
                )
            })
            .collect();

        serde_json::json!({
            "uptime_seconds": self.uptime().as_secs(),
            "counters": counters,
            "histograms": histograms,
        })
    }

    /// Reset all metrics
    pub fn reset(&self) {
        for counter in self.counters.read().unwrap().values() {
            counter.store(0, Ordering::Relaxed);
        }
        for hist in self.histograms.read().unwrap().values() {
            hist.count.store(0, Ordering::Relaxed);
            hist.sum_ms.store(0, Ordering::Relaxed);
            hist.min_ms.store(u64::MAX, Ordering::Relaxed);
            hist.max_ms.store(0, Ordering::Relaxed);
        }
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics from a histogram
#[derive(Debug, Clone)]
pub struct HistogramStats {
    pub count: u64,
    pub sum_ms: u64,
    pub avg_ms: u64,
    pub min_ms: u64,
    pub max_ms: u64,
}

/// Metric names used throughout the codebase
pub mod metric_names {
    pub const FILES_ANALYZED: &str = "files_analyzed_total";
    pub const FINDINGS_DETECTED: &str = "findings_detected_total";
    pub const PARSE_ERRORS: &str = "parse_errors_total";
    pub const ANALYSIS_DURATION: &str = "analysis_duration_ms";
    pub const PATTERN_CHECKS: &str = "pattern_checks_total";
    pub const LLM_CALLS: &str = "llm_api_calls_total";
    pub const LLM_TOKENS: &str = "llm_tokens_used_total";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_increment() {
        let registry = MetricsRegistry::new();
        registry.inc("test_counter");
        registry.inc("test_counter");
        registry.inc_by("test_counter", 5);

        assert_eq!(registry.get_counter("test_counter"), 7);
    }

    #[test]
    fn test_histogram_observation() {
        let registry = MetricsRegistry::new();
        registry.observe("test_latency", Duration::from_millis(100));
        registry.observe("test_latency", Duration::from_millis(200));
        registry.observe("test_latency", Duration::from_millis(150));

        let stats = registry.get_histogram_stats("test_latency").unwrap();
        assert_eq!(stats.count, 3);
        assert_eq!(stats.sum_ms, 450);
        assert_eq!(stats.avg_ms, 150);
        assert_eq!(stats.min_ms, 100);
        assert_eq!(stats.max_ms, 200);
    }

    #[test]
    fn test_time_function() {
        let registry = MetricsRegistry::new();

        let result = registry.time("test_op", || {
            std::thread::sleep(Duration::from_millis(10));
            42
        });

        assert_eq!(result, 42);

        let stats = registry.get_histogram_stats("test_op").unwrap();
        assert_eq!(stats.count, 1);
        assert!(stats.sum_ms >= 10);
    }

    #[test]
    fn test_export_json() {
        let registry = MetricsRegistry::new();
        registry.inc("counter1");
        registry.observe("hist1", Duration::from_millis(100));

        let json = registry.export_json();
        assert!(json["counters"]["counter1"].as_u64().unwrap() >= 1);
        assert!(json["histograms"]["hist1"]["count"].as_u64().unwrap() >= 1);
    }
}
