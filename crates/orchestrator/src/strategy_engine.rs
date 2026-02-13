//! Strategy Engine: The brain of the Triage Funnel.
//!
//! Responsibilities:
//! 1. Rank findings by Risk/Effort ratio.
//! 2. Identify "Quick Wins" (High confidence + Low effort).
//! 3. Group findings by impact chains.

use crate::audit_pipeline::ConfirmedExploit;

use std::collections::HashMap;

pub struct StrategyEngine;

#[derive(Debug, Clone)]
pub struct RankedFinding<'a> {
    pub exploit: &'a ConfirmedExploit,
    pub risk_score: f32,
    pub effort_score: u32,
    pub quick_win: bool,
    pub instance_count: usize,
    pub aggregated_ids: Vec<String>,
}

impl StrategyEngine {
    /// Ranks exploits with DEDUPLICATION and high-signal filtering.
    pub fn rank_findings(exploits: &[ConfirmedExploit]) -> Vec<RankedFinding<'_>> {
        // Group by (Vulnerability Type + Instruction/Function) to eliminate the "Crying Wolf" spam.
        let mut grouped: HashMap<(String, String), Vec<&ConfirmedExploit>> = HashMap::new();

        for e in exploits {
            if e.confidence_score >= 85 {
                let key = (e.vulnerability_type.clone(), e.instruction.clone());
                grouped.entry(key).or_default().push(e);
            }
        }

        let mut ranked: Vec<RankedFinding> = grouped
            .into_iter()
            .map(|((vuln_type, _), instances)| {
                let primary = instances[0];

                // Adjust severity: Downgrade noise patterns
                let adjusted_severity = match vuln_type.as_str() {
                    "Missing Event Emission" | "Missing IDL Description" => 1,
                    "Missing Pause Mechanism" if primary.value_at_risk_usd < 50_000.0 => 2,
                    _ => primary.severity,
                };

                // IMPACT ANALYSIS: Sum the risk but CAP it at a reasonable per-program limit ($1.2M cap)
                // This avoids the typical noise where the same TVL is counted multiple times across instances.
                let raw_risk_sum: f32 = instances.iter().map(|e| e.value_at_risk_usd as f32).sum();
                let limited_risk = raw_risk_sum.min(1_200_000.0);

                let risk_score = limited_risk
                    * (primary.confidence_score as f32 / 100.0)
                    * adjusted_severity as f32;

                // EFFORT ESTIMATION: Root causes are often quick fixes once identified.
                let effort = match vuln_type.as_str() {
                    "Missing Signer Validation" | "Authority Bypass" => 10,
                    "Integer Overflow/Underflow" => 20,
                    _ => 60,
                };

                RankedFinding {
                    exploit: primary,
                    risk_score,
                    effort_score: effort,
                    quick_win: adjusted_severity >= 4 && effort <= 30,
                    instance_count: instances.len(),
                    aggregated_ids: instances.iter().map(|e| e.id.clone()).collect(),
                }
            })
            .collect();

        ranked.sort_by(|a, b| {
            b.risk_score
                .partial_cmp(&a.risk_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        ranked
    }

    /// Identify the "Critical Path" using Aggregated Root Cause analysis.
    pub fn identify_critical_path(exploits: &[ConfirmedExploit]) -> Vec<String> {
        let ranked = Self::rank_findings(exploits);
        if ranked.is_empty() {
            return Vec::new();
        }

        // Take only the top 5 focus points - the Pareto root causes
        ranked
            .iter()
            .take(5)
            .map(|r| r.exploit.id.clone())
            .collect()
    }
}
