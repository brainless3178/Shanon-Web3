//! Ensemble Scoring Module
//!
//! Combines predictions from multiple ML models (embeddings, GNN, anomaly detection,
//! pattern learning) using weighted voting to produce final confidence scores.

use crate::report::{DetectionMethod, L3xFinding};
use rayon::prelude::*;

pub struct EnsembleScorer {
    /// Weights for each detection method
    weights: EnsembleWeights,
}

struct EnsembleWeights {
    code_embedding: f32,
    control_flow_gnn: f32,
    anomaly_detection: f32,
    pattern_learning: f32,
}

impl Default for EnsembleWeights {
    fn default() -> Self {
        Self {
            code_embedding: 0.25,
            control_flow_gnn: 0.30,
            anomaly_detection: 0.20,
            pattern_learning: 0.25,
        }
    }
}

impl EnsembleScorer {
    pub fn new() -> Self {
        Self {
            weights: EnsembleWeights::default(),
        }
    }

    /// Score and rank findings using ensemble method
    pub fn score_and_rank(
        &self,
        mut findings: Vec<L3xFinding>,
        confidence_threshold: f32,
    ) -> Vec<L3xFinding> {
        // Parallel processing for large finding sets
        findings.par_iter_mut().for_each(|finding| {
            let ensemble_score = self.compute_ensemble_score(finding);
            finding.confidence = ensemble_score;
        });

        // Filter by threshold
        findings.retain(|f| f.confidence >= confidence_threshold);

        // Sort by confidence (descending)
        findings.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        findings
    }

    /// Compute ensemble score from individual model predictions
    fn compute_ensemble_score(&self, finding: &L3xFinding) -> f32 {
        let base_confidence = finding.confidence;

        let method_weight = match &finding.detection_method {
            DetectionMethod::CodeEmbedding { .. } => self.weights.code_embedding,
            DetectionMethod::ControlFlowGNN { .. } => self.weights.control_flow_gnn,
            DetectionMethod::AnomalyDetection { .. } => self.weights.anomaly_detection,
            DetectionMethod::PatternLearning { .. } => self.weights.pattern_learning,
            DetectionMethod::Ensemble { .. } => 1.0,
        };

        // Weighted score with severity boost
        let severity_boost = match finding.severity {
            crate::report::L3xSeverity::Critical => 1.2,
            crate::report::L3xSeverity::High => 1.1,
            crate::report::L3xSeverity::Medium => 1.0,
            crate::report::L3xSeverity::Low => 0.9,
            crate::report::L3xSeverity::Info => 0.8,
        };

        (base_confidence * method_weight * severity_boost).min(0.99)
    }
}

impl Default for EnsembleScorer {
    fn default() -> Self {
        Self::new()
    }
}
