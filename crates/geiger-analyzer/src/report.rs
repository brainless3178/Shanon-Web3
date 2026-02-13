//! Cargo-geiger analysis report data structures

use crate::metrics::UnsafeMetrics;
use serde::{Deserialize, Serialize};

/// Geiger analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeigerAnalysisReport {
    pub program_path: String,
    pub timestamp: String,
    pub findings: Vec<GeigerFinding>,
    pub metrics: UnsafeMetrics,
    pub files_scanned: usize,
    pub lines_scanned: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub safety_score: u8, // 0-100, higher is safer
    pub execution_time_ms: u64,
    pub engine_version: String,
}

/// Geiger vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeigerFinding {
    pub id: String,
    pub category: UnsafeCategory,
    pub severity: GeigerSeverity,
    pub file_path: String,
    pub line_number: usize,
    pub function_name: Option<String>,
    pub description: String,
    pub unsafe_code_snippet: String,
    pub risk_explanation: String,
    pub fix_recommendation: String,
    pub cwe: String,
    pub fingerprint: String,
    pub justification_comment: Option<String>, // SAFETY: comment if present
}

/// Unsafe code category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnsafeCategory {
    UnsafeBlock,
    UnsafeFunction,
    UnsafeTrait,
    FFICall,
    RawPointer,
    TransmuteCall,
    InlineAssembly,
    UnionType,
    UnsafeDeref,
    UnsafeCast,
}

impl UnsafeCategory {
    pub fn label(&self) -> &'static str {
        match self {
            Self::UnsafeBlock => "Unsafe Block",
            Self::UnsafeFunction => "Unsafe Function",
            Self::UnsafeTrait => "Unsafe Trait Implementation",
            Self::FFICall => "Foreign Function Interface (FFI)",
            Self::RawPointer => "Raw Pointer Usage",
            Self::TransmuteCall => "Type Transmutation",
            Self::InlineAssembly => "Inline Assembly",
            Self::UnionType => "Union Type",
            Self::UnsafeDeref => "Unsafe Dereference",
            Self::UnsafeCast => "Unsafe Type Cast",
        }
    }

    pub fn cwe(&self) -> &'static str {
        match self {
            Self::UnsafeBlock => "CWE-119", // Improper Restriction of Operations within Memory Buffer
            Self::UnsafeFunction => "CWE-676", // Use of Potentially Dangerous Function
            Self::UnsafeTrait => "CWE-1021", // Improper Restriction of Rendered UI Layers
            Self::FFICall => "CWE-111",     // Direct Use of Unsafe JNI
            Self::RawPointer => "CWE-822",  // Untrusted Pointer Dereference
            Self::TransmuteCall => "CWE-704", // Incorrect Type Conversion
            Self::InlineAssembly => "CWE-1242", // Inclusion of Undocumented Features
            Self::UnionType => "CWE-843",   // Access of Resource Using Incompatible Type
            Self::UnsafeDeref => "CWE-476", // NULL Pointer Dereference
            Self::UnsafeCast => "CWE-704",  // Incorrect Type Conversion
        }
    }
}

/// Geiger severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GeigerSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl GeigerSeverity {
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Low => 2,
            Self::Medium => 3,
            Self::High => 4,
            Self::Critical => 5,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}
