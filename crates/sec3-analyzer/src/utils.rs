//! Shared AST utilities for Sec3 static analysis detectors.
//!
//! Provides helper functions for:
//! - Collecting Rust source files from a program directory
//! - Parsing `syn` AST attributes (#[derive(...)], #[account(...)])
//! - Generating deterministic finding IDs and fingerprints
//! - Extracting source snippets and line numbers

use crate::report::Sec3Category;
use sha2::{Digest, Sha256};
use std::path::Path;
use walkdir::WalkDir;

// ─── File Collection ────────────────────────────────────────────────────────

/// Recursively collect all `.rs` source files under a program directory.
/// Returns `(relative_path, file_content)` pairs.
///
/// Skips `target/`, `node_modules/`, `.git/`, `test_targets/`, and hidden dirs.
pub fn collect_rust_sources(program_path: &Path) -> Vec<(String, String)> {
    let mut sources = Vec::new();

    let walker = WalkDir::new(program_path)
        .max_depth(10)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_str().unwrap_or("");
            !name.starts_with('.')
                && name != "target"
                && name != "node_modules"
                && name != "test_targets"
                && name != "tests"
        });

    for entry in walker.filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "rs") {
                if let Ok(content) = std::fs::read_to_string(path) {
                    let relative = path
                        .strip_prefix(program_path)
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|_| path.to_string_lossy().to_string());
                    sources.push((relative, content));
                }
            }
        }
    }

    sources
}

// ─── Attribute Helpers ──────────────────────────────────────────────────────

/// Check if an AST item has `#[derive(Name)]` among its attributes.
pub fn has_derive(attrs: &[syn::Attribute], derive_name: &str) -> bool {
    for attr in attrs {
        if attr.path().is_ident("derive") {
            let tokens = attr.meta.to_token_stream().to_string();
            if tokens.contains(derive_name) {
                return true;
            }
        }
    }
    false
}

use quote::ToTokens;

/// Convert all attributes to a single string for pattern matching.
pub fn attrs_to_string(attrs: &[syn::Attribute]) -> String {
    attrs
        .iter()
        .map(|a| a.to_token_stream().to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Check if an `#[account(...)]` attribute contains a specific key.
pub fn field_has_account_attr_key(attrs: &[syn::Attribute], key: &str) -> bool {
    for attr in attrs {
        if attr.path().is_ident("account") {
            let tokens = attr.meta.to_token_stream().to_string();
            if tokens.contains(key) {
                return true;
            }
        }
    }
    false
}

/// Check if a field has any `#[account(...)]` constraint at all.
pub fn field_has_any_account_constraint(attrs: &[syn::Attribute]) -> bool {
    for attr in attrs {
        if attr.path().is_ident("account") {
            let tokens = attr.meta.to_token_stream().to_string();
            // Has meaningful content beyond just `#[account]`
            if tokens.len() > 15 {
                return true;
            }
        }
    }
    false
}

/// Check for `/// CHECK:` doc comment, optionally containing a keyword.
pub fn has_check_doc_comment(attrs: &[syn::Attribute], keyword: &str) -> bool {
    for attr in attrs {
        if let syn::Meta::NameValue(nv) = &attr.meta {
            if nv.path.is_ident("doc") {
                let value = nv.value.to_token_stream().to_string();
                let lower = value.to_lowercase();
                if lower.contains("check:") && lower.contains(keyword) {
                    return true;
                }
            }
        }
    }
    false
}

/// Check for any `/// CHECK:` doc comment (regardless of content).
pub fn has_any_check_doc(attrs: &[syn::Attribute]) -> bool {
    for attr in attrs {
        if let syn::Meta::NameValue(nv) = &attr.meta {
            if nv.path.is_ident("doc") {
                let value = nv.value.to_token_stream().to_string();
                if value.to_uppercase().contains("CHECK:")
                    || value.to_uppercase().contains("CHECK :")
                {
                    return true;
                }
            }
        }
    }
    false
}

// ─── Type Helpers ───────────────────────────────────────────────────────────

/// Convert a `syn::Type` to its string representation.
pub fn type_to_string(ty: &syn::Type) -> String {
    ty.to_token_stream().to_string()
}

// ─── Line Number Helpers ────────────────────────────────────────────────────

/// Get the approximate line number of a field in the source content.
pub fn span_start_line(content: &str, field: &syn::Field) -> usize {
    // Use the field name identifier's span if available
    if let Some(ref ident) = field.ident {
        let field_name = ident.to_string();
        // Search for the field declaration pattern
        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.contains(&format!("pub {}", field_name))
                || trimmed.contains(&format!("{}: ", field_name))
                || trimmed.contains(&format!("{}:", field_name))
            {
                return idx + 1;
            }
        }
    }
    1
}

/// Get the line number of a struct declaration.
pub fn struct_line(content: &str, s: &syn::ItemStruct) -> usize {
    let struct_name = s.ident.to_string();
    for (idx, line) in content.lines().enumerate() {
        if line.contains(&format!("struct {}", struct_name)) {
            return idx + 1;
        }
    }
    1
}

/// Get the approximate line number of an expression.
pub fn expr_line(content: &str, _expr: &syn::Expr) -> usize {
    // For expressions, we use the token stream to find the closest match
    let expr_str = _expr.to_token_stream().to_string();
    // Take the first meaningful token for matching
    let first_tokens: String = expr_str.chars().take(30).collect();

    if first_tokens.len() > 5 {
        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            // Normalize whitespace for comparison
            let normalized_line = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
            let normalized_expr = first_tokens
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            if normalized_line.contains(&normalized_expr) {
                return idx + 1;
            }
        }
    }
    1
}

// ─── Source Snippets ────────────────────────────────────────────────────────

/// Extract a 3-line snippet around the given line number.
pub fn extract_snippet(content: &str, line_number: usize) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    if line_number == 0 || line_number > lines.len() {
        return None;
    }

    let start = line_number.saturating_sub(2);
    let end = (line_number + 1).min(lines.len());

    let snippet: String = lines[start..end]
        .iter()
        .enumerate()
        .map(|(i, l)| format!("{}: {}", start + i + 1, l))
        .collect::<Vec<_>>()
        .join("\n");

    Some(snippet)
}

// ─── Naming Conventions ─────────────────────────────────────────────────────

/// Infer the instruction name from an Anchor accounts struct name.
///
/// Convention: `WithdrawAccounts` → `withdraw`, `InitializeVault` → `initialize_vault`.
pub fn infer_instruction_name(struct_name: &str) -> String {
    let name = struct_name
        .trim_end_matches("Accounts")
        .trim_end_matches("Context")
        .trim_end_matches("Ctx");

    if name.is_empty() {
        return struct_name.to_lowercase();
    }

    // Convert CamelCase to snake_case
    let mut result = String::new();
    for (i, ch) in name.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            result.push('_');
        }
        result.push(ch.to_ascii_lowercase());
    }

    result
}

// ─── Fingerprinting ─────────────────────────────────────────────────────────

/// Generate a deterministic finding ID like `SEC3-A1B2C3D4`.
pub fn generate_finding_id(
    prefix: &str,
    category: &Sec3Category,
    file: &str,
    line: usize,
) -> String {
    let fp = fingerprint(category, file, line, "");
    format!("{}-{}", prefix, &fp[..8].to_uppercase())
}

/// Generate a SHA-256 fingerprint for deduplication.
pub fn fingerprint(category: &Sec3Category, file: &str, line: usize, instruction: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{:?}:{}:{}:{}", category, file, line, instruction));
    hex::encode(hasher.finalize())
}
