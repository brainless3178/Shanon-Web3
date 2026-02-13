//! **Integer Safety Analyzer** — detects unchecked arithmetic operations
//! in Solana program instruction handlers.
//!
//! Solana programs compiled in release mode have overflow checks **disabled**
//! by default (unlike standard Rust). Unchecked arithmetic on token amounts,
//! balances, or timestamps can lead to minting infinite tokens or draining
//! vaults.
//!
//! Detection strategy:
//! 1. Parse all function bodies inside `impl` blocks.
//! 2. Flag binary expressions (`+`, `-`, `*`, `/`, `%`, `<<`, `>>`) on
//!    integer-typed variables that are NOT wrapped in `.checked_*()`,
//!    `.saturating_*()`, or `overflow-checks = true` in Cargo.toml.
//! 3. Report the instruction context and exact expression location.

use crate::report::{Sec3Category, Sec3Finding, Sec3Severity};
use crate::utils;
use std::path::Path;

/// Scan for unchecked arithmetic in instruction handler bodies.
pub fn scan(program_path: &Path) -> Vec<Sec3Finding> {
    let mut findings = Vec::new();
    let has_overflow_flag = check_cargo_overflow_checks(program_path);

    for (file_path, content) in utils::collect_rust_sources(program_path) {
        scan_file(&file_path, &content, has_overflow_flag, &mut findings);
    }

    findings
}

/// Check if Cargo.toml has overflow-checks = true in [profile.release].
fn check_cargo_overflow_checks(program_path: &Path) -> bool {
    let cargo_path = program_path.join("Cargo.toml");
    if let Ok(content) = std::fs::read_to_string(cargo_path) {
        // Simple but effective: check if overflow-checks = true appears
        // after [profile.release]
        let lower = content.to_lowercase();
        if let Some(release_pos) = lower.find("[profile.release]") {
            let after_release = &lower[release_pos..];
            return after_release.contains("overflow-checks = true")
                || after_release.contains("overflow-checks=true");
        }
    }
    false
}

fn scan_file(
    file_path: &str,
    content: &str,
    has_overflow_flag: bool,
    findings: &mut Vec<Sec3Finding>,
) {
    let syntax = match syn::parse_file(content) {
        Ok(f) => f,
        Err(_) => return,
    };

    // Gather function names that look like Anchor instruction handlers
    for item in &syntax.items {
        match item {
            syn::Item::Fn(func) => {
                let fn_name = func.sig.ident.to_string();
                scan_function_body(
                    file_path,
                    content,
                    &fn_name,
                    &func.block,
                    has_overflow_flag,
                    findings,
                );
            }
            syn::Item::Impl(imp) => {
                for impl_item in &imp.items {
                    if let syn::ImplItem::Fn(method) = impl_item {
                        let fn_name = method.sig.ident.to_string();
                        scan_function_body(
                            file_path,
                            content,
                            &fn_name,
                            &method.block,
                            has_overflow_flag,
                            findings,
                        );
                    }
                }
            }
            syn::Item::Mod(module) => {
                if let Some((_, ref items)) = module.content {
                    for sub_item in items {
                        if let syn::Item::Fn(func) = sub_item {
                            let fn_name = func.sig.ident.to_string();
                            scan_function_body(
                                file_path,
                                content,
                                &fn_name,
                                &func.block,
                                has_overflow_flag,
                                findings,
                            );
                        }
                        if let syn::Item::Impl(imp) = sub_item {
                            for impl_item in &imp.items {
                                if let syn::ImplItem::Fn(method) = impl_item {
                                    let fn_name = method.sig.ident.to_string();
                                    scan_function_body(
                                        file_path,
                                        content,
                                        &fn_name,
                                        &method.block,
                                        has_overflow_flag,
                                        findings,
                                    );
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn scan_function_body(
    file_path: &str,
    content: &str,
    fn_name: &str,
    block: &syn::Block,
    has_overflow_flag: bool,
    findings: &mut Vec<Sec3Finding>,
) {
    // Walk each statement looking for arithmetic binary expressions
    for stmt in &block.stmts {
        scan_stmt_for_arithmetic(
            file_path,
            content,
            fn_name,
            stmt,
            has_overflow_flag,
            findings,
        );
    }
}

fn scan_stmt_for_arithmetic(
    file_path: &str,
    content: &str,
    fn_name: &str,
    stmt: &syn::Stmt,
    has_overflow_flag: bool,
    findings: &mut Vec<Sec3Finding>,
) {
    match stmt {
        syn::Stmt::Expr(expr, _) => {
            scan_expr_for_arithmetic(
                file_path,
                content,
                fn_name,
                expr,
                has_overflow_flag,
                findings,
            );
        }
        syn::Stmt::Local(local) => {
            if let Some(ref init) = local.init {
                scan_expr_for_arithmetic(
                    file_path,
                    content,
                    fn_name,
                    &init.expr,
                    has_overflow_flag,
                    findings,
                );
            }
        }
        _ => {}
    }
}

fn scan_expr_for_arithmetic(
    file_path: &str,
    content: &str,
    fn_name: &str,
    expr: &syn::Expr,
    has_overflow_flag: bool,
    findings: &mut Vec<Sec3Finding>,
) {
    match expr {
        syn::Expr::Binary(bin) => {
            let op_str = match bin.op {
                syn::BinOp::Add(_) => Some("+"),
                syn::BinOp::Sub(_) => Some("-"),
                syn::BinOp::Mul(_) => Some("*"),
                syn::BinOp::Div(_) => Some("/"),
                syn::BinOp::Rem(_) => Some("%"),
                syn::BinOp::Shl(_) => Some("<<"),
                syn::BinOp::Shr(_) => Some(">>"),
                _ => None,
            };

            if let Some(op) = op_str {
                let line = utils::expr_line(content, expr);
                let snippet = utils::extract_snippet(content, line);

                // Check if this line already uses checked/saturating variants
                if let Some(ref snip) = snippet {
                    let lower = snip.to_lowercase();
                    if lower.contains("checked_")
                        || lower.contains("saturating_")
                        || lower.contains(".try_into()")
                        || lower.contains("wrapping_")
                    {
                        // Already safe
                        return;
                    }
                }

                let severity = if has_overflow_flag {
                    // overflow-checks=true mitigates to medium — still panics instead of returning Err
                    Sec3Severity::Medium
                } else {
                    match op {
                        "+" | "-" | "*" => Sec3Severity::Critical,
                        "/" | "%" => Sec3Severity::High, // division by zero
                        "<<" | ">>" => Sec3Severity::High,
                        _ => Sec3Severity::Medium,
                    }
                };

                let checked_method = match op {
                    "+" => "checked_add",
                    "-" => "checked_sub",
                    "*" => "checked_mul",
                    "/" => "checked_div",
                    "%" => "checked_rem",
                    "<<" => "checked_shl",
                    ">>" => "checked_shr",
                    _ => "checked_op",
                };

                findings.push(Sec3Finding {
                    id: utils::generate_finding_id("SEC3", &Sec3Category::IntegerOverflow, file_path, line),
                    category: Sec3Category::IntegerOverflow,
                    severity,
                    file_path: file_path.to_string(),
                    line_number: line,
                    instruction: fn_name.to_string(),
                    account_name: None,
                    description: format!(
                        "Unchecked arithmetic operator `{}` in function '{}' — Solana release \
                         builds disable overflow checks by default. An attacker supplying \
                         boundary values (u64::MAX, 0) can trigger silent wraparound, \
                         inflating token balances or draining vaults.{}",
                        op, fn_name,
                        if has_overflow_flag {
                            " Note: overflow-checks=true is set, but this causes an unrecoverable \
                             panic rather than a graceful error return."
                        } else { "" },
                    ),
                    fix_recommendation: format!(
                        "Replace `a {} b` with `a.{}(b).ok_or(ErrorCode::MathOverflow)?` \
                         to propagate a recoverable error instead of panicking or silently wrapping.",
                        op, checked_method,
                    ),
                    cwe: Sec3Category::IntegerOverflow.cwe().to_string(),
                    fingerprint: utils::fingerprint(&Sec3Category::IntegerOverflow, file_path, line, fn_name),
                    source_snippet: snippet,
                    fix_diff: None,
                });
            }

            // Recurse into sub-expressions
            scan_expr_for_arithmetic(
                file_path,
                content,
                fn_name,
                &bin.left,
                has_overflow_flag,
                findings,
            );
            scan_expr_for_arithmetic(
                file_path,
                content,
                fn_name,
                &bin.right,
                has_overflow_flag,
                findings,
            );
        }
        syn::Expr::Assign(assign) => {
            scan_expr_for_arithmetic(
                file_path,
                content,
                fn_name,
                &assign.right,
                has_overflow_flag,
                findings,
            );
        }
        syn::Expr::Block(block) => {
            for stmt in &block.block.stmts {
                scan_stmt_for_arithmetic(
                    file_path,
                    content,
                    fn_name,
                    stmt,
                    has_overflow_flag,
                    findings,
                );
            }
        }
        syn::Expr::If(if_expr) => {
            scan_expr_for_arithmetic(
                file_path,
                content,
                fn_name,
                &if_expr.cond,
                has_overflow_flag,
                findings,
            );
            for stmt in &if_expr.then_branch.stmts {
                scan_stmt_for_arithmetic(
                    file_path,
                    content,
                    fn_name,
                    stmt,
                    has_overflow_flag,
                    findings,
                );
            }
            if let Some((_, else_branch)) = &if_expr.else_branch {
                scan_expr_for_arithmetic(
                    file_path,
                    content,
                    fn_name,
                    else_branch,
                    has_overflow_flag,
                    findings,
                );
            }
        }
        syn::Expr::Paren(p) => {
            scan_expr_for_arithmetic(
                file_path,
                content,
                fn_name,
                &p.expr,
                has_overflow_flag,
                findings,
            );
        }
        syn::Expr::Return(r) => {
            if let Some(ref expr) = r.expr {
                scan_expr_for_arithmetic(
                    file_path,
                    content,
                    fn_name,
                    expr,
                    has_overflow_flag,
                    findings,
                );
            }
        }
        _ => {}
    }
}
