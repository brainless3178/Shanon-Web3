//! Token-2022 Transfer Hook Analyzer
//!
//! Validates SPL Token-2022 transfer hook implementations.
//! Transfer hooks allow programs to execute custom logic during token transfers,
//! but incorrect implementation creates security vulnerabilities:
//! - Missing validation of the hook program ID in the mint
//! - Incorrect ExtraAccountMeta list derivation
//! - Missing signer checks on hook authority
//! - Unbounded compute in hook handler (exceeding CU limits)

use crate::metrics::AnchorMetrics;
use crate::report::{AnchorFinding, AnchorSeverity, AnchorViolation};
use sha2::{Digest, Sha256};
use syn::visit::Visit;

pub struct TokenHookAnalyzer;

impl TokenHookAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze_hooks(
        &self,
        file_path: &str,
        syntax_tree: &syn::File,
        content: &str,
        metrics: &mut AnchorMetrics,
    ) -> Vec<AnchorFinding> {
        let mut visitor = HookVisitor {
            file_path: file_path.to_string(),
            content: content.to_string(),
            findings: Vec::new(),
            metrics,
            has_transfer_hook_impl: false,
            has_extra_account_meta: false,
            has_hook_authority_check: false,
        };

        visitor.visit_file(syntax_tree);

        // After AST walk, do a content-level scan for patterns
        visitor.check_hook_patterns();

        visitor.findings
    }
}

impl Default for TokenHookAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

struct HookVisitor<'a> {
    file_path: String,
    content: String,
    findings: Vec<AnchorFinding>,
    metrics: &'a mut AnchorMetrics,
    has_transfer_hook_impl: bool,
    has_extra_account_meta: bool,
    has_hook_authority_check: bool,
}

impl<'ast> Visit<'ast> for HookVisitor<'_> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let fn_name = node.sig.ident.to_string();

        // Detect transfer hook handler functions
        if fn_name.contains("transfer_hook")
            || fn_name.contains("execute")
            || fn_name.contains("on_transfer")
        {
            // Check if this file also has TransferHook-related imports/types
            if self.content.contains("TransferHook") || self.content.contains("transfer_hook") {
                self.has_transfer_hook_impl = true;
                self.metrics.token_hook_implementations += 1;
            }
        }

        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        let struct_name = node.ident.to_string();

        // Check if this is an Accounts struct for a transfer hook
        let is_accounts_struct = node.attrs.iter().any(|attr| {
            attr.path().is_ident("derive") && {
                let attr_str = quote::quote!(#attr).to_string();
                attr_str.contains("Accounts")
            }
        });

        if is_accounts_struct
            && (struct_name.contains("TransferHook")
                || struct_name.contains("Hook")
                || struct_name.contains("Execute"))
        {
            // Check fields for ExtraAccountMeta and authority patterns
            for field in &node.fields {
                let field_name = match &field.ident {
                    Some(ident) => ident.to_string(),
                    None => continue,
                };

                let type_str = quote::quote!(#field.ty).to_string();
                let attr_str: String = field
                    .attrs
                    .iter()
                    .filter(|a| a.path().is_ident("account"))
                    .map(|a| quote::quote!(#a).to_string())
                    .collect::<Vec<_>>()
                    .join(" ");

                if field_name.contains("extra_account_meta") || type_str.contains("ExtraAccountMeta")
                {
                    self.has_extra_account_meta = true;
                }

                if (field_name.contains("authority") || field_name.contains("hook_authority"))
                    && (attr_str.contains("signer") || type_str.contains("Signer"))
                {
                    self.has_hook_authority_check = true;
                }
            }
        }

        syn::visit::visit_item_struct(self, node);
    }
}

impl HookVisitor<'_> {
    fn check_hook_patterns(&mut self) {
        // Only run these checks if the file has transfer hook related code
        let has_hook_code = self.content.contains("TransferHook")
            || self.content.contains("transfer_hook")
            || self.content.contains("spl_transfer_hook");

        if !has_hook_code {
            return;
        }

        self.has_transfer_hook_impl = true;

        // Check 1: Hook implementation without ExtraAccountMeta validation
        if self.has_transfer_hook_impl && !self.has_extra_account_meta {
            let line = self.find_line("TransferHook").unwrap_or(1);
            self.findings.push(AnchorFinding {
                id: format!(
                    "ANC-HookMeta-{}",
                    &self.fingerprint(line, "hook_meta")[..8]
                ),
                violation: AnchorViolation::InvalidTokenHook,
                severity: AnchorSeverity::High,
                file_path: self.file_path.clone(),
                line_number: line,
                struct_name: None,
                field_name: None,
                description: format!(
                    "Transfer hook implementation at line {} does not validate `ExtraAccountMetaList`. \
                     Token-2022 transfer hooks receive additional accounts via the `ExtraAccountMeta` \
                     PDA. Without validating this list, the hook cannot verify that the correct accounts \
                     were passed, allowing an attacker to substitute accounts during the transfer CPI.",
                    line,
                ),
                code_snippet: self.snippet_around(line, 2),
                risk_explanation:
                    "Transfer hooks are invoked by the Token-2022 program during transfers. The hook \
                     receives accounts from the `ExtraAccountMetaList` PDA, which is derived from the \
                     mint address. Without validation, the hook operates on attacker-controlled accounts."
                        .into(),
                fix_recommendation:
                    "Add ExtraAccountMeta validation:\n\
                     ```rust\n\
                     #[account(\n\
                         seeds = [b\"extra-account-metas\", mint.key().as_ref()],\n\
                         bump,\n\
                     )]\n\
                     pub extra_account_meta_list: AccountInfo<'info>,\n\
                     ```"
                        .into(),
                anchor_pattern: "ExtraAccountMeta validation".into(),
                cwe: "CWE-20".into(),
                fingerprint: self.fingerprint(line, "hook_meta"),
            });
        }

        // Check 2: Hook handler without authority check
        if self.has_transfer_hook_impl && !self.has_hook_authority_check {
            // This is informational -- not all hooks need an authority check
            // Only flag if the hook has state mutations
            let has_mutations = self.content.contains("ctx.accounts")
                && (self.content.contains(".amount") || self.content.contains(".balance")
                    || self.content.contains("transfer") || self.content.contains("mint_to"));

            if has_mutations {
                let line = self.find_line("transfer_hook").unwrap_or(1);
                self.findings.push(AnchorFinding {
                    id: format!(
                        "ANC-HookAuth-{}",
                        &self.fingerprint(line, "hook_auth")[..8]
                    ),
                    violation: AnchorViolation::InvalidTokenHook,
                    severity: AnchorSeverity::Medium,
                    file_path: self.file_path.clone(),
                    line_number: line,
                    struct_name: None,
                    field_name: None,
                    description: format!(
                        "Transfer hook at line {} mutates state but does not check a hook authority. \
                         If the hook updates balances, mints tokens, or modifies pool state, it should \
                         verify that the caller is the authorized token program and mint.",
                        line,
                    ),
                    code_snippet: self.snippet_around(line, 2),
                    risk_explanation:
                        "Transfer hooks that mutate state without authority checks can be invoked \
                         by any program via CPI, potentially allowing unauthorized state changes."
                            .into(),
                    fix_recommendation:
                        "Verify the CPI caller is the Token-2022 program:\n\
                         ```rust\n\
                         require!(\n\
                             ctx.accounts.token_program.key() == spl_token_2022::ID,\n\
                             ErrorCode::InvalidProgram\n\
                         );\n\
                         ```"
                            .into(),
                    anchor_pattern: "Transfer hook authority validation".into(),
                    cwe: "CWE-862".into(),
                    fingerprint: self.fingerprint(line, "hook_auth"),
                });
            }
        }

        // Check 3: Detect compute-heavy operations in hook handlers
        for (i, line) in self.content.lines().enumerate() {
            // Look for unbounded loops or heavy compute within hook functions
            if (line.contains("for ") || line.contains("while ") || line.contains("loop"))
                && self.is_within_hook_function(i)
            {
                self.findings.push(AnchorFinding {
                    id: format!(
                        "ANC-HookCU-{}",
                        &self.fingerprint(i + 1, "hook_cu")[..8]
                    ),
                    violation: AnchorViolation::InvalidTokenHook,
                    severity: AnchorSeverity::Medium,
                    file_path: self.file_path.clone(),
                    line_number: i + 1,
                    struct_name: None,
                    field_name: None,
                    description: format!(
                        "Line {}: Loop detected inside transfer hook handler. Transfer hooks share \
                         the compute budget of the parent transfer instruction (~200,000 CU by default). \
                         Unbounded loops can cause the hook to exceed the budget, failing ALL transfers \
                         for this token. Use bounded iteration or precomputed values.",
                        i + 1,
                    ),
                    code_snippet: self.snippet_around(i + 1, 2),
                    risk_explanation:
                        "Transfer hooks execute within the caller's compute budget. An expensive hook \
                         makes the token un-transferable if it exceeds the budget. This is a denial-of- \
                         service vector against all token holders."
                            .into(),
                    fix_recommendation:
                        "Use bounded iteration or precompute values off-chain:\n\
                         ```rust\n\
                         // Bad: unbounded\n\
                         for item in collection.iter() { ... }\n\
                         // Good: bounded\n\
                         for item in collection.iter().take(MAX_ITEMS) { ... }\n\
                         ```"
                            .into(),
                    anchor_pattern: "Transfer hook compute budget".into(),
                    cwe: "CWE-400".into(),
                    fingerprint: self.fingerprint(i + 1, "hook_cu"),
                });
                break; // Report once per file, not per loop
            }
        }
    }

    fn is_within_hook_function(&self, target_line: usize) -> bool {
        // Walk backwards from target_line to find if we're inside a hook function
        let lines: Vec<&str> = self.content.lines().collect();
        let mut brace_depth: i32 = 0;

        for i in (0..target_line).rev() {
            let line = lines[i];
            brace_depth += line.matches('}').count() as i32;
            brace_depth -= line.matches('{').count() as i32;

            if brace_depth <= 0
                && (line.contains("fn transfer_hook")
                    || line.contains("fn execute")
                    || line.contains("fn on_transfer"))
            {
                return true;
            }
        }
        false
    }

    fn find_line(&self, needle: &str) -> Option<usize> {
        self.content
            .lines()
            .enumerate()
            .find(|(_, l)| l.contains(needle))
            .map(|(i, _)| i + 1)
    }

    fn snippet_around(&self, line: usize, context: usize) -> String {
        let lines: Vec<&str> = self.content.lines().collect();
        let start = line.saturating_sub(context + 1);
        let end = (line + context).min(lines.len());
        lines[start..end]
            .iter()
            .enumerate()
            .map(|(i, l)| format!("{}: {}", start + i + 1, l))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn fingerprint(&self, line: usize, tag: &str) -> String {
        let mut h = Sha256::new();
        h.update(self.file_path.as_bytes());
        h.update(line.to_string().as_bytes());
        h.update(tag.as_bytes());
        hex::encode(h.finalize())
    }
}
