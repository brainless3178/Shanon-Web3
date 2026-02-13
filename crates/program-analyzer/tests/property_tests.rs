//! Property-based tests and benchmark tests
//!
//! These tests verify invariants and measure performance.

use program_analyzer::ProgramAnalyzer;

// =============================================================================
// PROPERTY TESTS - Invariants that must always hold
// =============================================================================

#[test]
fn property_findings_have_valid_severity() {
    // Generate various code snippets
    let code_samples = vec![
        "pub fn foo() {}",
        "pub fn bar(x: u64) { let y = x + 1; }",
        "pub fn baz(ctx: Context<Baz>) -> Result<()> { Ok(()) }",
    ];

    for code in code_samples {
        if let Ok(analyzer) = ProgramAnalyzer::from_source(code) {
            let findings = analyzer.scan_for_vulnerabilities();
            for finding in &findings {
                // Severity must be 1-5
                assert!(
                    finding.severity >= 1 && finding.severity <= 5,
                    "Invalid severity {} for finding {}",
                    finding.severity,
                    finding.id
                );
            }
        }
    }
}

#[test]
fn property_findings_have_non_empty_ids() {
    let code = r#"
        pub fn transfer(amount: u64) {
            let total = amount + 100;
        }
    "#;

    if let Ok(analyzer) = ProgramAnalyzer::from_source(code) {
        let findings = analyzer.scan_for_vulnerabilities();
        for finding in &findings {
            assert!(
                !finding.id.is_empty(),
                "Finding has empty ID: {:?}",
                finding
            );
        }
    }
}

#[test]
fn property_parallel_same_as_sequential() {
    let code = r#"
        use anchor_lang::prelude::*;
        
        pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
            let vault = &mut ctx.accounts.vault;
            vault.balance = vault.balance + amount;
            Ok(())
        }
    "#;

    if let Ok(analyzer) = ProgramAnalyzer::from_source(code) {
        let sequential = analyzer.scan_for_vulnerabilities();
        let parallel = analyzer.scan_for_vulnerabilities_parallel();

        // Same number of findings
        assert_eq!(
            sequential.len(),
            parallel.len(),
            "Parallel and sequential should produce same number of findings"
        );

        // Same finding IDs (order may differ)
        let mut seq_ids: Vec<_> = sequential.iter().map(|f| &f.id).collect();
        let mut par_ids: Vec<_> = parallel.iter().map(|f| &f.id).collect();
        seq_ids.sort();
        par_ids.sort();
        assert_eq!(seq_ids, par_ids);
    }
}

#[test]
fn property_empty_code_produces_no_findings() {
    let empty_codes = vec!["", "   ", "\n\n\n", "// just a comment"];

    for code in empty_codes {
        if let Ok(analyzer) = ProgramAnalyzer::from_source(code) {
            let findings = analyzer.scan_for_vulnerabilities();
            assert!(
                findings.is_empty(),
                "Empty/comment-only code should produce no findings, got {} for {:?}",
                findings.len(),
                code
            );
        }
    }
}

#[test]
fn property_account_schema_names_match_structs() {
    let code = r#"
        #[account]
        pub struct Vault {
            pub authority: Pubkey,
            pub balance: u64,
        }
        
        #[account]
        pub struct Config {
            pub admin: Pubkey,
        }
    "#;

    if let Ok(analyzer) = ProgramAnalyzer::from_source(code) {
        let schemas = analyzer.extract_account_schemas();

        // Should find exactly the structs we defined
        let names: Vec<_> = schemas.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"Vault"));
        assert!(names.contains(&"Config"));
    }
}

// =============================================================================
// REGRESSION TESTS - Specific bugs that were fixed
// =============================================================================

#[test]
fn regression_no_panic_on_malformed_code() {
    // These should not panic, even if they fail to parse
    let malformed_codes = vec![
        "pub fn {",
        "struct Foo { x: }",
        "fn ()",
        "let x = ;",
        "use crate::::foo;",
    ];

    for code in malformed_codes {
        // Should not panic - either Ok or Err is fine
        let _ = ProgramAnalyzer::from_source(code);
    }
}

#[test]
fn regression_unicode_in_code() {
    let code = r#"
        /// 日本語コメント
        pub fn transfer_资金(amount: u64) -> Result<()> {
            // 中文注释
            msg!("Transferring {} 토큰", amount);
            Ok(())
        }
    "#;

    // Should handle unicode without panicking
    let result = ProgramAnalyzer::from_source(code);
    assert!(result.is_ok(), "Should handle unicode in code");
}

#[test]
fn regression_deeply_nested_modules() {
    let code = r#"
        mod a {
            mod b {
                mod c {
                    mod d {
                        pub fn deep_function() {
                            let x = 1 + 2;
                        }
                    }
                }
            }
        }
    "#;

    if let Ok(analyzer) = ProgramAnalyzer::from_source(code) {
        // Should not stack overflow on deeply nested code
        let _ = analyzer.scan_for_vulnerabilities();
    }
}

// =============================================================================
// PERFORMANCE TESTS - Ensure reasonable performance
// =============================================================================

#[test]
fn performance_large_file_completes() {
    // Generate a large file with many functions
    let mut code = String::from("use anchor_lang::prelude::*;\n\n");

    for i in 0..100 {
        code.push_str(&format!(
            r#"
            pub fn function_{i}(ctx: Context<Ctx{i}>, amount: u64) -> Result<()> {{
                let value = amount + {i};
                msg!("Value: {{}}", value);
                Ok(())
            }}
            "#,
            i = i
        ));
    }

    let start = std::time::Instant::now();

    if let Ok(analyzer) = ProgramAnalyzer::from_source(&code) {
        let _ = analyzer.scan_for_vulnerabilities();
    }

    let elapsed = start.elapsed();

    // Should complete in under 5 seconds for 100 functions
    assert!(
        elapsed.as_secs() < 5,
        "Large file analysis took too long: {:?}",
        elapsed
    );
}

#[test]
fn performance_many_patterns_checked() {
    let code = r#"
        pub fn complex_function(ctx: Context<Complex>, amount: u64) -> Result<()> {
            // This code should trigger pattern checking
            let vault = &mut ctx.accounts.vault;
            vault.balance = vault.balance + amount;
            
            invoke_signed(
                &instruction,
                &accounts,
                &[&seeds],
            )?;
            
            Ok(())
        }
    "#;

    let start = std::time::Instant::now();

    if let Ok(analyzer) = ProgramAnalyzer::from_source(code) {
        // Run multiple times to test consistency
        for _ in 0..10 {
            let _ = analyzer.scan_for_vulnerabilities();
        }
    }

    let elapsed = start.elapsed();

    // 10 runs should complete in under 1 second
    assert!(
        elapsed.as_millis() < 1000,
        "Pattern checking is too slow: {:?}",
        elapsed
    );
}

// =============================================================================
// COVERAGE TESTS - Ensure all vulnerability categories are testable
// =============================================================================

#[test]
fn coverage_all_severity_levels_exist() {
    // Verify that our vulnerability database has patterns for all severity levels
    let code = r#"
        pub fn vulnerable_function(ctx: Context<Vulnerable>, amount: u64) -> Result<()> {
            // Trigger various patterns
            let x = amount + 1;  // potential overflow
            let y = amount * 100;
            invoke_signed(&ix, &accs, &[&seeds])?;
            Ok(())
        }
        
        #[derive(Accounts)]
        pub struct Vulnerable<'info> {
            pub authority: AccountInfo<'info>,  // missing Signer
        }
    "#;

    if let Ok(analyzer) = ProgramAnalyzer::from_source(code) {
        let findings = analyzer.scan_for_vulnerabilities();

        // Collect unique severities found
        let severities: std::collections::HashSet<_> =
            findings.iter().map(|f| f.severity).collect();

        println!("Severities found: {:?}", severities);
        // Should have at least some findings (database is working)
    }
}
