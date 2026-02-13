use colored::Colorize;
use program_analyzer::ProgramAnalyzer;
use std::fs;
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let cctp_dir = Path::new("test_targets/solana-cctp-contracts/programs");

    println!("{}", "=".repeat(70).bright_cyan());
    println!(
        "{}",
        "  CIRCLE CCTP CONTRACTS - SECURITY AUDIT"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        "  Cross-Chain Transfer Protocol (Production Code)".bright_cyan()
    );
    println!("{}", "=".repeat(70).bright_cyan());
    println!();

    let mut total_findings = 0;
    let mut files_scanned = 0;
    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;

    // Scan all .rs files recursively
    for entry in walkdir::WalkDir::new(cctp_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "rs"))
    {
        let rs_path = entry.path();
        let relative_path = rs_path.strip_prefix(cctp_dir).unwrap_or(rs_path);

        let source = match fs::read_to_string(rs_path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        match ProgramAnalyzer::from_source(&source) {
            Ok(analyzer) => {
                let findings = analyzer.scan_for_vulnerabilities();

                if !findings.is_empty() {
                    println!(
                        "{}",
                        format!("📄 {}", relative_path.display())
                            .bright_white()
                            .bold()
                    );

                    for finding in &findings {
                        let (severity_label, icon) = match finding.severity {
                            5 => {
                                critical_count += 1;
                                ("CRITICAL".bright_red().bold(), "🔴")
                            }
                            4 => {
                                high_count += 1;
                                ("HIGH".red().bold(), "🟠")
                            }
                            3 => {
                                medium_count += 1;
                                ("MEDIUM".yellow().bold(), "🟡")
                            }
                            2 => ("LOW".blue().bold(), "🔵"),
                            _ => ("INFO".white().bold(), "⚪"),
                        };

                        println!(
                            "   {} [{}] {}",
                            icon,
                            severity_label,
                            finding.vuln_type.bright_white()
                        );
                        println!("      └─ {}", finding.description.dimmed());

                        if !finding.attack_scenario.is_empty() {
                            println!("      └─ Attack: {}", finding.attack_scenario.dimmed());
                        }

                        total_findings += 1;
                    }
                    println!();
                }

                files_scanned += 1;
            }
            Err(_) => {
                // Skip files that don't parse (macros, etc.)
            }
        }
    }

    println!("{}", "=".repeat(70).bright_green());
    println!("{}", "  AUDIT COMPLETE".bright_green().bold());
    println!("{}", "=".repeat(70).bright_green());
    println!();
    println!("📊 Summary:");
    println!(
        "   Files Scanned:    {}",
        files_scanned.to_string().bright_white()
    );
    println!(
        "   Total Findings:   {}",
        total_findings.to_string().bright_red().bold()
    );
    println!();
    println!(
        "   🔴 Critical:      {}",
        critical_count.to_string().bright_red()
    );
    println!("   🟠 High:          {}", high_count.to_string().red());
    println!("   🟡 Medium:        {}", medium_count.to_string().yellow());
    println!();

    if total_findings == 0 {
        println!(
            "{}",
            "✅ No vulnerabilities detected!".bright_green().bold()
        );
    } else {
        println!(
            "{}",
            "⚠️  Review findings above for potential issues.".yellow()
        );
    }

    Ok(())
}
