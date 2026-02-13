use colored::Colorize;
use program_analyzer::ProgramAnalyzer;
use std::fs;
use std::path::Path;
use std::time::Instant;

use orchestrator::terminal_ui::{
    print_banner, print_section_footer, print_section_header, print_statistics, print_verdict,
    ProgressBar, Theme,
};

fn main() -> anyhow::Result<()> {
    let scan_start = Instant::now();

    // Print beautiful banner
    print_banner();

    let targets_dir = Path::new("test_targets/sealevel-attacks/programs");

    print_section_header("Sealevel-Attacks Testing Suite");
    println!(
        "  │ {} Target: {}",
        Theme::bullet(),
        "sealevel-attacks (Coral/Anchor)".bright_yellow()
    );
    println!(
        "  │ {} Programs: {}",
        Theme::bullet(),
        "11 intentionally vulnerable Solana programs".bright_cyan()
    );
    print_section_footer();
    println!();

    let mut total_findings = 0;
    let mut programs_tested = 0;
    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;

    // Count total programs for progress bar
    let mut vuln_dirs = Vec::new();
    if targets_dir.exists() {
        for entry in fs::read_dir(targets_dir)? {
            let entry = entry?;
            let vuln_path = entry.path();
            if vuln_path.is_dir() && vuln_path.join("insecure/src").exists() {
                vuln_dirs.push(vuln_path);
            }
        }
    }

    let mut progress = ProgressBar::new(vuln_dirs.len().max(1), "Scanning programs");

    // Iterate through each vulnerability category
    for vuln_path in &vuln_dirs {
        let vuln_name = vuln_path.file_name().unwrap().to_string_lossy();
        let insecure_src = vuln_path.join("insecure/src");

        println!();
        println!(
            "  {} {} {}",
            "🔍".normal(),
            "Analyzing:".bright_white(),
            vuln_name.bright_yellow().bold()
        );
        println!("  {}", "─".repeat(50).bright_black());

        // Analyze each .rs file
        for rs_entry in fs::read_dir(&insecure_src)? {
            let rs_entry = rs_entry?;
            let rs_path = rs_entry.path();

            if rs_path.extension().is_some_and(|ext| ext == "rs") {
                let source = fs::read_to_string(&rs_path)?;
                let filename = rs_path.file_name().unwrap().to_string_lossy();

                // Create analyzer from source
                match ProgramAnalyzer::from_source(&source) {
                    Ok(analyzer) => {
                        let findings = analyzer.scan_for_vulnerabilities();

                        if findings.is_empty() {
                            println!(
                                "  {} {}",
                                Theme::warning(),
                                format!(
                                    "No vulnerabilities detected in {} (possible false negative)",
                                    filename
                                )
                                .yellow()
                            );
                        } else {
                            for finding in &findings {
                                // Show compact vulnerability line
                                let severity_badge = match finding.severity {
                                    5 => " CRITICAL ".on_red().white().bold(),
                                    4 => "   HIGH   ".on_yellow().black().bold(),
                                    3 => "  MEDIUM  ".on_blue().white().bold(),
                                    2 => "   LOW    ".on_bright_black().white(),
                                    _ => "   INFO   ".on_bright_black().white(),
                                };

                                println!(
                                    "  {} {} {} {}",
                                    Theme::success(),
                                    severity_badge,
                                    finding.id.bright_cyan(),
                                    finding.vuln_type.bright_white()
                                );

                                // Count by severity
                                match finding.severity {
                                    5 => critical_count += 1,
                                    4 => high_count += 1,
                                    3 => medium_count += 1,
                                    2 => low_count += 1,
                                    _ => {}
                                }

                                total_findings += 1;
                            }
                        }

                        programs_tested += 1;
                    }
                    Err(e) => {
                        println!(
                            "  {} Parse error in {}: {}",
                            Theme::warning(),
                            filename.bright_yellow(),
                            e.to_string().bright_black()
                        );
                    }
                }
            }
        }
        progress.increment();
    }
    progress.finish();

    // Test Raydium AMM (real production code)
    println!();
    print_section_header("Raydium AMM (Production Code)");

    let raydium_src = Path::new("test_targets/raydium-amm/program/src");
    if raydium_src.exists() {
        let mut raydium_files = Vec::new();
        for rs_entry in fs::read_dir(raydium_src)? {
            let rs_entry = rs_entry?;
            let rs_path = rs_entry.path();
            if rs_path.extension().is_some_and(|ext| ext == "rs") {
                raydium_files.push(rs_path);
            }
        }

        let mut ray_progress = ProgressBar::new(raydium_files.len().max(1), "Scanning Raydium");

        for rs_path in raydium_files {
            let filename = rs_path.file_name().unwrap().to_string_lossy();
            let source = fs::read_to_string(&rs_path)?;

            match ProgramAnalyzer::from_source(&source) {
                Ok(analyzer) => {
                    let findings = analyzer.scan_for_vulnerabilities();

                    if !findings.is_empty() {
                        for finding in &findings {
                            let severity_badge = match finding.severity {
                                5 => " CRITICAL ".on_red().white().bold(),
                                4 => "   HIGH   ".on_yellow().black().bold(),
                                3 => "  MEDIUM  ".on_blue().white().bold(),
                                2 => "   LOW    ".on_bright_black().white(),
                                _ => "   INFO   ".on_bright_black().white(),
                            };

                            println!(
                                "  {} {} {} in {}",
                                "⚠".yellow().bold(),
                                severity_badge,
                                finding.vuln_type.bright_white(),
                                filename.bright_cyan()
                            );

                            match finding.severity {
                                5 => critical_count += 1,
                                4 => high_count += 1,
                                3 => medium_count += 1,
                                2 => low_count += 1,
                                _ => {}
                            }

                            total_findings += 1;
                        }
                    }

                    programs_tested += 1;
                }
                Err(_) => {
                    // Silently skip parse errors in production code
                }
            }
            ray_progress.increment();
        }
        ray_progress.finish();
    } else {
        println!(
            "  {} Raydium AMM not found at {}",
            Theme::warning(),
            raydium_src.display().to_string().yellow()
        );
    }

    print_section_footer();

    // Final statistics
    let scan_duration = scan_start.elapsed();

    print_statistics(
        programs_tested,
        total_findings,
        critical_count,
        high_count,
        medium_count,
        low_count,
        scan_duration,
    );

    print_verdict(critical_count, high_count, medium_count);

    // Success message
    println!();
    println!(
        "  {} Scan complete! Tested {} programs in {:.2}s",
        Theme::success(),
        programs_tested,
        scan_duration.as_secs_f64()
    );
    println!();

    Ok(())
}
