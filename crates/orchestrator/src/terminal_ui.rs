//! Terminal UI Module
//!
//! High-fidelity, transparent security reporting.
//! Includes exploit proofs, confidence reasoning, and financial risk context.

use colored::*;
use std::io::{self, Write};
use std::time::Instant;

/// Terminal UI styling constants
pub struct Theme;

impl Theme {
    pub fn critical() -> ColoredString {
        "[!]".bright_red().bold()
    }
    pub fn high() -> ColoredString {
        "[!]".yellow().bold()
    }
    pub fn medium() -> ColoredString {
        "[~]".blue()
    }
    pub fn low() -> ColoredString {
        "[.]".bright_black()
    }
    pub fn warning() -> ColoredString {
        "[W]".yellow().bold()
    }
    pub fn success() -> ColoredString {
        "[V]".bright_green().bold()
    }
    pub fn failure() -> ColoredString {
        "[X]".bright_red().bold()
    }
    pub fn arrow() -> ColoredString {
        ">>".bright_cyan()
    }
    pub fn bullet() -> ColoredString {
        "*".bright_white()
    }
    pub fn spinner_frames() -> &'static [&'static str] {
        &["|", "/", "-", "\\"]
    }
}

pub fn print_banner() {
    print_bug();

    println!("\n  {}", format!("+{}+", "─".repeat(78)).bright_black());
    println!("  |{:^78}|", "SOLANA SECURITY SWARM".bright_white().bold());
    println!(
        "  |{:^78}|",
        "AUTONOMOUS ON-CHAIN THREAT INTELLIGENCE & FORMAL ANALYSIS".bright_black()
    );
    println!("  {}\n", format!("+{}+", "─".repeat(78)).bright_black());

    print_badges();
    print_credits();
}

pub fn print_credits() {
    let credits = [
        r"   __  __     _     ____   _____ ",
        r"  |  \/  |   / \   |  _ \ | ____|",
        r"  | |\/| |  / _ \  | | | ||  _|  ",
        r"  | |  | | / ___ \ | |_| || |___ ",
        r"  |_|  |_|/_/   \_\|____/ |_____|",
        r"                                ",
        r"   ____ __   __  ____   ____  _  ___ _   _ ",
        r"  | __ )\ \ / / |___ \ |  _ \/ ||_ _| \ | |",
        r"  |  _ \ \ V /    __) || |_) | | | ||  \| |",
        r"  | |_) | | |    / __/ |  _ <| | | || |\  |",
        r"  |____/  |_|   |_____||_| \_|_||___|_| \_|",
    ];
    for line in credits {
        println!("{}", line.bright_cyan().bold());
    }
}

pub fn print_bug() {
    let bug = [
        r"                                          ▒░            ▒▒                                          ",
        r"                               ::.      @█▒@ ::.    .:. ░▒█#      .-:                               ",
        r"                               +@*+     %@===%@-    +@%+++░%    .=%@=                               ",
        r"                                 *&*+     &&&%*:    -*&&&%     +*&*                                 ",
        r"                                   █▒      .%░█#&&&&░█@&.      ▓▓                                   ",
        r"                                 *@+=     #@███░░██*#███@#     +*@*                                 ",
        r"                                 #█     %▒███@=░█+*▓@=░███▒%    :█#                                 ",
        r"                                 #█▒@.*▓███▒:%▓*:▒@:%▓██████▓*.░▓█#                                 ",
        r"                                    -▒▓██████▒+░█++▓█████████▓▒:                                    ",
        r"                                 -====&███████████▓+#█▓██████&====-                                 ",
        r"                        -***     @█##██████▓###░#▓▓#░█░#███████##█#    :***:                        ",
        r"                        =%%%%&&&&▒█ :██████▓&&%#&▓█&&%&&███████::█▒&&&&%%%%:                        ",
        r"                            +++++++ :████████& @████# #████████:.++++++=                            ",
        r"                                    :████████# @████# #████████:                                    ",
        r"                                 #▒▒▓████████# @████# #████████▓▒▒&                                 ",
        r"                               %█=  :████████@:░████@:@████████:  *█*                               ",
        r"                             .=%@-  :@▒██████████████████████▒@:  =@%=.                             ",
        r"                             -█%      *██████████████████████*      #█:                             ",
        r"                            %%%=    .&%%░██████████████████@%&&.    =%%*                            ",
        r"                          %@*=      :█% -+████████████████+- #█:      ++@%                          ",
        r"                          -=.       :█%   -=████████████=-   #█:       .=-                          ",
        r"                                    .:*▓=  ..%████████*..  *▓*:.                                    ",
        r"                                      *█+        @@        *█*                                      ",
        r"                                    .=*░=                  +░%=.                                    ",
        r"                                    :█%                      #█:                                    ",
        r"                                    .%=                      =%.                                    ",
    ];

    for line in bug {
        println!("{}", line.bright_red());
    }
    println!();
}

fn print_badges() {
    let badges = [
        ("F-VERIFY", "Formal Proof", "bright_red"),
        ("AI-CONSENSUS", "Multi-Pass", "bright_magenta"),
        ("TVR-SCALER", "Risk Analytics", "yellow"),
        ("ON-CHAIN", "Live Ledger", "bright_green"),
    ];
    print!("  ");
    for (tag, label, _) in badges {
        print!(
            "{} ",
            format!(" [{}:{}] ", tag, label)
                .on_bright_black()
                .bright_white()
                .bold()
        );
    }
    println!("\n");
}

pub fn print_config_pro(rpc: &str, models: &[(String, bool, String)]) {
    println!("  ╔══ System Configuration ═════════════════════════════════════════════╗");
    println!("  ║ • RPC Endpoint: {:<51} ║", rpc.bright_cyan());
    println!("  ╠══ Model Consensus Breakdown ════════════════════════════════════════╣");
    for (name, verified, reason) in models {
        let status = if *verified {
            "✓".bright_green()
        } else {
            "✗".bright_red()
        };
        println!(
            "  ║   {} {:<18} | {:<42} ║",
            status,
            name,
            reason.bright_black()
        );
    }
    println!("  ╚═════════════════════════════════════════════════════════════════════╝");
}

#[allow(clippy::too_many_arguments)]
pub fn print_vulnerability_high_fid(
    index: usize,
    id: &str,
    name: &str,
    severity: u8,
    category: &str,
    location: &str,
    confidence: u8,
    reasoning: &[String],
    gas: u64,
    complexity: &str,
    steps: &[String],
    var_usd: f64,
    history: Option<&str>,
    diff: Option<&str>,
    receipt: Option<(String, u64, u64)>, // (Signature, Drained, ActualGas)
) {
    let badge = match severity {
        5 => " CRITICAL ".on_red().white().bold(),
        4 => "   HIGH   ".on_yellow().black().bold(),
        3 => "  MEDIUM  ".on_blue().white().bold(),
        _ => "   LOW    ".on_bright_black().white(),
    };

    println!("\n  ┌─────────────────────────────────────────────────────────────────────┐");
    println!(
        "  │ {} {} │ {} │ {}% Confidence │",
        format!("#{:02}", index).white(),
        id.bright_cyan().bold(),
        badge,
        confidence
    );
    println!("  │ → {:<65} │", name.bright_white().bold());
    println!("  ├─────────────────────────────────────────────────────────────────────┤");

    // Confidence Reasoning
    println!("  │ Confidence Analysis:                                                │");
    for reason in reasoning {
        println!(
            "  │   {} {:<62} │",
            "•".bright_cyan(),
            reason.bright_black()
        );
    }

    println!("  ├─────────────────────────────────────────────────────────────────────┤");
    println!(
        "  │ Category: {:<16} | Location: {:<26} │",
        category.yellow(),
        location.cyan()
    );
    println!(
        "  │ Value at Risk: {:<14} | Gas Cost: {:<21} │",
        format!("${:.2}M", var_usd).bright_red().bold(),
        format!("{:.5} SOL", gas as f64 / 1e9).bright_red()
    );

    println!("  ├─────────────────────────────────────────────────────────────────────┤");
    println!(
        "  │ Exploit Steps [{} Complexity]:                               │",
        complexity.bright_red()
    );
    for (i, step) in steps.iter().enumerate() {
        println!("  │   {}. {:<62} │", i + 1, step);
    }

    if let Some(h) = history {
        println!("  │  │");
        println!(
            "  │ {} {:<52} │",
            "Historical Precedent:".bright_magenta().underline(),
            ""
        );
        for line in wrap_text(h, 65) {
            println!("  │   {:<65} │", line.bright_magenta());
        }
    }

    if let Some(d) = diff {
        println!("  │  │");
        println!(
            "  │ {} {:<47} │",
            "Professional Remediation [Diff]:"
                .bright_green()
                .underline(),
            ""
        );
        for line in d.lines() {
            let colored = if line.starts_with('+') {
                line.bright_green()
            } else if line.starts_with('-') {
                line.bright_red()
            } else {
                line.normal()
            };
            println!("  │   {:<65} │", colored);
        }
    }

    if let Some((sig, drained, actual_gas)) = receipt {
        println!("  ├─────────────────────────────────────────────────────────────────────┤");
        println!(
            "  │ {} │",
            "PROOF OF EXPLOIT [RECEIPT]"
                .on_bright_green()
                .white()
                .bold()
        );
        println!("  │ • TX Signature: {:<51} │", sig.bright_cyan());
        println!(
            "  │ • Funds Drained: {:<16} | Actual Gas: {:<18} │",
            format!("{:.2} SOL", drained as f64 / 1e9).bright_green(),
            format!("{:.5} SOL", actual_gas as f64 / 1e9).bright_yellow()
        );
    }

    println!("  └─────────────────────────────────────────────────────────────────────┘");
}

pub fn print_priority_queue(items: &[(String, String, f32, &str)]) {
    println!("\n  ╔══ Fix Priority Queue (Risk × Feasibility) ══════════════════════════╗");
    for (i, (id, name, score, time)) in items.iter().enumerate() {
        println!(
            "  ║ {}. [{}] {:<35} | Risk: {:>4.1} | Fix: {:<6} ║",
            i + 1,
            id.bright_cyan(),
            name,
            score.to_string().bright_red(),
            time.bright_green()
        );
    }
    println!("  ╚═════════════════════════════════════════════════════════════════════╝");
}

pub fn print_standards_detailed(results: Vec<(String, Vec<(String, bool)>)>) {
    println!("\n  ╔══ Standards Detailed Compliance ════════════════════════════════════╗");
    for (group, checks) in results {
        let passed_count = checks.iter().filter(|(_, p)| *p).count();
        let total = checks.len();
        let color = if passed_count == total {
            "bright_green"
        } else {
            "yellow"
        };
        println!(
            "  ║ [{}/{}] {:<62} ║",
            passed_count,
            total,
            group.color(color).bold()
        );
        for (name, passed) in checks {
            let status = if passed {
                "✓".bright_green()
            } else {
                "✗".bright_red()
            };
            println!("  ║   {} {:<62} ║", status, name.bright_black());
        }
        println!("  ╠─────────────────────────────────────────────────────────────────────╣");
    }
    println!("  ╚═════════════════════════════════════════════════════════════════════╝");
}

pub fn print_tvr_summary(total_usd: f64, rpc_status: &str, scope: &[&str]) {
    println!(
        "\n  Total Value at Risk (TVR): {}",
        format!("${:.2}M USD", total_usd).bright_red().bold()
    );
    println!("  RPC Integrity: {}", rpc_status.bright_green());
    println!("  Project Scope: {}", scope.join(", ").bright_blue());
}

pub struct Spinner {
    message: String,
    start_time: Instant,
    frame: usize,
}
impl Spinner {
    pub fn new(m: &str) -> Self {
        print!("\r  {} {} ", Theme::spinner_frames()[0].bright_cyan(), m);
        io::stdout().flush().unwrap();
        Self {
            message: m.to_string(),
            start_time: Instant::now(),
            frame: 0,
        }
    }
    pub fn tick(&mut self) {
        self.frame = (self.frame + 1) % Theme::spinner_frames().len();
        print!(
            "\r  {} {} {}",
            Theme::spinner_frames()[self.frame].bright_cyan(),
            self.message,
            format!("[{:.1}s]", self.start_time.elapsed().as_secs_f64()).bright_black()
        );
        io::stdout().flush().unwrap();
    }
    pub fn success(self, m: &str) {
        println!(
            "\r  {} {} {}",
            Theme::success(),
            m.bright_green(),
            format!("[{:.2}s]", self.start_time.elapsed().as_secs_f64()).bright_black()
        );
    }
    pub fn fail(self, m: &str) {
        println!(
            "\r  {} {} {}",
            Theme::failure(),
            m.bright_red(),
            format!("[{:.2}s]", self.start_time.elapsed().as_secs_f64()).bright_black()
        );
    }
}

pub struct ProgressBar {
    total: usize,
    current: usize,
    width: usize,
    label: String,
    start_time: Instant,
}
impl ProgressBar {
    pub fn new(t: usize, l: &str) -> Self {
        Self {
            total: t,
            current: 0,
            width: 40,
            label: l.to_string(),
            start_time: Instant::now(),
        }
    }
    pub fn increment(&mut self) {
        self.current += 1;
        self.draw();
    }
    fn draw(&self) {
        let filled = (self.current as f64 / self.total as f64 * self.width as f64) as usize;
        let bar = format!(
            "{}{}",
            "█".repeat(filled).bright_green(),
            "░".repeat(self.width - filled).bright_black()
        );
        print!(
            "\r  {} {} {}% ",
            self.label.bright_cyan(),
            bar,
            (self.current * 100 / self.total)
        );
        io::stdout().flush().unwrap();
    }
    pub fn finish(&self) {
        println!(
            "\r  {} {} 100% [{:.2}s]",
            Theme::success(),
            self.label.bright_green(),
            self.start_time.elapsed().as_secs_f64()
        );
    }
}

pub fn print_report_saved(paths: &[&str]) {
    println!(
        "\n  {} {}",
        Theme::success(),
        "Reports successfully generated:".bright_green().bold()
    );
    for path in paths {
        println!("    {} {}", Theme::arrow(), path.bright_cyan());
    }
}

pub fn print_section_header(title: &str) {
    println!(
        "\n  {} {}",
        "╔══".bright_cyan(),
        title.bright_white().bold()
    );
}

pub fn print_section_footer() {
    println!("  ╚═════════════════════════════════════════════════════════════════════╝");
}

pub fn print_statistics(
    total: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    _ignored: usize,
    duration: std::time::Duration,
) {
    println!("\n  {} Statistics:", "[REPORT]".bright_cyan());
    println!("    * Total Findings: {}", total);
    println!(
        "    * Critical:       {}",
        critical.to_string().bright_red()
    );
    println!("    * High:           {}", high.to_string().yellow());
    println!("    * Medium:         {}", medium.to_string().blue());
    println!("    * Low:            {}", low.to_string().bright_black());
    println!("    * Scan Duration:  {:.2}s", duration.as_secs_f64());
}

pub fn print_verdict(critical: usize, _high: usize, _medium: usize) {
    if critical == 0 {
        println!(
            "\n  {} VERDICT: {}",
            "✓".bright_green(),
            "DEPLOYMENT READY".bright_green().bold()
        );
    } else {
        println!(
            "\n  {} VERDICT: {}",
            "✗".bright_red(),
            "DEPLOYMENT BLOCKED".bright_red().bold()
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub fn print_vulnerability(
    id: &str,
    vuln: &str,
    sev: u8,
    _category: &str,
    desc: &str,
    _loc: &str,
    _conf: u8,
    _gas: u64,
    _complex: &str,
    _history: Option<&str>,
) {
    println!(
        "  [{}] {} (Sev: {}) - {}",
        id.bright_cyan(),
        vuln.bright_white().bold(),
        sev,
        desc.bright_black()
    );
}

fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();
    for word in text.split_whitespace() {
        if current_line.len() + word.len() + 1 > max_width {
            lines.push(current_line);
            current_line = word.to_string();
        } else {
            if !current_line.is_empty() {
                current_line.push(' ');
            }
            current_line.push_str(word);
        }
    }
    if !current_line.is_empty() {
        lines.push(current_line);
    }
    lines
}

pub fn print_tips() {
    println!(
        "\n  [ADVISORY] {} Run --prove to generate on-chain signatures for every CRITICAL finding.",
        "Security Advisory:".bright_yellow().bold()
    );
}
