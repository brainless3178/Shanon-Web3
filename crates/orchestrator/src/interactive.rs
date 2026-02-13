//! Interactive guided wizard — walks through every audit flag step by step.

use colored::*;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, MultiSelect, Select};
use std::path::PathBuf;

pub struct AuditConfig {
    pub repo: Option<String>,
    pub idl: Option<PathBuf>,
    pub output_dir: PathBuf,
    pub bug_bounty: bool,
    pub prove: bool,
    pub register: bool,
    pub dashboard: bool,
    pub wacana: bool,
    pub trident: bool,
    pub fuzzdelsol: bool,
    pub sec3: bool,
    pub l3x: bool,
    pub geiger: bool,
    pub anchor: bool,
}

impl AuditConfig {
    pub fn print_summary(&self) {
        println!(
            "\n  {} {}\n",
            "✅".bright_green(),
            "Configuration Summary".bright_green().bold()
        );

        let repo_display = self
            .repo
            .as_deref()
            .unwrap_or("(auto-detect workspace)");
        let idl_display = self
            .idl
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "(auto-detect)".to_string());

        let mut engines = Vec::new();
        if self.wacana {
            engines.push("WACANA");
        }
        if self.trident {
            engines.push("Trident");
        }
        if self.fuzzdelsol {
            engines.push("FuzzDelSol");
        }
        if self.sec3 {
            engines.push("Sec3");
        }
        if self.l3x {
            engines.push("L3X");
        }
        if self.geiger {
            engines.push("Geiger");
        }
        if self.anchor {
            engines.push("Anchor");
        }
        let engines_str = if engines.is_empty() {
            "(none)".to_string()
        } else {
            engines.join(", ")
        };

        let mode_str = if self.bug_bounty {
            "Bug Bounty".bright_yellow().bold().to_string()
        } else {
            "Standard Audit".bright_cyan().to_string()
        };

        println!("  ├ Target:     {}", repo_display.bright_white());
        println!("  ├ IDL:        {}", idl_display.bright_white());
        println!(
            "  ├ Output:     {}",
            self.output_dir.display().to_string().bright_white()
        );
        println!("  ├ Mode:       {}", mode_str);
        println!("  ├ Engines:    {}", engines_str.bright_white());
        println!(
            "  ├ Prove:      {}",
            if self.prove { "Yes" } else { "No" }
        );
        println!(
            "  ├ Register:   {}",
            if self.register { "Yes" } else { "No" }
        );
        println!(
            "  └ Dashboard:  {}",
            if self.dashboard { "Yes" } else { "No" }
        );
        println!();
    }
}

pub struct WatchConfig {
    pub dashboard: bool,
}

pub struct DashboardConfig {
    pub report: Option<PathBuf>,
}

pub struct ExplorerConfig {
    pub transaction: Option<String>,
    pub replay: bool,
}

pub struct ScanConfig {
    pub target: String,
    pub idl: Option<PathBuf>,
    pub output_dir: PathBuf,
    pub branch: Option<String>,
    pub bug_bounty: bool,
    pub dashboard: bool,
    pub prove: bool,
    pub register: bool,
    pub post_to_forum: bool,
    pub hackathon_api_key: Option<String>,
    pub wacana: bool,
    pub trident: bool,
    pub fuzzdelsol: bool,
    pub sec3: bool,
    pub l3x: bool,
    pub geiger: bool,
    pub anchor: bool,
}

pub enum WizardResult {
    Audit(AuditConfig),
    Watch(WatchConfig),
    Dashboard(DashboardConfig),
    Explorer(ExplorerConfig),
    Scan(ScanConfig),
}

pub fn run_wizard() -> anyhow::Result<WizardResult> {
    println!(
        "\n  {} {}\n",
        "🔐".bright_cyan(),
        "Interactive Security Wizard".bright_cyan().bold()
    );

    let theme = ColorfulTheme::default();

    let modes = &[
        "Scan      — Quick scan: give a Git URL (GitHub/GitLab/Bitbucket/…) or Solana address",
        "Audit     — Deep-scrutiny security audit of a local Solana program",
        "Watch     — Continuous mainnet monitoring for real-time threats",
        "Dashboard — Browse past audit reports in a TUI",
        "Explorer  — Transaction forensics and on-chain inspection",
    ];

    let mode = Select::with_theme(&theme)
        .with_prompt("What would you like to do?")
        .items(modes)
        .default(0)
        .interact()?;

    match mode {
        0 => scan_wizard(&theme),
        1 => audit_wizard(&theme),
        2 => watch_wizard(&theme),
        3 => dashboard_wizard(&theme),
        4 => explorer_wizard(&theme),
        _ => unreachable!(),
    }
}

fn audit_wizard(theme: &ColorfulTheme) -> anyhow::Result<WizardResult> {
    println!(
        "\n  {} {}\n",
        "🔍".bright_yellow(),
        "Audit Configuration".bright_yellow().bold()
    );

    let repo: String = Input::with_theme(theme)
        .with_prompt("Target repository path (local path or URL, enter to auto-detect)")
        .allow_empty(true)
        .interact_text()?;
    let repo = if repo.trim().is_empty() {
        None
    } else {
        Some(repo.trim().to_string())
    };

    let idl: String = Input::with_theme(theme)
        .with_prompt("Path to Anchor IDL JSON (enter to auto-detect)")
        .allow_empty(true)
        .interact_text()?;
    let idl = if idl.trim().is_empty() {
        None
    } else {
        Some(PathBuf::from(idl.trim()))
    };

    let output_dir: String = Input::with_theme(theme)
        .with_prompt("Output directory for reports")
        .default("audit_reports".to_string())
        .interact_text()?;
    let output_dir = PathBuf::from(output_dir.trim());

    let bug_bounty = Confirm::with_theme(theme)
        .with_prompt("Enable Bug Bounty mode? (all engines ON, generates submission-ready report)")
        .default(false)
        .interact()?;

    let engine_labels = &[
        "WACANA     — Concolic bytecode analysis",
        "Trident   — Stateful fuzzing (Ackee Blockchain)",
        "FuzzDelSol — Binary fuzzing (eBPF coverage-guided)",
        "Sec3      — Advanced static analysis (Soteria)",
        "L3X       — AI-driven vulnerability detection",
        "Geiger    — Unsafe Rust code detection",
        "Anchor    — Framework constraint validation",
    ];

    let selected_engines = if bug_bounty {
        println!(
            "  {} All engines enabled for bug bounty mode\n",
            "✓".bright_green()
        );
        vec![0, 1, 2, 3, 4, 5, 6]
    } else {
        let defaults = vec![true; 7];
        MultiSelect::with_theme(theme)
            .with_prompt("Select analysis engines (space to toggle, enter to confirm)")
            .items(engine_labels)
            .defaults(&defaults)
            .interact()?
    };

    let wacana = selected_engines.contains(&0);
    let trident = selected_engines.contains(&1);
    let fuzzdelsol = selected_engines.contains(&2);
    let sec3 = selected_engines.contains(&3);
    let l3x = selected_engines.contains(&4);
    let geiger = selected_engines.contains(&5);
    let anchor = selected_engines.contains(&6);

    println!(
        "\n  {} {}\n",
        "⚙️",
        "Advanced Options".bright_yellow().bold()
    );

    let prove = Confirm::with_theme(theme)
        .with_prompt("Enable on-chain exploit proving?")
        .default(false)
        .interact()?;

    let register = Confirm::with_theme(theme)
        .with_prompt("Register verified exploits on-chain?")
        .default(false)
        .interact()?;

    let dashboard = Confirm::with_theme(theme)
        .with_prompt("Launch interactive dashboard after audit?")
        .default(true)
        .interact()?;

    let config = AuditConfig {
        repo,
        idl,
        output_dir,
        bug_bounty,
        prove,
        register,
        dashboard,
        wacana,
        trident,
        fuzzdelsol,
        sec3,
        l3x,
        geiger,
        anchor,
    };

    config.print_summary();

    let proceed = Confirm::with_theme(theme)
        .with_prompt("Start audit with this configuration?")
        .default(true)
        .interact()?;

    if !proceed {
        anyhow::bail!("Audit cancelled by user");
    }

    Ok(WizardResult::Audit(config))
}

fn watch_wizard(theme: &ColorfulTheme) -> anyhow::Result<WizardResult> {
    println!(
        "\n  {} {}\n",
        "👁️",
        "Watch Configuration".bright_yellow().bold()
    );

    let dashboard = Confirm::with_theme(theme)
        .with_prompt("Launch with live dashboard view?")
        .default(true)
        .interact()?;

    Ok(WizardResult::Watch(WatchConfig { dashboard }))
}

fn dashboard_wizard(theme: &ColorfulTheme) -> anyhow::Result<WizardResult> {
    println!(
        "\n  {} {}\n",
        "📊".bright_cyan(),
        "Dashboard Configuration".bright_yellow().bold()
    );

    let report: String = Input::with_theme(theme)
        .with_prompt("Path to report JSON file (enter for blank dashboard)")
        .allow_empty(true)
        .interact_text()?;
    let report = if report.trim().is_empty() {
        None
    } else {
        Some(PathBuf::from(report.trim()))
    };

    Ok(WizardResult::Dashboard(DashboardConfig { report }))
}

fn scan_wizard(theme: &ColorfulTheme) -> anyhow::Result<WizardResult> {
    println!(
        "\n  {} {}\n",
        "🔗".bright_yellow(),
        "Quick Scan".bright_yellow().bold()
    );

    let target: String = Input::with_theme(theme)
        .with_prompt("Git repo URL (GitHub/GitLab/Bitbucket/…) or Solana program address")
        .interact_text()?;

    let branch_input: String = Input::with_theme(theme)
        .with_prompt("Branch to clone (enter for default branch)")
        .allow_empty(true)
        .interact_text()?;
    let branch = if branch_input.trim().is_empty() {
        None
    } else {
        Some(branch_input.trim().to_string())
    };

    let idl_input: String = Input::with_theme(theme)
        .with_prompt("Path to Anchor IDL JSON (enter to auto-detect)")
        .allow_empty(true)
        .interact_text()?;
    let idl = if idl_input.trim().is_empty() {
        None
    } else {
        Some(PathBuf::from(idl_input.trim()))
    };

    let output_dir: String = Input::with_theme(theme)
        .with_prompt("Output directory for reports")
        .default("audit_reports".to_string())
        .interact_text()?;
    let output_dir = PathBuf::from(output_dir.trim());

    let bug_bounty = Confirm::with_theme(theme)
        .with_prompt("Enable Bug Bounty mode? (all engines ON, generates submission-ready report)")
        .default(false)
        .interact()?;

    let engine_labels = &[
        "WACANA     — Concolic bytecode analysis",
        "Trident   — Stateful fuzzing (Ackee Blockchain)",
        "FuzzDelSol — Binary fuzzing (eBPF coverage-guided)",
        "Sec3      — Advanced static analysis (Soteria)",
        "L3X       — AI-driven vulnerability detection",
        "Geiger    — Unsafe Rust code detection",
        "Anchor    — Framework constraint validation",
    ];

    let selected_engines = if bug_bounty {
        println!(
            "  {} All engines enabled for bug bounty mode\n",
            "✓".bright_green()
        );
        vec![0, 1, 2, 3, 4, 5, 6]
    } else {
        let defaults = vec![true; 7];
        MultiSelect::with_theme(theme)
            .with_prompt("Select analysis engines (space to toggle, enter to confirm)")
            .items(engine_labels)
            .defaults(&defaults)
            .interact()?
    };

    let wacana = selected_engines.contains(&0);
    let trident = selected_engines.contains(&1);
    let fuzzdelsol = selected_engines.contains(&2);
    let sec3 = selected_engines.contains(&3);
    let l3x = selected_engines.contains(&4);
    let geiger = selected_engines.contains(&5);
    let anchor = selected_engines.contains(&6);

    println!(
        "\n  {} {}\n",
        "⚙️",
        "Advanced Options".bright_yellow().bold()
    );

    let prove = Confirm::with_theme(theme)
        .with_prompt("Enable on-chain exploit proving?")
        .default(false)
        .interact()?;

    let register = Confirm::with_theme(theme)
        .with_prompt("Register verified exploits on-chain?")
        .default(false)
        .interact()?;

    let post_to_forum = Confirm::with_theme(theme)
        .with_prompt("Submit results to hackathon forum?")
        .default(false)
        .interact()?;

    let hackathon_api_key = if post_to_forum {
        let key: String = Input::with_theme(theme)
            .with_prompt("Hackathon API key (or set HACKATHON_API_KEY env var)")
            .allow_empty(true)
            .interact_text()?;
        if key.trim().is_empty() {
            None
        } else {
            Some(key.trim().to_string())
        }
    } else {
        None
    };

    let dashboard = Confirm::with_theme(theme)
        .with_prompt("Launch dashboard after scan?")
        .default(false)
        .interact()?;

    let config = ScanConfig {
        target: target.trim().to_string(),
        idl,
        output_dir,
        branch,
        bug_bounty,
        dashboard,
        prove,
        register,
        post_to_forum,
        hackathon_api_key,
        wacana,
        trident,
        fuzzdelsol,
        sec3,
        l3x,
        geiger,
        anchor,
    };

    // Build engine list for summary
    let mut engines = Vec::new();
    if config.wacana { engines.push("WACANA"); }
    if config.trident { engines.push("Trident"); }
    if config.fuzzdelsol { engines.push("FuzzDelSol"); }
    if config.sec3 { engines.push("Sec3"); }
    if config.l3x { engines.push("L3X"); }
    if config.geiger { engines.push("Geiger"); }
    if config.anchor { engines.push("Anchor"); }
    let engines_str = if engines.is_empty() { "(none)".to_string() } else { engines.join(", ") };

    let idl_display = config
        .idl
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(auto-detect)".to_string());

    let mode_str = if config.bug_bounty {
        "Bug Bounty".bright_yellow().bold().to_string()
    } else {
        "Standard Scan".bright_cyan().to_string()
    };

    println!(
        "\n  {} {}\n",
        "✅".bright_green(),
        "Scan Configuration".bright_green().bold()
    );
    println!("  ├ Target:     {}", config.target.bright_white());
    println!(
        "  ├ Branch:     {}",
        config.branch.as_deref().unwrap_or("(default)").bright_white()
    );
    println!("  ├ IDL:        {}", idl_display.bright_white());
    println!(
        "  ├ Output:     {}",
        config.output_dir.display().to_string().bright_white()
    );
    println!("  ├ Mode:       {}", mode_str);
    println!("  ├ Engines:    {}", engines_str.bright_white());
    println!(
        "  ├ Prove:      {}",
        if config.prove { "Yes" } else { "No" }
    );
    println!(
        "  ├ Register:   {}",
        if config.register { "Yes" } else { "No" }
    );
    println!(
        "  ├ Forum:      {}",
        if config.post_to_forum { "Yes" } else { "No" }
    );
    println!(
        "  └ Dashboard:  {}",
        if config.dashboard { "Yes" } else { "No" }
    );
    println!();

    let proceed = Confirm::with_theme(theme)
        .with_prompt("Start scan with this configuration?")
        .default(true)
        .interact()?;

    if !proceed {
        anyhow::bail!("Scan cancelled by user");
    }

    Ok(WizardResult::Scan(config))
}

fn explorer_wizard(theme: &ColorfulTheme) -> anyhow::Result<WizardResult> {
    println!(
        "\n  {} {}\n",
        "🔎".bright_yellow(),
        "Explorer Configuration".bright_yellow().bold()
    );

    let tx: String = Input::with_theme(theme)
        .with_prompt("Transaction signature to inspect (enter to skip)")
        .allow_empty(true)
        .interact_text()?;
    let transaction = if tx.trim().is_empty() {
        None
    } else {
        Some(tx.trim().to_string())
    };

    let replay = if transaction.is_some() {
        Confirm::with_theme(theme)
            .with_prompt("Replay transaction in sandbox?")
            .default(false)
            .interact()?
    } else {
        false
    };

    Ok(WizardResult::Explorer(ExplorerConfig {
        transaction,
        replay,
    }))
}
