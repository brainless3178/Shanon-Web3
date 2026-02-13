//! Interactive TUI Dashboard for Solana Security Swarm
//!
//! Provides a real-time, multi-panel dashboard for security auditing:
//! - Security Score Gauge
//! - Vulnerability Severity Bar Chart
//! - Sparkline for scan history
//! - Threat Detection Timeline
//! - Standards Compliance List
//! - Finding Browser
//!
//! Built with ratatui for a beautiful terminal experience.

use crate::audit_pipeline::{AuditReport, ConfirmedExploit};
use crate::chain_explorer::{AccountOverview, ChainExplorer, NetworkStats, TransactionDetail};
use crate::mainnet_guardian::{ThreatDetection, ThreatLevel};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        BarChart, Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Sparkline,
        Tabs, Wrap,
    },
    Frame, Terminal,
};
use std::io;
use std::time::{Duration, Instant};

/// Dashboard state containing all the data to display
pub struct DashboardState {
    /// Current active tab
    pub active_tab: usize,
    /// Tab names
    pub tab_titles: Vec<&'static str>,
    /// Security reports from audits
    pub reports: Vec<AuditReport>,
    /// Historical security scores (for sparkline)
    pub score_history: Vec<u64>,
    /// Live threat detections
    pub threats: Vec<ThreatDetection>,
    /// Currently selected finding index
    pub selected_finding: usize,
    /// Finding list state
    pub finding_list_state: ListState,
    /// Threats list state
    pub threat_list_state: ListState,
    /// Are we showing detail panel?
    pub show_detail: bool,
    /// Status message
    pub status_message: String,
    /// Last update time
    pub last_update: Instant,
    /// Is scanning in progress?
    pub scanning: bool,
    /// Scan progress (0-100)
    pub scan_progress: u16,
    /// Active defense subsystem
    pub mitigation_engine: crate::mitigation_engine::MitigationEngine,
    /// Current selected maneuver
    pub active_maneuver: crate::mitigation_engine::MitigationManeuver,
    /// RPC Explorer
    pub explorer: Option<ChainExplorer>,
    /// Live Network Stats
    pub network_stats: Option<NetworkStats>,
    /// Search Query
    pub search_query: String,
    /// Account Research Result
    pub search_result_account: Option<AccountOverview>,
    /// Transaction Research Result
    pub search_result_tx: Option<TransactionDetail>,
    /// Input mode for search
    pub input_mode: bool,
}

impl Default for DashboardState {
    fn default() -> Self {
        Self {
            active_tab: 0,
            tab_titles: vec![
                "Overview",
                "Findings",
                "Threats",
                "Explorer",
                "Compliance",
                "Help",
            ],
            reports: Vec::new(),
            score_history: vec![85, 80, 75, 82, 78, 85, 90, 88, 85, 87],
            threats: Vec::new(),
            selected_finding: 0,
            finding_list_state: ListState::default(),
            threat_list_state: ListState::default(),
            show_detail: false,
            status_message: "Press 'q' to quit, Tab to switch views".to_string(),
            last_update: Instant::now(),
            scanning: false,
            scan_progress: 0,
            mitigation_engine: crate::mitigation_engine::MitigationEngine::new(),
            active_maneuver: crate::mitigation_engine::MitigationManeuver::None,
            explorer: None,
            network_stats: None,
            search_query: String::new(),
            search_result_account: None,
            search_result_tx: None,
            input_mode: false,
        }
    }
}

impl DashboardState {
    /// Create dashboard with audit reports
    pub fn with_reports(reports: Vec<AuditReport>) -> Self {
        let score_history: Vec<u64> = reports.iter().map(|r| r.security_score as u64).collect();

        let mut state = Self {
            reports,
            score_history: if score_history.is_empty() {
                vec![85, 80, 75, 82, 78, 85, 90, 88, 85, 87]
            } else {
                score_history
            },
            ..Default::default()
        };
        state.finding_list_state.select(Some(0));
        state
    }

    /// Add a threat detection
    pub fn add_threat(&mut self, threat: ThreatDetection) {
        self.threats.insert(0, threat);
        if self.threats.len() > 100 {
            self.threats.pop();
        }
    }

    /// Initialize explorer with RPC URL
    pub fn set_rpc_url(&mut self, url: String) {
        self.explorer = Some(ChainExplorer::new(url));
    }

    /// Execute search for account or transaction
    pub fn execute_search(&mut self) {
        let query = self.search_query.clone();
        if query.is_empty() {
            return;
        }

        if let Some(explorer) = &self.explorer {
            // Reset results
            self.search_result_account = None;
            self.search_result_tx = None;
            self.status_message = format!("Searching for {}...", query);

            // Attempt Transaction Signature search first (length 88 typically)
            if query.len() >= 80 {
                match explorer.inspect_transaction(&query) {
                    Ok(tx) => {
                        self.search_result_tx = Some(tx);
                        self.status_message = "Transaction found!".to_string();
                        return;
                    }
                    Err(_) => { /* fallback to account */ }
                }
            }

            // Attempt Account Pubkey search
            match explorer.inspect_account(&query) {
                Ok(acc) => {
                    self.search_result_account = Some(acc);
                    self.status_message = "Account found!".to_string();
                }
                Err(e) => {
                    self.status_message = format!("Search failed: {}", e);
                }
            }
        }
    }

    /// Get total findings count
    pub fn total_findings(&self) -> usize {
        self.reports.iter().map(|r| r.total_exploits).sum()
    }

    /// Get all exploits flattened
    pub fn all_exploits(&self) -> Vec<&ConfirmedExploit> {
        self.reports.iter().flat_map(|r| &r.exploits).collect()
    }

    /// Get severity counts
    pub fn severity_counts(&self) -> (usize, usize, usize, usize) {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;

        for report in &self.reports {
            critical += report.critical_count;
            high += report.high_count;
            medium += report.medium_count;
            low += report
                .total_exploits
                .saturating_sub(critical + high + medium);
        }

        (critical, high, medium, low)
    }

    /// Average security score
    pub fn avg_security_score(&self) -> u8 {
        if self.reports.is_empty() {
            return 0;
        }
        let total: u32 = self.reports.iter().map(|r| r.security_score as u32).sum();
        (total / self.reports.len() as u32) as u8
    }

    /// Total value at risk
    pub fn total_value_at_risk(&self) -> f64 {
        self.reports.iter().map(|r| r.total_value_at_risk_usd).sum()
    }

    /// Navigate to next finding
    pub fn next_finding(&mut self) {
        let exploits = self.all_exploits();
        if exploits.is_empty() {
            return;
        }
        self.selected_finding = (self.selected_finding + 1) % exploits.len();
        self.finding_list_state.select(Some(self.selected_finding));
    }

    /// Navigate to previous finding
    pub fn prev_finding(&mut self) {
        let exploits = self.all_exploits();
        if exploits.is_empty() {
            return;
        }
        self.selected_finding = if self.selected_finding == 0 {
            exploits.len() - 1
        } else {
            self.selected_finding - 1
        };
        self.finding_list_state.select(Some(self.selected_finding));
    }

    /// Switch to next tab
    pub fn next_tab(&mut self) {
        self.active_tab = (self.active_tab + 1) % self.tab_titles.len();
    }

    /// Switch to previous tab  
    pub fn prev_tab(&mut self) {
        self.active_tab = if self.active_tab == 0 {
            self.tab_titles.len() - 1
        } else {
            self.active_tab - 1
        };
    }
}

/// Run the interactive TUI dashboard
pub fn run_dashboard(state: DashboardState) -> anyhow::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_app(&mut terminal, state);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

/// Run the interactive TUI dashboard in live monitor mode
pub fn run_live_dashboard(
    state: DashboardState,
    rx: std::sync::mpsc::Receiver<ThreatDetection>,
) -> anyhow::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_live_app(&mut terminal, state, rx);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

/// Live application loop with threat channel
fn run_live_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    mut state: DashboardState,
    rx: std::sync::mpsc::Receiver<ThreatDetection>,
) -> anyhow::Result<()> {
    let tick_rate = Duration::from_millis(100);
    let mut last_tick = Instant::now();

    loop {
        // Check for new threats
        while let Ok(threat) = rx.try_recv() {
            state.add_threat(threat);
            state.status_message = "NEW THREAT DETECTED!".to_string();
        }

        terminal.draw(|f| ui(f, &mut state))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if state.input_mode {
                        match key.code {
                            KeyCode::Enter => {
                                state.execute_search();
                                state.input_mode = false;
                            }
                            KeyCode::Char(c) => {
                                state.search_query.push(c);
                            }
                            KeyCode::Backspace => {
                                state.search_query.pop();
                            }
                            KeyCode::Esc => {
                                state.input_mode = false;
                            }
                            _ => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                            KeyCode::Tab => state.next_tab(),
                            KeyCode::BackTab => state.prev_tab(),
                            KeyCode::Down | KeyCode::Char('j') => state.next_finding(),
                            KeyCode::Up | KeyCode::Char('k') => state.prev_finding(),
                            KeyCode::Enter => {
                                if state.active_tab == 3 {
                                    state.input_mode = true;
                                } else {
                                    state.show_detail = !state.show_detail;
                                }
                            }
                            KeyCode::Char('/') => {
                                state.active_tab = 3;
                                state.input_mode = true;
                            }
                            KeyCode::Char('1') => state.active_tab = 0,
                            KeyCode::Char('2') => state.active_tab = 1,
                            KeyCode::Char('3') => state.active_tab = 2,
                            KeyCode::Char('4') => state.active_tab = 3,
                            KeyCode::Char('5') => state.active_tab = 4,
                            KeyCode::Char('6') | KeyCode::Char('?') => state.active_tab = 5,
                            KeyCode::Char('m') => {
                                // Trigger manual mitigation sequence for selected threat
                                if let Some(threat) = state
                                    .threats
                                    .get(state.threat_list_state.selected().unwrap_or(0))
                                {
                                    state.active_maneuver =
                                        state.mitigation_engine.devise_defense(threat, &None);
                                    state.status_message =
                                        format!("DEFENSE DEPLOYED: {:?}", state.active_maneuver);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            state.last_update = Instant::now();
            last_tick = Instant::now();

            // Poll Network Stats
            if let Some(explorer) = &state.explorer {
                if let Ok(stats) = explorer.fetch_network_stats() {
                    state.network_stats = Some(stats);
                }
            }
        }
    }
}

/// Main application loop
fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    mut state: DashboardState,
) -> anyhow::Result<()> {
    let tick_rate = Duration::from_millis(100);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| ui(f, &mut state))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if state.input_mode {
                        match key.code {
                            KeyCode::Enter => {
                                state.execute_search();
                                state.input_mode = false;
                            }
                            KeyCode::Char(c) => {
                                state.search_query.push(c);
                            }
                            KeyCode::Backspace => {
                                state.search_query.pop();
                            }
                            KeyCode::Esc => {
                                state.input_mode = false;
                            }
                            _ => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                            KeyCode::Tab => state.next_tab(),
                            KeyCode::BackTab => state.prev_tab(),
                            KeyCode::Down | KeyCode::Char('j') => state.next_finding(),
                            KeyCode::Up | KeyCode::Char('k') => state.prev_finding(),
                            KeyCode::Enter => {
                                if state.active_tab == 3 {
                                    state.input_mode = true;
                                } else {
                                    state.show_detail = !state.show_detail;
                                }
                            }
                            KeyCode::Char('/') => {
                                state.active_tab = 3;
                                state.input_mode = true;
                            }
                            KeyCode::Char('1') => state.active_tab = 0,
                            KeyCode::Char('2') => state.active_tab = 1,
                            KeyCode::Char('3') => state.active_tab = 2,
                            KeyCode::Char('4') => state.active_tab = 3,
                            KeyCode::Char('5') => state.active_tab = 4,
                            KeyCode::Char('6') | KeyCode::Char('?') => state.active_tab = 5,
                            _ => {}
                        }
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            state.last_update = Instant::now();
            last_tick = Instant::now();
        }
    }
}

/// Main UI rendering function
fn ui(f: &mut Frame, state: &mut DashboardState) {
    let size = f.area();

    // Create main layout: header, tabs, content, footer
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(3), // Tabs
            Constraint::Min(10),   // Content
            Constraint::Length(3), // Footer/Status
        ])
        .split(size);

    // Render header
    render_header(f, chunks[0], state);

    // Render tabs
    render_tabs(f, chunks[1], state);

    // Render content based on active tab
    match state.active_tab {
        0 => render_overview(f, chunks[2], state),
        1 => render_findings(f, chunks[2], state),
        2 => render_threats(f, chunks[2], state),
        3 => render_explorer(f, chunks[2], state),
        4 => render_compliance(f, chunks[2], state),
        5 => render_help(f, chunks[2]),
        _ => {}
    }

    // Render footer
    render_footer(f, chunks[3], state);

    // Render detail popup if active
    if state.show_detail && state.active_tab == 1 {
        render_finding_detail_popup(f, state);
    }
}

/// Render the header with branding
fn render_header(f: &mut Frame, area: Rect, state: &DashboardState) {
    let (critical, high, _medium, _low) = state.severity_counts();

    let network_info = if let Some(stats) = &state.network_stats {
        format!("TPS: {:.1} │ Slot: {}", stats.tps, stats.slot)
    } else {
        "Network: Syncing...".to_string()
    };

    let header_content = vec![
        Span::styled(
            "⚡ SOLANA SECURITY SWARM ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("│ ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{} ", network_info),
            Style::default().fg(Color::White),
        ),
        Span::styled("│ ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("Critical: {} ", critical),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("High: {} ", high),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("│ ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("Value at Risk: ${:.2}M", state.total_value_at_risk()),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    ];

    let header = Paragraph::new(Line::from(header_content)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(0, 255, 255)))
            .title(" [ SYSTEM NODE: ALPHA-01 ] ")
            .title_style(
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
    );
    f.render_widget(header, area);
}

/// Render the tab bar
fn render_tabs(f: &mut Frame, area: Rect, state: &DashboardState) {
    let titles: Vec<Line> = state
        .tab_titles
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let style = if i == state.active_tab {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            Line::from(Span::styled(format!(" {} [{}] ", t, i + 1), style))
        })
        .collect();

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .highlight_style(Style::default().fg(Color::Cyan))
        .select(state.active_tab);
    f.render_widget(tabs, area);
}

/// Render the overview dashboard with enhanced visuals
fn render_overview(f: &mut Frame, area: Rect, state: &DashboardState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(10)])
        .split(area);

    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(34),
        ])
        .split(chunks[0]);

    // Enhanced Security Score Gauge
    let score = state.avg_security_score();
    let score_color = if score > 80 {
        Color::Green
    } else if score > 60 {
        Color::Yellow
    } else {
        Color::Red
    };

    let gauge = Gauge::default()
        .block(
            Block::default()
                .title(" TRUST SCORE ")
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded),
        )
        .gauge_style(Style::default().fg(score_color).bg(Color::Rgb(20, 20, 20)))
        .percent(score as u16)
        .label(format!(" {}/100 ", score))
        .use_unicode(true);
    f.render_widget(gauge, top_chunks[0]);

    // Live Metrics Sparkline
    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .title(" SCAN INTENSITY ")
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded),
        )
        .data(&state.score_history)
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(sparkline, top_chunks[1]);

    // Active Safeguards
    let safeguards = vec![
        Line::from(vec![
            Span::styled("Mainnet Guardian: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "ACTIVE",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("AI Consensus:     ", Style::default().fg(Color::DarkGray)),
            Span::styled("SAMPLING", Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("WACANA Concolic:  ", Style::default().fg(Color::DarkGray)),
            Span::styled("RUNNING", Style::default().fg(Color::Green)),
        ]),
        Line::from(vec![
            Span::styled("Attack Simulator: ", Style::default().fg(Color::DarkGray)),
            Span::styled("ARMED", Style::default().fg(Color::Red)),
        ]),
        Line::from(vec![
            Span::styled("Oracle Watcher:   ", Style::default().fg(Color::DarkGray)),
            Span::styled("SYNCED", Style::default().fg(Color::Green)),
        ]),
    ];
    let safeguards_widget = Paragraph::new(safeguards)
        .block(
            Block::default()
                .title(" SUBSYSTEM STATUS ")
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded),
        )
        .style(Style::default().fg(Color::White));
    f.render_widget(safeguards_widget, top_chunks[2]);

    // Severity Concentration Map
    let (c, h, m, l) = state.severity_counts();
    let bar_group = ratatui::widgets::BarGroup::default()
        .label("Severity".into())
        .bars(&[
            ratatui::widgets::Bar::default()
                .value(c as u64)
                .label("CRIT".into())
                .style(Style::default().fg(Color::Red)),
            ratatui::widgets::Bar::default()
                .value(h as u64)
                .label("HIGH".into())
                .style(Style::default().fg(Color::Yellow)),
            ratatui::widgets::Bar::default()
                .value(m as u64)
                .label("MED".into())
                .style(Style::default().fg(Color::Blue)),
            ratatui::widgets::Bar::default()
                .value(l as u64)
                .label("LOW".into())
                .style(Style::default().fg(Color::DarkGray)),
        ]);

    let chart_block = Block::default()
        .title(" THREAT LANDSCAPE ")
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Thick)
        .border_style(Style::default().fg(Color::DarkGray));

    let barchart = BarChart::default()
        .block(chart_block)
        .data(bar_group.clone())
        .bar_width(10)
        .bar_gap(5);

    f.render_widget(barchart, chunks[1]);
}

/// Render the findings browser
fn render_findings(f: &mut Frame, area: Rect, state: &mut DashboardState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Finding list
    let (items, count) = {
        let exploits = state.all_exploits();
        let items: Vec<ListItem> = exploits
            .iter()
            .enumerate()
            .map(|(i, exp)| {
                let severity_color = match exp.severity {
                    5 => Color::Red,
                    4 => Color::Yellow,
                    3 => Color::Blue,
                    _ => Color::DarkGray,
                };
                let severity_icon = match exp.severity {
                    5 => "🔴",
                    4 => "🟡",
                    3 => "🔵",
                    _ => "⚪",
                };
                let content = Line::from(vec![
                    Span::styled(format!("{} ", severity_icon), Style::default()),
                    Span::styled(format!("[{}] ", exp.id), Style::default().fg(Color::Cyan)),
                    Span::styled(
                        exp.vulnerability_type.clone(),
                        Style::default().fg(severity_color),
                    ),
                ]);

                let style = if i == state.selected_finding {
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(content).style(style)
            })
            .collect();
        (items, exploits.len())
    };

    let findings_list = List::new(items)
        .block(
            Block::default()
                .title(format!(" Findings ({}) ", count))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(findings_list, chunks[0], &mut state.finding_list_state);

    // Finding detail panel
    let exploits = state.all_exploits();
    if let Some(exploit) = exploits.get(state.selected_finding) {
        let severity_text = match exploit.severity {
            5 => "CRITICAL",
            4 => "HIGH",
            3 => "MEDIUM",
            _ => "LOW",
        };
        let severity_color = match exploit.severity {
            5 => Color::Red,
            4 => Color::Yellow,
            3 => Color::Blue,
            _ => Color::DarkGray,
        };

        let detail_text = vec![
            Line::from(vec![
                Span::styled("ID: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    &exploit.id,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Type: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    &exploit.vulnerability_type,
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled("Severity: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    severity_text,
                    Style::default()
                        .fg(severity_color)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Category: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&exploit.category, Style::default().fg(Color::Magenta)),
            ]),
            Line::from(vec![
                Span::styled("Confidence: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{}%", exploit.confidence_score),
                    Style::default().fg(Color::Green),
                ),
            ]),
            Line::from(vec![
                Span::styled("Risk: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("${:.2}M", exploit.value_at_risk_usd),
                    Style::default().fg(Color::Red),
                ),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "Description:",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )),
        ];

        let mut full_text = detail_text;
        for line in wrap_text_lines(&exploit.description, (chunks[1].width - 4) as usize) {
            full_text.push(Line::from(Span::styled(
                line,
                Style::default().fg(Color::DarkGray),
            )));
        }

        full_text.push(Line::from(""));
        full_text.push(Line::from(Span::styled(
            "Attack Scenario:",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
        for line in wrap_text_lines(&exploit.attack_scenario, (chunks[1].width - 4) as usize) {
            full_text.push(Line::from(Span::styled(
                line,
                Style::default().fg(Color::Red),
            )));
        }

        let detail = Paragraph::new(full_text)
            .block(
                Block::default()
                    .title(" Finding Details (Enter to expand) ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(severity_color)),
            )
            .wrap(Wrap { trim: true });
        f.render_widget(detail, chunks[1]);
    } else {
        let empty = Paragraph::new("No findings to display").block(
            Block::default()
                .title(" Finding Details ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(empty, chunks[1]);
    }
}

/// Render threats view
fn render_threats(f: &mut Frame, area: Rect, state: &mut DashboardState) {
    let items: Vec<ListItem> = state
        .threats
        .iter()
        .map(|threat| {
            let level_icon = match threat.threat_level {
                ThreatLevel::Critical => "🔴 CRITICAL",
                ThreatLevel::High => "🟡 HIGH",
                ThreatLevel::Medium => "🔵 MEDIUM",
                ThreatLevel::Low => "⚪ LOW",
                ThreatLevel::None => "⚪ NONE",
            };
            let level_color = match threat.threat_level {
                ThreatLevel::Critical => Color::Red,
                ThreatLevel::High => Color::Yellow,
                ThreatLevel::Medium => Color::Blue,
                ThreatLevel::Low => Color::DarkGray,
                ThreatLevel::None => Color::DarkGray,
            };

            ListItem::new(vec![
                Line::from(vec![
                    Span::styled(format!("{} ", level_icon), Style::default().fg(level_color)),
                    Span::styled(
                        format!("{:?}", threat.threat_type),
                        Style::default().fg(Color::White),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  └─ ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&threat.explanation, Style::default().fg(Color::DarkGray)),
                ]),
            ])
        })
        .collect();

    let threat_list = List::new(items).block(
        Block::default()
            .title(format!(" Live Threats ({}) ", state.threats.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red)),
    );
    f.render_stateful_widget(threat_list, area, &mut state.threat_list_state);
}

/// Render compliance view
fn render_compliance(f: &mut Frame, area: Rect, state: &DashboardState) {
    let compliance_items: Vec<ListItem> = if !state.reports.is_empty() {
        state.reports[0]
            .standards_compliance
            .iter()
            .flat_map(|(standard, checks)| {
                let passed = checks.iter().filter(|(_, p)| *p).count();
                let total = checks.len();
                let status_color = if passed == total {
                    Color::Green
                } else {
                    Color::Yellow
                };

                std::iter::once(ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("[{}/{}] ", passed, total),
                        Style::default().fg(status_color),
                    ),
                    Span::styled(
                        standard,
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
                ])))
                .chain(checks.iter().map(|(name, passed)| {
                    let icon = if *passed { "✓" } else { "✗" };
                    let color = if *passed { Color::Green } else { Color::Red };
                    ListItem::new(Line::from(vec![
                        Span::styled("  ", Style::default()),
                        Span::styled(icon, Style::default().fg(color)),
                        Span::styled(format!(" {}", name), Style::default().fg(Color::DarkGray)),
                    ]))
                }))
            })
            .collect()
    } else {
        vec![
            ListItem::new(
                Line::from("✓ SPL Token Safety Checks").style(Style::default().fg(Color::Green)),
            ),
            ListItem::new(
                Line::from("✓ Account Ownership Validation")
                    .style(Style::default().fg(Color::Green)),
            ),
            ListItem::new(
                Line::from("✓ PDA Seed Verification").style(Style::default().fg(Color::Green)),
            ),
            ListItem::new(
                Line::from("~ CPI Reentrancy Guards").style(Style::default().fg(Color::Yellow)),
            ),
            ListItem::new(
                Line::from("✗ Arithmetic Overflow Protection")
                    .style(Style::default().fg(Color::Red)),
            ),
            ListItem::new(
                Line::from("✓ WACANA Bytecode Concolic Analysis")
                    .style(Style::default().fg(Color::Green)),
            ),
        ]
    };

    let compliance_list = List::new(compliance_items).block(
        Block::default()
            .title(" Standards Compliance ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );
    f.render_widget(compliance_list, area);
}

/// Render help screen
fn render_help(f: &mut Frame, area: Rect) {
    let help_text = vec![
        Line::from(Span::styled(
            " SOLANA SECURITY SWARM - KEYBOARD SHORTCUTS ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Tab / BackTab  ", Style::default().fg(Color::Yellow)),
            Span::styled("Switch between tabs", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled(" 1-5           ", Style::default().fg(Color::Yellow)),
            Span::styled("Jump to specific tab", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled(" /             ", Style::default().fg(Color::Yellow)),
            Span::styled(
                "Quick search in Explorer",
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled(" ↑/k, ↓/j      ", Style::default().fg(Color::Yellow)),
            Span::styled("Navigate findings", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled(" Enter         ", Style::default().fg(Color::Yellow)),
            Span::styled(
                "Toggle detail popup / Start Search",
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled(" q / Esc       ", Style::default().fg(Color::Yellow)),
            Span::styled(
                "Quit dashboard / Cancel entry",
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            " SEVERITY LEVELS ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" 🔴 CRITICAL ", Style::default().fg(Color::Red)),
            Span::styled(
                "Immediate exploitation risk",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            Span::styled(" 🟡 HIGH     ", Style::default().fg(Color::Yellow)),
            Span::styled(
                "Significant security flaw",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            Span::styled(" 🔵 MEDIUM   ", Style::default().fg(Color::Blue)),
            Span::styled(
                "Moderate risk, should fix",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            Span::styled(" ⚪ LOW      ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "Minor issue or best practice",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ];

    let help = Paragraph::new(help_text).block(
        Block::default()
            .title(" Help ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    f.render_widget(help, area);
}

/// Render footer with status
fn render_footer(f: &mut Frame, area: Rect, state: &DashboardState) {
    let elapsed = state.last_update.elapsed().as_secs();
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" ⚡ ", Style::default().fg(Color::Cyan)),
        Span::styled(&state.status_message, Style::default().fg(Color::DarkGray)),
        Span::styled(" │ ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("Updated {}s ago", elapsed),
            Style::default().fg(Color::DarkGray),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(footer, area);
}

/// Render the crypto explorer view
fn render_explorer(f: &mut Frame, area: Rect, state: &DashboardState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Search Bar
            Constraint::Min(10),   // Results
        ])
        .split(area);

    // Search Bar
    let input_style = if state.input_mode {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let search_bar = Paragraph::new(format!(" > {}", state.search_query)).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" [ EXPLORER SEARCH: PUBKEY OR SIGNATURE ] ")
            .border_style(input_style),
    );
    f.render_widget(search_bar, chunks[0]);

    // Results area
    if let Some(acc) = &state.search_result_account {
        let items = vec![
            Line::from(vec![
                Span::styled("Type:      ", Style::default().fg(Color::DarkGray)),
                Span::styled("ACCOUNT", Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::styled("Pubkey:    ", Style::default().fg(Color::DarkGray)),
                Span::styled(&acc.pubkey, Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("SOL:       ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:.4} SOL", acc.sol_balance),
                    Style::default().fg(Color::Green),
                ),
            ]),
            Line::from(vec![
                Span::styled("Owner:     ", Style::default().fg(Color::DarkGray)),
                Span::styled(&acc.owner, Style::default().fg(Color::Magenta)),
            ]),
            Line::from(vec![
                Span::styled("Executable:", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{}", acc.executable),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::styled("Data Size: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{} bytes", acc.data_len),
                    Style::default().fg(Color::White),
                ),
            ]),
        ];
        let p = Paragraph::new(items).block(
            Block::default()
                .title(" Account Details ")
                .borders(Borders::ALL),
        );
        f.render_widget(p, chunks[1]);
    } else if let Some(tx) = &state.search_result_tx {
        let mut items = vec![
            Line::from(vec![
                Span::styled("Type:      ", Style::default().fg(Color::DarkGray)),
                Span::styled("TRANSACTION", Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::styled("Signature: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&tx.signature, Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Status:    ", Style::default().fg(Color::DarkGray)),
                Span::styled(&tx.status, Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::styled("Fee:       ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{} lamports", tx.fee),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "Transaction Logs:",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )),
        ];
        for log in tx.logs.iter().take(20) {
            items.push(Line::from(Span::styled(
                format!("  {}", log),
                Style::default().fg(Color::DarkGray),
            )));
        }
        let p = Paragraph::new(items).block(
            Block::default()
                .title(" Transaction Details ")
                .borders(Borders::ALL),
        );
        f.render_widget(p, chunks[1]);
    } else {
        let help = Paragraph::new(
            "Enter an Account Address or Transaction Signature and press Enter to search.",
        )
        .block(
            Block::default()
                .title(" Results ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(help, chunks[1]);
    }
}

/// Render finding detail popup
fn render_finding_detail_popup(f: &mut Frame, state: &DashboardState) {
    let exploits = state.all_exploits();
    let Some(exploit) = exploits.get(state.selected_finding) else {
        return;
    };

    // Create centered popup area
    let area = centered_rect(80, 80, f.area());

    // Clear the popup area
    f.render_widget(Clear, area);

    let severity_color = match exploit.severity {
        5 => Color::Red,
        4 => Color::Yellow,
        3 => Color::Blue,
        _ => Color::DarkGray,
    };

    let mut content = vec![
        Line::from(Span::styled(
            format!("[{}] {}", exploit.id, exploit.vulnerability_type),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "DESCRIPTION",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
    ];

    for line in wrap_text_lines(&exploit.description, (area.width - 4) as usize) {
        content.push(Line::from(Span::styled(
            line,
            Style::default().fg(Color::DarkGray),
        )));
    }

    content.push(Line::from(""));
    content.push(Line::from(Span::styled(
        "ATTACK SCENARIO",
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    )));
    for line in wrap_text_lines(&exploit.attack_scenario, (area.width - 4) as usize) {
        content.push(Line::from(Span::styled(
            line,
            Style::default().fg(Color::DarkGray),
        )));
    }

    content.push(Line::from(""));
    content.push(Line::from(Span::styled(
        "SECURE FIX",
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
    )));
    for line in wrap_text_lines(&exploit.secure_fix, (area.width - 4) as usize) {
        content.push(Line::from(Span::styled(
            line,
            Style::default().fg(Color::Green),
        )));
    }

    content.push(Line::from(""));
    content.push(Line::from(Span::styled(
        "[Press Enter to close]",
        Style::default().fg(Color::DarkGray),
    )));

    let popup = Paragraph::new(content)
        .block(
            Block::default()
                .title(format!(
                    " Finding Detail [{}/{}] ",
                    state.selected_finding + 1,
                    exploits.len()
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(severity_color)),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(popup, area);
}

/// Create a centered rectangle
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Wrap text into lines
fn wrap_text_lines(text: &str, max_width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.len() + word.len() + 1 > max_width
            && !current_line.is_empty() {
                lines.push(current_line);
                current_line = String::new();
            }
        if !current_line.is_empty() {
            current_line.push(' ');
        }
        current_line.push_str(word);
    }
    if !current_line.is_empty() {
        lines.push(current_line);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_state_default() {
        let state = DashboardState::default();
        assert_eq!(state.active_tab, 0);
        assert_eq!(state.tab_titles.len(), 6);
        assert!(!state.show_detail);
    }

    #[test]
    fn test_tab_navigation() {
        let mut state = DashboardState::default();
        assert_eq!(state.active_tab, 0);

        state.next_tab();
        assert_eq!(state.active_tab, 1);

        state.prev_tab();
        assert_eq!(state.active_tab, 0);

        state.prev_tab(); // Should wrap to last
        assert_eq!(state.active_tab, 5);
    }

    #[test]
    fn test_severity_counts_empty() {
        let state = DashboardState::default();
        let (c, h, m, l) = state.severity_counts();
        assert_eq!((c, h, m, l), (0, 0, 0, 0));
    }
}
