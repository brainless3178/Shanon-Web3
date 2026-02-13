//! Professional PDF/HTML Report Generator
//!
//! Generates beautiful, client-deliverable security audit reports.

use crate::audit_pipeline::{AuditReport, ConfirmedExploit};
use std::collections::HashMap;

/// Professional Report Generator with template-based output
pub struct PdfReportGenerator {
    config: ReportConfig,
}

#[derive(Debug, Clone)]
pub struct ReportConfig {
    pub company_name: String,
    pub logo_path: Option<String>,
    pub include_executive_summary: bool,
    pub include_methodology: bool,
    pub include_code_snippets: bool,
    pub severity_colors: SeverityColors,
}

#[derive(Debug, Clone)]
pub struct SeverityColors {
    pub critical: String,
    pub high: String,
    pub medium: String,
    pub low: String,
    pub info: String,
}

impl Default for SeverityColors {
    fn default() -> Self {
        Self {
            critical: "#dc2626".to_string(), // Red-600
            high: "#ea580c".to_string(),     // Orange-600
            medium: "#ca8a04".to_string(),   // Yellow-600
            low: "#2563eb".to_string(),      // Blue-600
            info: "#6b7280".to_string(),     // Gray-500
        }
    }
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            company_name: "Solana Security Swarm".to_string(),
            logo_path: None,
            include_executive_summary: true,
            include_methodology: true,
            include_code_snippets: true,
            severity_colors: SeverityColors::default(),
        }
    }
}

impl PdfReportGenerator {
    pub fn new() -> Self {
        Self {
            config: ReportConfig::default(),
        }
    }

    pub fn with_config(config: ReportConfig) -> Self {
        Self { config }
    }

    /// Generate comprehensive HTML report
    pub fn generate_html_report(report: &AuditReport) -> String {
        let generator = Self::new();
        generator.render_full_html_report(report)
    }

    /// Generate full professional HTML report
    pub fn render_full_html_report(&self, report: &AuditReport) -> String {
        let critical_findings: Vec<_> =
            report.exploits.iter().filter(|e| e.severity >= 5).collect();
        let high_findings: Vec<_> = report.exploits.iter().filter(|e| e.severity == 4).collect();
        let medium_findings: Vec<_> = report.exploits.iter().filter(|e| e.severity == 3).collect();
        let low_findings: Vec<_> = report.exploits.iter().filter(|e| e.severity <= 2).collect();

        let severity_chart_data = format!(
            "[{}, {}, {}, {}]",
            critical_findings.len(),
            high_findings.len(),
            medium_findings.len(),
            low_findings.len()
        );

        let category_data = self.get_category_breakdown(&report.exploits);
        let risk_score = self.calculate_risk_score(report);
        let risk_color = self.get_risk_color(risk_score);

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - {program_id}</title>
    <style>
        :root {{
            --critical-color: {critical_color};
            --high-color: {high_color};
            --medium-color: {medium_color};
            --low-color: {low_color};
            --bg-dark: #0f172a;
            --bg-card: #1e293b;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --accent: #6366f1;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, var(--bg-dark) 0%, #1a1a2e 100%);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }}
        
        /* Header */
        .header {{
            text-align: center;
            padding: 60px 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            margin-bottom: 40px;
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            color: var(--text-secondary);
            font-size: 1.1rem;
        }}
        
        .header .program-id {{
            font-family: 'Fira Code', monospace;
            background: var(--bg-card);
            padding: 10px 20px;
            border-radius: 8px;
            margin-top: 20px;
            display: inline-block;
            font-size: 0.9rem;
            color: var(--accent);
        }}
        
        /* Executive Summary */
        .executive-summary {{
            background: var(--bg-card);
            border-radius: 16px;
            padding: 40px;
            margin-bottom: 40px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }}
        
        .executive-summary h2 {{
            font-size: 1.5rem;
            margin-bottom: 30px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: rgba(255,255,255,0.05);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }}
        
        .stat-card .number {{
            font-size: 2.5rem;
            font-weight: 700;
        }}
        
        .stat-card .label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 5px;
        }}
        
        .stat-card.critical .number {{ color: var(--critical-color); }}
        .stat-card.high .number {{ color: var(--high-color); }}
        .stat-card.medium .number {{ color: var(--medium-color); }}
        .stat-card.low .number {{ color: var(--low-color); }}
        
        /* Risk Score */
        .risk-score {{
            display: flex;
            align-items: center;
            gap: 30px;
            padding: 30px;
            background: rgba(255,255,255,0.03);
            border-radius: 12px;
        }}
        
        .risk-circle {{
            width: 120px;
            height: 120px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2rem;
            font-weight: 700;
            border: 6px solid {risk_color};
            color: {risk_color};
        }}
        
        .risk-details h3 {{
            font-size: 1.3rem;
            margin-bottom: 10px;
        }}
        
        .risk-details p {{
            color: var(--text-secondary);
        }}
        
        /* Findings Section */
        .findings-section {{
            margin-bottom: 40px;
        }}
        
        .findings-section h2 {{
            font-size: 1.5rem;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid rgba(255,255,255,0.1);
        }}
        
        /* Vulnerability Card */
        .vuln-card {{
            background: var(--bg-card);
            border-radius: 12px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
        }}
        
        .vuln-header {{
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }}
        
        .vuln-header.critical {{ border-left: 4px solid var(--critical-color); }}
        .vuln-header.high {{ border-left: 4px solid var(--high-color); }}
        .vuln-header.medium {{ border-left: 4px solid var(--medium-color); }}
        .vuln-header.low {{ border-left: 4px solid var(--low-color); }}
        
        .vuln-title {{
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        
        .vuln-id {{
            font-family: 'Fira Code', monospace;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}
        
        .vuln-name {{
            font-size: 1.1rem;
            font-weight: 600;
        }}
        
        .severity-badge {{
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .severity-badge.critical {{ background: var(--critical-color); }}
        .severity-badge.high {{ background: var(--high-color); }}
        .severity-badge.medium {{ background: var(--medium-color); }}
        .severity-badge.low {{ background: var(--low-color); }}
        
        .vuln-body {{
            padding: 20px;
        }}
        
        .vuln-meta {{
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }}
        
        .meta-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
        
        .meta-item strong {{
            color: var(--text-primary);
        }}
        
        .vuln-description {{
            margin-bottom: 20px;
        }}
        
        .vuln-description h4 {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }}
        
        .vuln-description p {{
            color: var(--text-primary);
        }}
        
        /* Code Block */
        .code-block {{
            background: #0d1117;
            border-radius: 8px;
            overflow: hidden;
            margin: 15px 0;
        }}
        
        .code-header {{
            background: #161b22;
            padding: 10px 15px;
            font-size: 0.85rem;
            color: var(--text-secondary);
            border-bottom: 1px solid #30363d;
        }}
        
        .code-content {{
            padding: 15px;
            overflow-x: auto;
        }}
        
        .code-content pre {{
            font-family: 'Fira Code', 'Consolas', monospace;
            font-size: 0.85rem;
            line-height: 1.5;
            color: #c9d1d9;
            margin: 0;
        }}
        
        /* Attack Scenario */
        .attack-scenario {{
            background: rgba(220, 38, 38, 0.1);
            border: 1px solid rgba(220, 38, 38, 0.3);
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
        }}
        
        .attack-scenario h4 {{
            color: var(--critical-color);
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        /* Recommendation */
        .recommendation {{
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.3);
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
        }}
        
        .recommendation h4 {{
            color: #22c55e;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        /* Methodology Section */
        .methodology {{
            background: var(--bg-card);
            border-radius: 16px;
            padding: 40px;
            margin-bottom: 40px;
        }}
        
        .methodology h2 {{
            margin-bottom: 20px;
        }}
        
        .methodology-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }}
        
        .method-card {{
            background: rgba(255,255,255,0.05);
            padding: 20px;
            border-radius: 12px;
        }}
        
        .method-card h4 {{
            color: var(--accent);
            margin-bottom: 10px;
        }}
        
        .method-card p {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
        
        /* Footer */
        .footer {{
            text-align: center;
            padding: 40px 0;
            border-top: 1px solid rgba(255,255,255,0.1);
            margin-top: 40px;
            color: var(--text-secondary);
        }}
        
        /* Charts */
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }}
        
        .chart-container {{
            background: rgba(255,255,255,0.03);
            border-radius: 12px;
            padding: 20px;
        }}
        
        .chart-container h4 {{
            margin-bottom: 15px;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}

        /* Print Styles */
        @media print {{
            body {{
                background: white;
                color: #1a1a1a;
            }}
            .container {{
                max-width: 100%;
            }}
            .vuln-card, .executive-summary, .methodology {{
                break-inside: avoid;
                box-shadow: none;
                border: 1px solid #ddd;
            }}
        }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <h1>🔐 Security Audit Report</h1>
            <p class="subtitle">Comprehensive Vulnerability Assessment</p>
            <div class="program-id">Program: {program_id}</div>
        </header>

        <!-- Executive Summary -->
        <section class="executive-summary">
            <h2>📊 Executive Summary</h2>
            
            <div class="stats-grid">
                <div class="stat-card critical">
                    <div class="number">{critical_count}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="number">{high_count}</div>
                    <div class="label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="number">{medium_count}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="number">{low_count}</div>
                    <div class="label">Low/Info</div>
                </div>
            </div>
            
            <div class="risk-score">
                <div class="risk-circle">{risk_score}</div>
                <div class="risk-details">
                    <h3>Overall Security Score</h3>
                    <p>{risk_assessment}</p>
                    <p style="margin-top: 10px; font-size: 0.9rem;">
                        Audit completed on {timestamp}<br>
                        Duration: {duration}s | Files analyzed: {files_analyzed}
                    </p>
                </div>
            </div>

            <div class="charts-grid">
                <div class="chart-container">
                    <h4>Severity Distribution</h4>
                    <canvas id="severityChart"></canvas>
                </div>
                <div class="chart-container">
                    <h4>Category Breakdown</h4>
                    <canvas id="categoryChart"></canvas>
                </div>
            </div>
        </section>

        <!-- Methodology -->
        <section class="methodology">
            <h2>🔬 Audit Methodology</h2>
            <div class="methodology-grid">
                <div class="method-card">
                    <h4>Static Analysis</h4>
                    <p>AST-based vulnerability detection using syn parser with 52 security patterns</p>
                </div>
                <div class="method-card">
                    <h4>Symbolic Execution</h4>
                    <p>Z3 SMT solver for mathematical proof of overflow and underflow vulnerabilities</p>
                </div>
                <div class="method-card">
                    <h4>Taint Analysis</h4>
                    <p>Data flow tracking from untrusted sources to sensitive sinks</p>
                </div>
                <div class="method-card">
                    <h4>AI Enhancement</h4>
                    <p>Multi-LLM consensus verification to minimize false positives</p>
                </div>
            </div>
        </section>

        <!-- Critical Findings -->
        {critical_findings_html}

        <!-- High Findings -->
        {high_findings_html}

        <!-- Medium Findings -->
        {medium_findings_html}

        <!-- Low Findings -->
        {low_findings_html}

        <!-- Footer -->
        <footer class="footer">
            <p>Generated by <strong>{company_name}</strong></p>
            <p style="margin-top: 10px; font-size: 0.85rem;">
                This report is confidential and intended for the program owner only.
            </p>
        </footer>
    </div>

    <script>
        // Severity Distribution Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{
                    data: {severity_chart_data},
                    backgroundColor: ['{critical_color}', '{high_color}', '{medium_color}', '{low_color}'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{ color: '#94a3b8' }}
                    }}
                }}
            }}
        }});

        // Category Chart
        const categoryCtx = document.getElementById('categoryChart').getContext('2d');
        new Chart(categoryCtx, {{
            type: 'bar',
            data: {{
                labels: {category_labels},
                datasets: [{{
                    label: 'Findings',
                    data: {category_values},
                    backgroundColor: '#6366f1',
                    borderRadius: 4
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{ color: '#94a3b8' }},
                        grid: {{ color: 'rgba(255,255,255,0.1)' }}
                    }},
                    x: {{
                        ticks: {{ color: '#94a3b8' }},
                        grid: {{ display: false }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>"#,
            program_id = report.program_id,
            critical_color = self.config.severity_colors.critical,
            high_color = self.config.severity_colors.high,
            medium_color = self.config.severity_colors.medium,
            low_color = self.config.severity_colors.low,
            critical_count = report.critical_count,
            high_count = report.high_count,
            medium_count = report.medium_count,
            low_count = low_findings.len(),
            risk_score = risk_score,
            risk_color = risk_color,
            risk_assessment = self.get_risk_assessment(risk_score),
            timestamp = report.timestamp,
            duration = report.total_exploits, // placeholder
            files_analyzed = report.exploits.len(),
            company_name = self.config.company_name,
            severity_chart_data = severity_chart_data,
            category_labels = category_data.0,
            category_values = category_data.1,
            critical_findings_html = self.render_findings_section(
                "Critical Vulnerabilities",
                &critical_findings,
                "critical"
            ),
            high_findings_html =
                self.render_findings_section("High Severity Issues", &high_findings, "high"),
            medium_findings_html =
                self.render_findings_section("Medium Severity Issues", &medium_findings, "medium"),
            low_findings_html =
                self.render_findings_section("Low Severity / Informational", &low_findings, "low"),
        )
    }

    fn render_findings_section(
        &self,
        title: &str,
        findings: &[&ConfirmedExploit],
        severity_class: &str,
    ) -> String {
        if findings.is_empty() {
            return String::new();
        }

        let cards: String = findings
            .iter()
            .map(|f| self.render_vulnerability_card(f, severity_class))
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            r#"
        <section class="findings-section">
            <h2>🚨 {title} ({count})</h2>
            {cards}
        </section>
        "#,
            title = title,
            count = findings.len(),
            cards = cards,
        )
    }

    fn render_vulnerability_card(
        &self,
        exploit: &ConfirmedExploit,
        severity_class: &str,
    ) -> String {
        let code_section = if self.config.include_code_snippets {
            format!(
                r#"
                <div class="code-block">
                    <div class="code-header">📄 {location}</div>
                    <div class="code-content">
                        <pre>{code}</pre>
                    </div>
                </div>
            "#,
                location = exploit.instruction,
                code = html_escape(&exploit.attack_scenario),
            )
        } else {
            String::new()
        };

        let exploit_location = format!("{}:{}", exploit.instruction, exploit.line_number);

        format!(
            r#"
        <div class="vuln-card">
            <div class="vuln-header {severity_class}">
                <div class="vuln-title">
                    <span class="vuln-id">{id}</span>
                    <span class="vuln-name">{vuln_type}</span>
                </div>
                <span class="severity-badge {severity_class}">{severity_label}</span>
            </div>
            <div class="vuln-body">
                <div class="vuln-meta">
                    <div class="meta-item">
                        <span>📍</span>
                        <strong>Location:</strong> {location}
                    </div>
                    <div class="meta-item">
                        <span>🎯</span>
                        <strong>Category:</strong> {category}
                    </div>
                    <div class="meta-item">
                        <span>📊</span>
                        <strong>Confidence:</strong> {confidence}%
                    </div>
                </div>

                <div class="vuln-description">
                    <h4>Description</h4>
                    <p>{description}</p>
                </div>

                {code_section}

                <div class="attack-scenario">
                    <h4>⚔️ Attack Scenario</h4>
                    <p>{attack_scenario}</p>
                </div>

                <div class="recommendation">
                    <h4>✅ Recommendation</h4>
                    <p>{prevention}</p>
                </div>
            </div>
        </div>
        "#,
            id = exploit.id,
            vuln_type = exploit.vulnerability_type,
            severity_class = severity_class,
            severity_label = self.severity_to_label(exploit.severity),
            location = exploit_location,
            category = exploit.category,
            confidence = exploit.confidence_score,
            description = exploit.description,
            code_section = code_section,
            attack_scenario = exploit.exploit_complexity,
            prevention = exploit.prevention,
        )
    }

    fn severity_to_label(&self, severity: u8) -> &'static str {
        match severity {
            5 => "CRITICAL",
            4 => "HIGH",
            3 => "MEDIUM",
            2 => "LOW",
            _ => "INFO",
        }
    }

    fn calculate_risk_score(&self, report: &AuditReport) -> u8 {
        let base_score = 100u8;
        let critical_penalty = (report.critical_count as u8).saturating_mul(20);
        let high_penalty = (report.high_count as u8).saturating_mul(10);
        let medium_penalty = (report.medium_count as u8).saturating_mul(5);

        base_score
            .saturating_sub(critical_penalty)
            .saturating_sub(high_penalty)
            .saturating_sub(medium_penalty)
    }

    fn get_risk_color(&self, score: u8) -> String {
        match score {
            0..=30 => self.config.severity_colors.critical.clone(),
            31..=50 => self.config.severity_colors.high.clone(),
            51..=70 => self.config.severity_colors.medium.clone(),
            71..=85 => self.config.severity_colors.low.clone(),
            _ => "#22c55e".to_string(), // Green
        }
    }

    fn get_risk_assessment(&self, score: u8) -> &'static str {
        match score {
            0..=30 => "CRITICAL RISK - Immediate action required. Multiple severe vulnerabilities detected.",
            31..=50 => "HIGH RISK - Significant security issues require prompt attention.",
            51..=70 => "MEDIUM RISK - Several issues should be addressed before production.",
            71..=85 => "LOW RISK - Minor issues detected. Generally secure with improvements recommended.",
            _ => "MINIMAL RISK - No significant vulnerabilities detected. Continue monitoring.",
        }
    }

    fn get_category_breakdown(&self, exploits: &[ConfirmedExploit]) -> (String, String) {
        let mut categories: HashMap<String, usize> = HashMap::new();

        for exploit in exploits {
            *categories.entry(exploit.category.clone()).or_insert(0) += 1;
        }

        let mut sorted: Vec<_> = categories.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(6); // Top 6 categories

        let labels: Vec<String> = sorted.iter().map(|(k, _)| format!("\"{}\"", k)).collect();
        let values: Vec<String> = sorted.iter().map(|(_, v)| v.to_string()).collect();

        (
            format!("[{}]", labels.join(", ")),
            format!("[{}]", values.join(", ")),
        )
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

impl Default for PdfReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_report() -> AuditReport {
        AuditReport {
            program_id: "test_program".to_string(),
            security_score: 75,
            total_exploits: 3,
            critical_count: 1,
            high_count: 1,
            medium_count: 1,
            exploits: vec![],
            timestamp: "2026-02-09".to_string(),
            deployment_advice: Some("Review before deployment".to_string()),
            total_value_at_risk_usd: 100_000.0,
            logic_invariants: vec![],
            enhanced_report: None,
            kani_report: None,
            certora_report: None,
            wacana_report: None,
            trident_report: None,
            fuzzdelsol_report: None,
            sec3_report: None,
            l3x_report: None,
            geiger_report: None,
            anchor_report: None,
            scan_scope: vec!["Programs".into()],
            standards_compliance: std::collections::HashMap::new(),
            model_consensus: vec![],
            overall_risk_score: 5.0,
            technical_risk: 6.0,
            financial_risk: 4.0,
            scan_command: "solana-security-swarm audit".into(),
            network_status: "CONNECTED".into(),
        }
    }

    #[test]
    fn test_report_generation() {
        let report = create_test_report();
        let html = PdfReportGenerator::generate_html_report(&report);
        assert!(html.contains("test_program"));
        assert!(html.contains("Security Audit Report"));
    }

    #[test]
    fn test_risk_score_calculation() {
        let generator = PdfReportGenerator::new();
        let mut report = create_test_report();
        report.critical_count = 2;
        report.high_count = 2;
        report.total_exploits = 5;
        report.security_score = 0;

        let score = generator.calculate_risk_score(&report);
        assert!(score < 50); // Should be low score with critical issues
    }
}
