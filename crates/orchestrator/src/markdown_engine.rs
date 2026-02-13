use crate::audit_pipeline::AuditReport;

pub struct MarkdownEngine;

impl MarkdownEngine {
    pub fn generate_audit_report(report: &AuditReport) -> String {
        let mut md = String::from("# 🛡️ PROFESSIONAL SECURITY AUDIT REPORT\n\n");

        md.push_str(&format!(
            "## **Overall Risk Score: {:.1}/10.0**\n\n",
            report.overall_risk_score
        ));
        md.push_str(&format!(
            "### **Total Value at Risk (TVR): ${:.2}M USD** 💰\n\n",
            report.total_value_at_risk_usd
        ));

        md.push_str(&format!(
            "- **Critical Issues:** {} 🔴\n",
            report.critical_count
        ));
        md.push_str(&format!("- **High Issues:** {} 🟠\n", report.high_count));
        md.push_str(&format!(
            "- **Medium Issues:** {} 🟡\n",
            report.medium_count
        ));
        md.push_str("- **Status:** CONNECTED (mainnet-beta) 🌐\n\n");

        md.push_str("## **Executive Summary**\n");
        if let Some(advice) = &report.deployment_advice {
            md.push_str(&format!("> {}\n\n", advice));
        }

        md.push_str("### **Model Consensus Breakdown**\n");
        md.push_str("| Model | Consensus | Reasoning |\n");
        md.push_str("|-------|-----------|-----------|\n");
        for (name, verified, reason) in &report.model_consensus {
            let status = if *verified {
                "✅ Verified"
            } else {
                "❌ Flagged"
            };
            md.push_str(&format!("| {} | {} | {} |\n", name, status, reason));
        }
        md.push('\n');

        md.push_str("## **Detailed Findings**\n\n");

        for (i, exploit) in report.exploits.iter().enumerate() {
            md.push_str(&format!(
                "### Finding #{:02}: {} - {}\n\n",
                i + 1,
                exploit.id,
                exploit.vulnerability_type
            ));
            md.push_str(&format!(
                "- **Severity:** {} ({}/5)\n",
                exploit.severity_label, exploit.severity
            ));
            md.push_str(&format!(
                "- **Confidence:** {}% ({} Priority)\n",
                exploit.confidence_score, exploit.risk_priority
            ));
            md.push_str("- **Confidence Reasoning:**\n");
            for reason in &exploit.confidence_reasoning {
                md.push_str(&format!("  - {}\n", reason));
            }
            md.push('\n');

            md.push_str(&format!(
                "- **Location:** `{}`\n",
                exploit.location().unwrap_or_else(|| "Unknown".into())
            ));
            md.push_str(&format!(
                "- **Value at Risk:** ${:.2}M USD\n",
                exploit.value_at_risk_usd
            ));
            md.push_str(&format!(
                "- **Exploit Gas Estimate:** {:.5} SOL\n\n",
                exploit.exploit_gas_estimate as f64 / 1e9
            ));

            md.push_str("#### **Vulnerability Description**\n");
            md.push_str(&format!("{}\n\n", exploit.description));

            md.push_str("#### **Exploit Attack Steps**\n");
            for (step_idx, step) in exploit.exploit_steps.iter().enumerate() {
                md.push_str(&format!("{}. {}\n", step_idx + 1, step));
            }
            md.push('\n');

            if let Some(precedent) = &exploit.historical_hack_context {
                md.push_str("#### **Historical Context**\n");
                md.push_str(&format!("> {}\n\n", precedent));
            }

            md.push_str("#### **Suggested Remediation**\n");
            if let Some(diff) = &exploit.mitigation_diff {
                md.push_str("```diff\n");
                md.push_str(diff);
                md.push_str("\n```\n\n");
            } else {
                md.push_str("```rust\n");
                md.push_str(&exploit.secure_fix);
                md.push_str("\n```\n\n");
            }

            if let Some(receipt) = &exploit.proof_receipt {
                md.push_str("#### **Proof of Exploit (Receipt)**\n");
                md.push_str("| Field | Value |\n");
                md.push_str("|-------|-------|\n");
                md.push_str(&format!(
                    "| **TX Signature** | `{}` |\n",
                    receipt.transaction_signature
                ));
                md.push_str(&format!(
                    "| **Funds Drained** | {:.2} SOL |\n",
                    receipt.funds_drained_lamports as f64 / 1e9
                ));
                md.push_str(&format!(
                    "| **Actual Gas** | {:.5} SOL |\n",
                    receipt.actual_gas_cost as f64 / 1e9
                ));
                md.push('\n');
                md.push_str("**Execution Logs:**\n");
                for log in &receipt.execution_logs {
                    md.push_str(&format!("- `{}`\n", log));
                }
                md.push('\n');
            }

            md.push_str("---\n\n");
        }

        md.push_str("## **Standards Compliance Checklist**\n");
        for (group, results) in &report.standards_compliance {
            md.push_str(&format!("### {}\n", group));
            for (name, passed) in results {
                let status = if *passed { "✅" } else { "❌" };
                md.push_str(&format!("- {} {}\n", status, name));
            }
            md.push('\n');
        }

        md.push_str("## **Recommendations**\n");
        md.push_str("1. **IMMEDIATE:** Apply fixes for all critical vulnerabilities identified in the Triage Priority Queue.\n");
        md.push_str("2. **VERIFICATION:** Run `swarm audit --verify-fix` after applying changes to ensure regressions are not introduced.\n");
        md.push_str("3. **CONTINUOUS:** Integrate this SARIF output into your GitHub Actions for per-PR security verification.\n\n");

        md.push_str("---\n");
        md.push_str(&format!("*Report generated at: {}*\n", report.timestamp));
        md.push_str(&format!("*Command used: `{}`*\n", report.scan_command));

        md
    }
}

// Helper trait to get location if needed
trait ExploitExt {
    fn location(&self) -> Option<String>;
}

impl ExploitExt for crate::audit_pipeline::ConfirmedExploit {
    fn location(&self) -> Option<String> {
        Some(format!("{}:{}", self.instruction, self.line_number))
    }
}
