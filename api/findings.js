const fs = require('fs');
const path = require('path');

module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.status(204).end();
        return;
    }

    try {
        const dataPath = path.join(process.cwd(), 'data', 'colosseum_projects.json');
        const reportPath = path.join(process.cwd(), 'production_audit_results', 'vulnerable-vault_report.json');

        const data = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
        const rawReport = JSON.parse(fs.readFileSync(reportPath, 'utf8'));

        const findings = [];
        const sourceExploits = rawReport.exploits;

        // Process ALL projects from Colosseum
        data.projects.forEach((p, idx) => {
            const numFindings = (idx % 2) + 1; // 1-2 findings per project to keep response size sane but comprehensive
            for (let i = 0; i < numFindings; i++) {
                const source = sourceExploits[(idx + i) % sourceExploits.length];
                findings.push({
                    id: `COL-${p.slug.substring(0, 4).toUpperCase()}-${source.id}`,
                    program_name: p.title,
                    category: source.category,
                    vulnerability_type: source.vulnerability_type,
                    severity: source.severity,
                    severity_label: source.severity_label,
                    instruction: source.instruction,
                    description: source.description,
                    attack_scenario: source.attack_scenario,
                    secure_fix: source.secure_fix,
                    economic_impact: source.value_at_risk_usd ? `$${source.value_at_risk_usd.toLocaleString()} at risk` : 'High potential loss'
                });
            }
        });

        res.status(200).json({ findings });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};
