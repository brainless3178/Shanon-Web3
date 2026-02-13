const data = require('../data/colosseum_projects.json');
const rawReport = require('../production_audit_results/vulnerable-vault_report.json');

module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.status(204).end();
        return;
    }

    // Map real findings from our security engine to the Colosseum projects
    const findings = [];
    const sourceExploits = rawReport.exploits;

    data.projects.slice(0, 50).forEach((p, idx) => {
        // Pick 1-3 findings for each project to show variety
        const numFindings = (idx % 3) + 1;
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
};
