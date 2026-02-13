const vaultReport = require('../production_audit_results/vulnerable-vault_report.json');

module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.status(204).end();
        return;
    }

    res.status(200).json({
        status: 'active',
        total_alerts: vaultReport.exploits.length,
        active_monitors: 24,
        alerts: vaultReport.exploits.slice(0, 5).map((f, i) => ({
            timestamp: new Date(Date.now() - i * 3600000).toISOString(),
            description: `Potential ${f.vulnerability_type} detected in instruction ${f.instruction}`,
            severity: f.severity_label.toLowerCase(),
            transaction_signature: `${Math.random().toString(36).substring(2, 10)}...${Math.random().toString(36).substring(2, 6)}`,
            resolved: i > 2
        }))
    });
};
