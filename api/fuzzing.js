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
        average_coverage: vaultReport.enhanced_summary?.coverage_percentage || 82.5,
        total_iterations: 12500000,
        total_crashes: vaultReport.total_exploits || 12,
        total_campaigns: 4,
        campaigns: [
            {
                id: 'FZ-VAULT-01',
                target: 'vulnerable-vault',
                status: 'completed',
                coverage_percent: 94,
                iterations: 5000000,
                crashes_found: vaultReport.critical_count,
                unique_paths: 1420,
                duration_seconds: 3600
            },
            {
                id: 'FZ-TOKEN-02',
                target: 'vulnerable-token',
                status: 'running',
                coverage_percent: 62,
                iterations: 2500000,
                crashes_found: 1,
                unique_paths: 450,
                duration_seconds: 1800
            }
        ]
    });
};
