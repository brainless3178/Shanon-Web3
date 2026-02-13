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
        status: 'Operational',
        engine_version: 'v4.2.1-prod',
        last_scan: vaultReport.timestamp || new Date().toISOString(),
        network: vaultReport.network_status || 'Mainnet-Beta',
        consensus_active: true,
        analyzers: [
            { name: 'Static Analysis', status: 'online' },
            { name: 'Taint Engine', status: 'online' },
            { name: 'Formal Prover', status: 'online' },
            { name: 'Fuzzer', status: 'online' },
            { name: 'Kimi AI Consensus', status: 'online' }
        ]
    });
};
