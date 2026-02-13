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
        total_alerts: 2,
        active_monitors: 12,
        alerts: [
            {
                timestamp: new Date().toISOString(),
                description: 'Unusual withdrawal pattern on vulnerable-vault',
                severity: 'high',
                transaction_signature: '5xY...8sP',
                resolved: false
            },
            {
                timestamp: new Date().toISOString(),
                description: 'Anomalous transfer pattern detected in Vault-A',
                severity: 'medium',
                transaction_signature: '2zP...9qR',
                resolved: false
            }
        ]
    });
};
