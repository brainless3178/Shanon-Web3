module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.status(204).end();
        return;
    }

    res.status(200).json({
        average_coverage: 87.3,
        total_iterations: 1250000,
        total_crashes: 1,
        total_campaigns: 2,
        campaigns: [
            {
                id: 'FZ-001',
                target: 'vulnerable-vault',
                status: 'stopped',
                coverage_percent: 92,
                iterations: 850000,
                crashes_found: 1,
                unique_paths: 450,
                duration_seconds: 8100
            },
            {
                id: 'FZ-002',
                target: 'vulnerable-token',
                status: 'running',
                coverage_percent: 45,
                iterations: 400000,
                crashes_found: 0,
                unique_paths: 120,
                duration_seconds: 2700
            }
        ]
    });
};
