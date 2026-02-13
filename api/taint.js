const vaultReport = require('../production_audit_results/vulnerable-vault_report.json');

module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.status(204).end();
        return;
    }

    // Derive taint nodes and edges from real arithmetic and logic findings
    const findings = vaultReport.exploits.slice(0, 10);
    const nodes = [
        { id: 'user_input', label: 'User Instruction Data', type: 'source', color: '#ff4757' },
        { id: 'instr_handler', label: 'Instruction Handler', type: 'transform', color: '#ffa502' }
    ];
    const edges = [
        { from: 'user_input', to: 'instr_handler', label: 'tainted' }
    ];

    findings.forEach((f, i) => {
        const nodeId = `var_${i}`;
        nodes.push({
            id: nodeId,
            label: f.instruction || 'variable',
            type: 'sink',
            color: f.severity >= 4 ? '#ff4757' : '#ffa502'
        });
        edges.push({ from: 'instr_handler', to: nodeId, label: 'flow' });
    });

    res.status(200).json({ nodes, edges });
};
