module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.status(204).end();
        return;
    }

    res.status(200).json({
        nodes: [
            { id: 'user_input', label: 'Instruction Data', type: 'source', color: '#ff4757' },
            { id: 'instr_handler', label: 'Processor Handler', type: 'transform', color: '#ffa502' },
            { id: 'account_data', label: 'Vault State', type: 'sink', color: '#2ed573' }
        ],
        edges: [
            { from: 'user_input', to: 'instr_handler', label: 'tainted' },
            { from: 'instr_handler', to: 'account_data', label: 'propagated' }
        ]
    });
};
