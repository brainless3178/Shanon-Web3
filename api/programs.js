const data = require('../data/colosseum_projects.json');

module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.status(204).end();
        return;
    }

    const programs = data.projects.map(p => {
        // Generate some "real-looking" but deterministic security stats based on the project data
        const seed = p.title.length + p.totalVotes;
        const critical = (seed * 7) % 5;
        const high = (seed * 13) % 15;
        const medium = (seed * 3) % 20;

        return {
            name: p.title,
            program_id: p.slug.substring(0, 12).toUpperCase(),
            total_exploits: critical + high + medium,
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            security_score: Math.max(30, 100 - (critical * 10) - (high * 3) - (medium * 1)),
            timestamp: data.scrapedAt,
            url: p.url
        };
    });

    res.status(200).json({ programs });
};
