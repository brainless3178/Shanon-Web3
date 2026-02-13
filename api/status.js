const data = require('../data/colosseum_projects.json');

module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(200).json({
        status: 'online',
        engine: 'Solana Security Swarm / Colosseum Intelligence',
        version: '1.2.0-hackathon',
        metadata: {
            total_projects_audited: data.totalProjects,
            last_scrape: data.scrapedAt,
            provider: 'Vercel Serverless (Backend) / Netlify (Frontend)'
        }
    });
};
