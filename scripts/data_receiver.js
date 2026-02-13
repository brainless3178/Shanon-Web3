const http = require('http');
const fs = require('fs');
const path = require('path');

const OUTPUT = path.join(__dirname, '..', 'data', 'colosseum_projects.json');

const server = http.createServer((req, res) => {
    // CORS headers for cross-origin requests from colosseum.com
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    if (req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            fs.writeFileSync(OUTPUT, body);
            console.log(`Saved ${body.length} bytes to ${OUTPUT}`);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true, bytes: body.length }));
            // Shut down after saving
            setTimeout(() => {
                console.log('Data saved. Shutting down.');
                process.exit(0);
            }, 1000);
        });
        return;
    }

    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('POST your data here');
});

server.listen(9999, () => {
    console.log('Receiver listening on http://localhost:9999');
    console.log('POST data from browser to save it.');
});
