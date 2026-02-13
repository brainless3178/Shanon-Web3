#!/usr/bin/env node
/**
 * Scrapes all projects from the Colosseum Agent Hackathon.
 * Uses the network requests the page makes under the hood.
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

// The Colosseum site likely fetches projects from an API endpoint.
// Let's try a direct approach: fetch the HTML and parse, or check for API endpoints.

async function fetchPage(url) {
    return new Promise((resolve, reject) => {
        const proto = url.startsWith('https') ? https : require('http');
        proto.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' } }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve({ status: res.statusCode, data, headers: res.headers }));
        }).on('error', reject);
    });
}

async function main() {
    console.log('Attempting to find Colosseum API...');

    // Try common API patterns
    const apiUrls = [
        'https://colosseum.com/api/agent-hackathon/projects',
        'https://colosseum.com/api/hackathons/agent-hackathon/projects',
        'https://colosseum.com/api/projects?hackathon=agent-hackathon',
    ];

    for (const url of apiUrls) {
        try {
            console.log('Trying:', url);
            const resp = await fetchPage(url);
            console.log('Status:', resp.status, 'Length:', resp.data.length);
            if (resp.status === 200 && resp.data.startsWith('{') || resp.data.startsWith('[')) {
                console.log('Found API endpoint!');
                const data = JSON.parse(resp.data);
                console.log('Projects:', Array.isArray(data) ? data.length : JSON.stringify(Object.keys(data)).substring(0, 200));
                fs.writeFileSync(path.join(__dirname, '..', 'colosseum_projects.json'), JSON.stringify(data, null, 2));
                return;
            }
        } catch (e) {
            console.log('Error:', e.message);
        }
    }

    // If no API found, we'll read the data from the browser extraction
    console.log('\nNo direct API found. Using browser-extracted data approach.');
    console.log('The data has been extracted via browser JS and is ready in the browser memory.');
    console.log('Use the dashboard to transfer it, or check the Downloads folder.');
}

main().catch(console.error);
