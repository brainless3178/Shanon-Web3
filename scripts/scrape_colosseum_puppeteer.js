#!/usr/bin/env node
/**
 * Scrapes all Colosseum Agent Hackathon projects using Puppeteer.
 * Scrolls through infinite scroll to load all 698+ projects,
 * then extracts title, description, votes, and URLs.
 */

const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

const OUTPUT_FILE = path.join(__dirname, '..', 'data', 'colosseum_projects.json');

async function scrape() {
    console.log('Launching browser...');
    const browser = await puppeteer.launch({
        headless: 'new',
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 1920, height: 1080 });

    console.log('Navigating to Colosseum projects page...');
    await page.goto('https://colosseum.com/agent-hackathon/projects', {
        waitUntil: 'networkidle2',
        timeout: 30000
    });

    // Scroll to load all projects
    console.log('Scrolling to load all projects...');
    let prevHeight = 0;
    let sameCount = 0;
    let scrollCount = 0;

    while (sameCount < 5) {
        await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
        await new Promise(r => setTimeout(r, 1200));
        const newHeight = await page.evaluate(() => document.body.scrollHeight);
        const linkCount = await page.evaluate(() =>
            document.querySelectorAll('a[href*="/agent-hackathon/projects/"]').length
        );
        scrollCount++;
        if (scrollCount % 10 === 0) {
            console.log(`  Scroll #${scrollCount}: ${linkCount} links, height=${newHeight}`);
        }
        if (newHeight === prevHeight) sameCount++;
        else sameCount = 0;
        prevHeight = newHeight;
    }

    console.log('All projects loaded. Extracting data...');

    const projects = await page.evaluate(() => {
        const cards = document.querySelectorAll('a[href*="/agent-hackathon/projects/"]');
        const results = [];
        const seen = new Set();

        cards.forEach(card => {
            const href = card.getAttribute('href') || '';
            if (seen.has(href) || !href.match(/\/projects\/.+/)) return;
            seen.add(href);

            const h3 = card.querySelector('h3') || card.querySelector('h2');
            const p = card.querySelector('p');
            const title = h3 ? h3.textContent.trim() : '';
            const desc = p ? p.textContent.trim() : '';

            // Extract vote counts from spans
            const allSpans = Array.from(card.querySelectorAll('span'));
            const numSpans = allSpans.filter(s => /^\d+$/.test(s.textContent.trim()));
            const humanVotes = numSpans.length >= 1 ? parseInt(numSpans[0].textContent.trim()) : 0;
            const agentVotes = numSpans.length >= 2 ? parseInt(numSpans[1].textContent.trim()) : 0;

            // Check for draft status
            const allText = card.innerText;
            const isDraft = /DRAFT/i.test(allText);

            results.push({
                title,
                description: desc,
                humanVotes,
                agentVotes,
                totalVotes: humanVotes + agentVotes,
                url: 'https://colosseum.com' + href,
                slug: href.replace('/agent-hackathon/projects/', ''),
                isDraft
            });
        });

        return results;
    });

    await browser.close();

    // Sort by total votes descending
    projects.sort((a, b) => b.totalVotes - a.totalVotes);

    const output = {
        scrapedAt: new Date().toISOString(),
        totalProjects: projects.length,
        projects
    };

    // Ensure data directory exists
    const dataDir = path.dirname(OUTPUT_FILE);
    if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
    }

    fs.writeFileSync(OUTPUT_FILE, JSON.stringify(output, null, 2));
    console.log(`\nDone! ${projects.length} projects saved to ${OUTPUT_FILE}`);
    console.log(`Top 10 projects by total votes:`);
    projects.slice(0, 10).forEach((p, i) => {
        console.log(`  ${i + 1}. ${p.title} (H:${p.humanVotes} A:${p.agentVotes})`);
    });
}

scrape().catch(err => {
    console.error('Scrape failed:', err.message);
    process.exit(1);
});
