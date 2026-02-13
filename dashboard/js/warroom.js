/**
 * WAR ROOM — Multi-Agent Adversarial Security Council
 *
 * Premium redesign: auto-play, live stats, agent activity tracking,
 * continuous analysis, and meaningful data connections.
 */
(function () {
    'use strict';

    var C = window.Components;
    var I = window.Icons;
    var Ch = window.Charts;

    /* ── Agent SVG Icons ── */
    var AGENT_ICONS = {
        cipher: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r="1" fill="currentColor"/></svg>',
        sentinel: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7L12 2z"/><polyline points="9 12 11 14 15 10"/></svg>',
        oracle: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="20" x2="12" y2="10"/><line x1="18" y1="20" x2="18" y2="4"/><line x1="6" y1="20" x2="6" y2="16"/><path d="M2 20h20"/><circle cx="18" cy="4" r="1.5" fill="currentColor"/></svg>',
        prover: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="3"/><path d="M7 12h2l2 4 4-8 2 4h2"/></svg>',
        arbiter: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="20" x2="21" y2="20"/><path d="M12 2L4 8h16L12 2z"/><line x1="7" y1="8" x2="7" y2="16"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="17" y1="8" x2="17" y2="16"/><rect x="4" y="16" width="16" height="2" rx="1"/></svg>'
    };

    /* ── Agent Definitions ── */
    var AGENTS = {
        cipher: {
            id: 'cipher', name: 'CIPHER', role: 'Red Team Lead',
            emoji: '🔴', color: '#ff4757',
            gradient: 'linear-gradient(135deg, #ff4757, #ff6b81)',
            avatar: AGENT_ICONS.cipher,
            desc: 'Offensive security. Finds attack vectors & constructs exploit chains.',
            thinkingPhrases: ['Scanning attack surface...', 'Constructing exploit chain...', 'Modeling adversarial path...', 'Reverse-engineering constraints...']
        },
        sentinel: {
            id: 'sentinel', name: 'SENTINEL', role: 'Blue Team Lead',
            emoji: '🔵', color: '#3742fa',
            gradient: 'linear-gradient(135deg, #3742fa, #5352ed)',
            avatar: AGENT_ICONS.sentinel,
            desc: 'Defensive analyst. Validates findings & checks mitigations.',
            thinkingPhrases: ['Validating finding context...', 'Checking mitigations...', 'Analyzing control flow...', 'Cross-referencing CWE database...']
        },
        oracle: {
            id: 'oracle', name: 'ORACLE', role: 'DeFi Economist',
            emoji: '💰', color: '#ffa502',
            gradient: 'linear-gradient(135deg, #ffa502, #ff7f50)',
            avatar: AGENT_ICONS.oracle,
            desc: 'Financial impact modeling. MEV exposure & attack profitability.',
            thinkingPhrases: ['Calculating value at risk...', 'Modeling attack economics...', 'Estimating MEV exposure...', 'Running Monte Carlo sim...']
        },
        prover: {
            id: 'prover', name: 'PROVER', role: 'Formal Verifier',
            emoji: '🔬', color: '#2ed573',
            gradient: 'linear-gradient(135deg, #2ed573, #7bed9f)',
            avatar: AGENT_ICONS.prover,
            desc: 'Formal methods. Mathematical proofs via Z3 SMT solver.',
            thinkingPhrases: ['Encoding Z3 constraints...', 'Checking satisfiability...', 'Building proof tree...', 'Verifying invariant...']
        },
        arbiter: {
            id: 'arbiter', name: 'ARBITER', role: 'Final Judge',
            emoji: '⚖️', color: '#a55eea',
            gradient: 'linear-gradient(135deg, #a55eea, #8854d0)',
            avatar: AGENT_ICONS.arbiter,
            desc: 'Synthesizes all perspectives. Delivers consensus verdicts.',
            thinkingPhrases: ['Weighing evidence...', 'Synthesizing perspectives...', 'Calculating consensus...', 'Forming final verdict...']
        }
    };

    var AGENT_ORDER = ['cipher', 'sentinel', 'oracle', 'prover', 'arbiter'];

    /* ── Debate Script: Real Backend Analysis ──
     * Calls POST /api/warroom/analyze with the full finding.
     * The backend runs genuine per-agent analysis:
     *   - CIPHER: categorizes vuln, builds attack path from real data
     *   - SENTINEL: validates independently, may DISPUTE or REJECT
     *   - ORACLE: computes economics from real value_at_risk_usd
     *   - PROVER: generates Z3 constraints per vulnerability category
     *   - ARBITER: synthesizes consensus from all agent positions
     *
     * Returns the same { rounds: [{ round, title, messages }] } format
     * that the debate engine expects. Falls back to a minimal local
     * script if the API is unreachable.
     */
    async function fetchDebateScript(finding) {
        try {
            var resp = await fetch('/api/warroom/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ finding: finding })
            });
            if (!resp.ok) throw new Error('API returned ' + resp.status);
            var data = await resp.json();
            /* Store verdict metadata for the UI */
            finding._apiVerdict = data.final_verdict;
            finding._apiSeverity = data.final_severity;
            finding._apiConfidence = data.final_confidence;
            finding._apiConsensus = data.consensus_count;
            finding._apiRejected = data.rejected;
            return data.rounds;
        } catch (err) {
            console.warn('War Room API unavailable, using fallback:', err.message);
            return fallbackScript(finding);
        }
    }

    /* Minimal fallback if API is down — just shows the raw finding data */
    function fallbackScript(finding) {
        var vtype = finding.vulnerability_type || 'Unknown';
        var sev = (finding._severity_norm || 'medium').toUpperCase();
        var program = finding._program_name || 'unknown';
        var instr = finding.instruction || 'unknown';
        var fid = finding.id || 'UNKNOWN';
        return [{
            round: 1, title: 'Analysis (Offline Mode)',
            messages: [
                {
                    agent: 'cipher', type: 'discovery',
                    text: 'Found `' + fid + '` — **' + sev + '** severity **' + vtype + '** in `' + program + '::' + instr + '`.\n\n' + (finding.description || 'No description available.'),
                    confidence: 50
                },
                {
                    agent: 'arbiter', type: 'verdict',
                    text: '## OFFLINE MODE\n\nBackend analysis API unavailable. Displaying raw finding data only.\n\n**Action:** Restart the server to enable full multi-agent analysis.',
                    confidence: 0
                }
            ]
        }];
    }

    /* ── War Room State ── */
    var state = {
        isRunning: false,
        isPaused: false,
        autoPlay: true,
        currentFindingIdx: 0,
        findings: [],
        analyzed: 0,
        verdicts: { critical: 0, high: 0, medium: 0, low: 0 },
        agentStats: {},
        timer: null,
        aborted: false,
        speed: 1 // 1 = normal, 2 = fast, 0.5 = slow
    };

    AGENT_ORDER.forEach(function (id) {
        state.agentStats[id] = { messages: 0, active: false };
    });

    /* ── Utilities ── */
    function sleep(ms) {
        return new Promise(function (resolve) { setTimeout(resolve, ms / state.speed); });
    }

    function esc(s) { return C && C.esc ? C.esc(s) : s; }

    function formatNum(n) {
        if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
        if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
        return String(n);
    }

    function sevColor(s) {
        var map = { critical: '#ff3355', high: '#ff8833', medium: '#ffcc33', low: '#33dd99' };
        return map[(s || 'medium').toLowerCase()] || '#ffcc33';
    }

    /* ── Inject Styles ── */
    function injectStyles() {
        if (document.getElementById('wr-styles-v2')) return;
        var s = document.createElement('style');
        s.id = 'wr-styles-v2';
        s.textContent = [
            '@keyframes wrSlide{from{opacity:0;transform:translateY(8px);}to{opacity:1;transform:translateY(0);}}',
            '@keyframes wrPulse{0%,100%{opacity:.6;}50%{opacity:1;}}',
            '@keyframes wrDot{0%,80%,100%{transform:scale(.5);opacity:.4;}40%{transform:scale(1);opacity:1;}}',
            '@keyframes wrGlow{0%,100%{box-shadow:0 0 20px rgba(20,241,149,.08);}50%{box-shadow:0 0 40px rgba(20,241,149,.16);}}',
            '@keyframes wrScanline{0%{transform:translateY(-100%);}100%{transform:translateY(100vh);}}',
            '@keyframes wrBorder{0%,100%{border-color:var(--border-subtle);}50%{border-color:var(--accent-primary);}}',
            '@keyframes wrCountUp{from{opacity:0;transform:translateY(6px);}to{opacity:1;transform:translateY(0);}}',
            /* War Room Layout */
            '.wr-grid{display:grid;grid-template-columns:280px 1fr;gap:0;height:calc(100vh - 120px);min-height:600px;}',
            '.wr-sidebar{background:var(--bg-card);border-right:1px solid var(--border-subtle);display:flex;flex-direction:column;overflow:hidden;}',
            '.wr-main{display:flex;flex-direction:column;overflow:hidden;}',
            /* Sidebar sections */
            '.wr-sb-section{padding:16px;border-bottom:1px solid var(--border-subtle);}',
            '.wr-sb-title{font-size:.7rem;font-weight:700;letter-spacing:.1em;color:var(--text-muted);margin-bottom:10px;text-transform:uppercase;}',
            /* Agent roster */
            '.wr-agent-row{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:8px;margin-bottom:4px;transition:all .3s ease;cursor:default;position:relative;}',
            '.wr-agent-row.is-active{background:var(--bg-surface);}',
            '.wr-agent-row.is-active::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;border-radius:0 3px 3px 0;}',
            '.wr-agent-dot{width:34px;height:34px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;padding:7px;color:#fff;transition:box-shadow .3s ease;}.wr-agent-dot svg{width:100%;height:100%;}',
            '.wr-agent-meta{flex:1;min-width:0;}',
            '.wr-agent-name{font-size:.82rem;font-weight:700;line-height:1.2;}',
            '.wr-agent-role{font-size:.72rem;color:var(--text-muted);}',
            '.wr-agent-count{font-size:.74rem;font-weight:600;color:var(--text-muted);font-family:var(--font-mono);}',
            /* Stats */
            '.wr-stat-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;}',
            '.wr-stat{padding:10px;background:var(--bg-surface);border-radius:8px;text-align:center;}',
            '.wr-stat-val{font-size:1.3rem;font-weight:800;line-height:1;}',
            '.wr-stat-lbl{font-size:.72rem;color:var(--text-muted);margin-top:4px;letter-spacing:.04em;}',
            /* Feed */
            '.wr-feed-header{padding:12px 20px;border-bottom:1px solid var(--border-subtle);display:flex;align-items:center;gap:10px;background:var(--bg-card);}',
            '.wr-feed-scroll{flex:1;overflow-y:auto;padding:0;}',
            '.wr-feed-scroll::-webkit-scrollbar{width:5px;}',
            '.wr-feed-scroll::-webkit-scrollbar-thumb{background:var(--border-subtle);border-radius:3px;}',
            /* Messages */
            '.wr-msg{display:flex;gap:12px;padding:14px 20px;border-left:3px solid transparent;animation:wrSlide .35s ease;position:relative;}',
            '.wr-msg:hover{background:rgba(255,255,255,.02);}',
            '.wr-msg-avi{width:34px;height:34px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;padding:7px;color:#fff;}.wr-msg-avi svg{width:100%;height:100%;}',
            '.wr-msg-body{flex:1;min-width:0;font-size:.84rem;line-height:1.65;color:var(--text-secondary);}',
            '.wr-msg-head{display:flex;align-items:center;gap:8px;margin-bottom:4px;}',
            '.wr-msg-name{font-size:.8rem;font-weight:700;}',
            '.wr-msg-tag{font-size:.7rem;padding:1px 8px;border-radius:10px;font-weight:600;}',
            '.wr-msg strong{color:var(--text-pure);}',
            '.wr-msg code{background:var(--bg-surface);padding:1px 5px;border-radius:3px;font-size:.8em;}',
            /* Code block */
            '.wr-code{margin:8px 0;padding:10px 14px;background:#0d1117;border:1px solid var(--border-subtle);border-radius:8px;font-family:var(--font-mono);font-size:.76rem;line-height:1.6;color:#c9d1d9;overflow-x:auto;white-space:pre;}',
            /* Metrics row */
            '.wr-metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin-top:10px;}',
            '.wr-metric{padding:8px;background:var(--bg-surface);border-radius:6px;text-align:center;}',
            '.wr-metric-val{font-size:1rem;font-weight:800;}',
            '.wr-metric-lbl{font-size:.68rem;color:var(--text-muted);margin-top:2px;text-transform:uppercase;letter-spacing:.04em;}',
            /* Consensus */
            '.wr-consensus{margin-top:12px;padding:14px;background:var(--bg-card);border:1px solid var(--border-subtle);border-radius:10px;}',
            '.wr-consensus-row{display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap;}',
            '.wr-consensus-agent{display:flex;align-items:center;gap:4px;padding:4px 10px;border-radius:20px;font-size:.74rem;font-weight:600;border:1px solid;}',
            '.wr-conf-bar{display:flex;align-items:center;gap:10px;}',
            '.wr-conf-track{flex:1;height:6px;background:var(--bg-surface);border-radius:3px;overflow:hidden;}',
            '.wr-conf-fill{height:100%;border-radius:3px;transition:width 1.2s ease;}',
            '.wr-conf-pct{font-size:.82rem;font-weight:700;}',
            /* Reactions */
            '.wr-reactions{display:flex;align-items:center;gap:6px;margin-top:8px;flex-wrap:wrap;}',
            '.wr-react-btn{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:12px;font-size:.68rem;background:var(--bg-surface);border:1px solid var(--border-subtle);cursor:pointer;transition:all .25s ease;color:var(--text-muted);user-select:none;}',
            '.wr-react-btn:hover{border-color:var(--accent-primary);background:rgba(0,242,195,.06);}',
            '.wr-react-btn.is-active{border-color:var(--accent-primary);background:rgba(0,242,195,.1);color:var(--text-primary);}',
            '.wr-react-btn .wr-react-count{font-weight:700;font-size:.66rem;min-width:8px;text-align:center;}',
            '@keyframes wrReactPop{0%{transform:scale(1)}50%{transform:scale(1.35)}100%{transform:scale(1)}}',
            '.wr-react-pop{animation:wrReactPop .3s ease;}',
            /* Agent Comments / Replies */
            '.wr-comments{margin-top:8px;padding-left:12px;border-left:2px solid var(--border-subtle);}',
            '.wr-comment{display:flex;align-items:flex-start;gap:8px;padding:6px 0;animation:wrSlide .3s ease;}',
            '.wr-comment-avi{width:20px;height:20px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;padding:4px;color:#fff;}.wr-comment-avi svg{width:100%;height:100%;}',
            '.wr-comment-body{flex:1;min-width:0;}',
            '.wr-comment-head{display:flex;align-items:center;gap:6px;margin-bottom:1px;}',
            '.wr-comment-name{font-size:.7rem;font-weight:700;}',
            '.wr-comment-text{font-size:.76rem;color:var(--text-secondary);line-height:1.5;}',
            '.wr-comment-text strong{color:var(--text-pure);}',
            /* Round divider */
            '.wr-round{display:flex;align-items:center;gap:12px;padding:10px 20px;margin:4px 0;background:linear-gradient(90deg,var(--bg-surface),transparent);}',
            '.wr-round-num{font-size:.7rem;font-weight:800;padding:3px 10px;background:var(--accent-primary);color:#000;border-radius:12px;letter-spacing:.1em;}',
            '.wr-round-title{font-size:.86rem;font-weight:600;color:var(--text-primary);}',

            '.wr-round-line{flex:1;height:1px;background:var(--border-subtle);}',
            /* Thinking */
            '.wr-thinking{display:flex;gap:12px;padding:12px 20px;border-left:3px solid transparent;animation:wrPulse 1.8s ease-in-out infinite;}',
            '.wr-thinking-dots{display:flex;gap:3px;align-items:center;}',
            '.wr-thinking-dots span{width:5px;height:5px;border-radius:50%;animation:wrDot 1.4s infinite ease-in-out;}',
            '.wr-thinking-phrase{font-size:.78rem;color:var(--text-muted);font-style:italic;}',
            /* Queue */
            '.wr-queue{flex:1;overflow-y:auto;padding:0 16px 16px;}',
            '.wr-queue::-webkit-scrollbar{width:4px;}',
            '.wr-queue::-webkit-scrollbar-thumb{background:var(--border-subtle);border-radius:2px;}',
            '.wr-queue-item{padding:8px 10px;border-radius:6px;margin-bottom:4px;cursor:pointer;display:flex;align-items:center;gap:8px;transition:all .2s ease;border-left:3px solid transparent;}',
            '.wr-queue-item:hover{background:var(--bg-surface);}',
            '.wr-queue-item.is-active{background:var(--bg-surface);border-left-color:var(--accent-primary);}',
            '.wr-queue-item.is-done{opacity:.5;}',
            '.wr-queue-sev{font-size:.68rem;font-weight:800;padding:2px 7px;border-radius:4px;letter-spacing:.05em;flex-shrink:0;}',
            '.wr-queue-text{font-size:.76rem;color:var(--text-secondary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1;}',
            '.wr-queue-check{font-size:.74rem;flex-shrink:0;}',
            /* Controls */
            '.wr-controls{padding:12px 16px;border-top:1px solid var(--border-subtle);display:flex;gap:8px;align-items:center;}',
            '.wr-btn{padding:6px 14px;border:1px solid var(--border-subtle);border-radius:6px;background:var(--bg-surface);color:var(--text-primary);font-size:.8rem;font-weight:600;cursor:pointer;transition:all .2s ease;display:flex;align-items:center;gap:5px;}',
            '.wr-btn:hover{background:var(--bg-card);border-color:var(--accent-primary);}',
            '.wr-btn.is-primary{background:var(--accent-primary);color:#000;border-color:var(--accent-primary);}',
            '.wr-btn.is-primary:hover{opacity:.85;}',
            '.wr-btn.is-danger{background:rgba(255,51,85,.15);color:var(--critical);border-color:rgba(255,51,85,.3);}',
            /* Finding context bar */
            '.wr-context{padding:12px 20px;background:var(--bg-surface);border-bottom:1px solid var(--border-subtle);display:flex;align-items:center;gap:16px;flex-wrap:wrap;}',
            '.wr-context-tag{font-size:.7rem;padding:3px 10px;border-radius:6px;font-weight:700;letter-spacing:.04em;}',
            '.wr-context-detail{font-size:.78rem;color:var(--text-secondary);}',
            '.wr-context-detail strong{color:var(--text-primary);}',
            /* Progress ring */
            '.wr-progress{position:relative;width:48px;height:48px;}',
            '.wr-progress svg{transform:rotate(-90deg);}',
            '.wr-progress-text{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:800;color:var(--text-primary);}',
            /* Responsive */
            '@media(max-width:900px){.wr-grid{grid-template-columns:1fr;height:auto;}.wr-sidebar{display:none;}}',
        ].join('\n');
        document.head.appendChild(s);
    }

    /* ── Render Helpers ── */
    function mdText(text, agentColor) {
        text = text.replace(/```([\s\S]*?)```/g, function (_, code) {
            return '<div class="wr-code">' + esc(code.trim()) + '</div>';
        });
        text = text.replace(/^## (.+)/gm, '<div style="font-size:1rem;font-weight:800;color:var(--text-pure);margin:6px 0 10px;padding-bottom:6px;border-bottom:2px solid ' + agentColor + '40;">$1</div>');
        text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
        text = text.replace(/`([^`]+)`/g, '<code style="color:' + agentColor + '">$1</code>');
        text = text.replace(/\n/g, '<br>');
        return text;
    }

    /* ── Unique message ID counter ── */
    var _msgIdCounter = 0;

    function renderMsg(msg, agent) {
        var msgId = 'wr-m-' + (++_msgIdCounter);
        var html = '<div class="wr-msg" id="' + msgId + '" style="border-left-color:' + agent.color + ';" data-agent="' + (msg.agent || '') + '" data-type="' + (msg.type || '') + '">';
        html += '<div class="wr-msg-avi" style="background:' + agent.gradient + ';">' + agent.avatar + '</div>';
        html += '<div class="wr-msg-body">';
        html += '<div class="wr-msg-head">';
        html += '<span class="wr-msg-name" style="color:' + agent.color + ';">' + agent.name + '</span>';
        html += '<span class="wr-msg-tag" style="background:' + agent.color + '18;color:' + agent.color + ';">' + agent.role + '</span>';
        if (msg.confidence) html += '<span class="wr-msg-tag" style="background:' + agent.color + '20;color:' + agent.color + ';">CONF: ' + msg.confidence + '%</span>';
        if (msg.proven) html += '<span class="wr-msg-tag" style="background:#2ed57320;color:#2ed573;">✅ PROVEN</span>';
        html += '</div>';
        html += '<div>' + mdText(msg.text || '', agent.color) + '</div>';

        if (msg.code) {
            html += '<div class="wr-code"><pre style="margin:0;white-space:pre;">' + esc(msg.code) + '</pre></div>';
        }

        if (msg.metrics) {
            var m = msg.metrics;
            html += '<div class="wr-metrics">';
            html += '<div class="wr-metric"><div class="wr-metric-val" style="color:var(--critical);">$' + (m.var_usd / 1e6).toFixed(0) + 'M</div><div class="wr-metric-lbl">Value at Risk</div></div>';
            html += '<div class="wr-metric"><div class="wr-metric-val" style="color:var(--low);">$' + m.attack_cost.toFixed(2) + '</div><div class="wr-metric-lbl">Attack Cost</div></div>';
            html += '<div class="wr-metric"><div class="wr-metric-val" style="color:' + (m.mev_risk === 'HIGH' ? 'var(--critical)' : 'var(--medium)') + ';">' + m.mev_risk + '</div><div class="wr-metric-lbl">MEV Risk</div></div>';
            html += '<div class="wr-metric"><div class="wr-metric-val" style="color:var(--critical);">' + m.profit_ratio + '</div><div class="wr-metric-lbl">Profit Ratio</div></div>';
            html += '</div>';
        }

        if (msg.consensus) {
            html += '<div class="wr-consensus">';
            html += '<div class="wr-consensus-row">';
            AGENT_ORDER.forEach(function (aId) {
                var a = AGENTS[aId];
                var voted = msg.consensus[aId];
                html += '<div class="wr-consensus-agent" style="background:' + (voted ? a.color + '18' : 'transparent') + ';border-color:' + (voted ? a.color : 'var(--border-subtle)') + ';color:' + (voted ? a.color : 'var(--text-muted)') + ';">';
                html += '<span style="display:inline-flex;width:14px;height:14px;">' + a.avatar + '</span> ' + a.name + ' ' + (voted ? '✅' : '❌');
                html += '</div>';
            });
            html += '</div>';
            html += '<div class="wr-conf-bar">';
            html += '<div class="wr-conf-track"><div class="wr-conf-fill" style="width:' + msg.confidence + '%;background:' + agent.gradient + ';"></div></div>';
            html += '<span class="wr-conf-pct" style="color:' + agent.color + ';">' + msg.confidence + '%</span>';
            html += '</div></div>';
        }

        /* Reactions bar — empty, filled by addReaction() later */
        html += '<div class="wr-reactions" id="' + msgId + '-reactions"></div>';

        /* Comments area — empty, filled by addComment() later */
        html += '<div class="wr-comments" id="' + msgId + '-comments" style="display:none;"></div>';

        html += '</div></div>';
        return html;
    }

    /* ── Reaction System ── */
    function addReaction(msgId, emoji, agentId) {
        var container = document.getElementById(msgId + '-reactions');
        if (!container) return;
        /* Check if this reaction type already exists on this message */
        var existing = container.querySelector('[data-emoji="' + emoji + '"]');
        if (existing) {
            /* Add agent avatar to existing reaction & bump count */
            var countEl = existing.querySelector('.wr-react-count');
            var count = parseInt(countEl.textContent || '1') + 1;
            countEl.textContent = count;
            existing.classList.add('wr-react-pop');
            existing.classList.add('is-active');
            /* Add agent mini-avatar */
            var a = AGENTS[agentId];
            if (a) {
                var dot = document.createElement('span');
                dot.style.cssText = 'width:14px;height:14px;border-radius:50%;background:' + a.gradient + ';display:inline-flex;align-items:center;justify-content:center;margin-left:-2px;';
                dot.innerHTML = '<span style="display:flex;width:10px;height:10px;">' + a.avatar + '</span>';
                existing.insertBefore(dot, countEl);
            }
            setTimeout(function () { existing.classList.remove('wr-react-pop'); }, 300);
        } else {
            var a = AGENTS[agentId];
            var btn = document.createElement('span');
            btn.className = 'wr-react-btn is-active wr-react-pop';
            btn.setAttribute('data-emoji', emoji);
            var avatarHtml = '';
            if (a) {
                avatarHtml = '<span style="width:14px;height:14px;border-radius:50%;background:' + a.gradient + ';display:inline-flex;align-items:center;justify-content:center;"><span style="display:flex;width:10px;height:10px;">' + a.avatar + '</span></span>';
            }
            btn.innerHTML = emoji + ' ' + avatarHtml + '<span class="wr-react-count">1</span>';
            container.appendChild(btn);
            setTimeout(function () { btn.classList.remove('wr-react-pop'); }, 300);
        }
    }

    /* ── Comment System ── */
    function addComment(msgId, agentId, text) {
        var container = document.getElementById(msgId + '-comments');
        if (!container) return;
        container.style.display = 'block';
        var a = AGENTS[agentId];
        if (!a) return;
        var html = '<div class="wr-comment">';
        html += '<div class="wr-comment-avi" style="background:' + a.gradient + ';">' + a.avatar + '</div>';
        html += '<div class="wr-comment-body">';
        html += '<div class="wr-comment-head"><span class="wr-comment-name" style="color:' + a.color + ';">' + a.name + '</span></div>';
        html += '<div class="wr-comment-text">' + mdText(text, a.color) + '</div>';
        html += '</div></div>';
        container.insertAdjacentHTML('beforeend', html);
    }

    /* ── Compute reactions & comments based on message context ── */
    function computeInteractions(msg, msgId, allMessages, msgIndex) {
        var interactions = []; /* { delay, fn } */
        var type = msg.type || '';
        var agent = msg.agent || '';

        if (type === 'discovery' && agent === 'cipher') {
            /* Other agents acknowledge the discovery */
            interactions.push({ delay: 400, fn: function () { addReaction(msgId, '👀', 'sentinel'); } });
            interactions.push({ delay: 700, fn: function () { addReaction(msgId, '👀', 'oracle'); } });
        }
        if (type === 'attack' && agent === 'cipher') {
            /* PROVER is interested in the exploit scenario */
            interactions.push({ delay: 500, fn: function () { addReaction(msgId, '🔬', 'prover'); } });
            /* If there's code, SENTINEL reacts */
            if (msg.code) {
                interactions.push({ delay: 800, fn: function () { addReaction(msgId, '⚠️', 'sentinel'); } });
            }
        }
        if (type === 'analysis' && agent === 'sentinel') {
            if (msg.verdict === 'confirmed') {
                /* CIPHER appreciates validation */
                interactions.push({ delay: 300, fn: function () { addReaction(msgId, '👍', 'cipher'); } });
                interactions.push({ delay: 600, fn: function () { addReaction(msgId, '✅', 'arbiter'); } });
            } else if (msg.verdict === 'disputed') {
                interactions.push({ delay: 400, fn: function () { addReaction(msgId, '⚔️', 'cipher'); } });
                interactions.push({
                    delay: 700, fn: function () {
                        addComment(msgId, 'oracle', 'Noted — I\'ll factor the disputed severity into my economic model.');
                    }
                });
            } else if (msg.verdict === 'rejected') {
                interactions.push({ delay: 400, fn: function () { addReaction(msgId, '❌', 'arbiter'); } });
                interactions.push({ delay: 600, fn: function () { addReaction(msgId, '🛑', 'prover'); } });
            }
        }
        if (type === 'metrics' && agent === 'oracle') {
            /* Agents react to economic data */
            interactions.push({ delay: 500, fn: function () { addReaction(msgId, '📊', 'arbiter'); } });
            if (msg.metrics && msg.metrics.var_usd > 1000000) {
                interactions.push({ delay: 800, fn: function () { addReaction(msgId, '🚨', 'cipher'); } });
                interactions.push({ delay: 1000, fn: function () { addReaction(msgId, '🚨', 'sentinel'); } });
            } else {
                interactions.push({ delay: 800, fn: function () { addReaction(msgId, '👀', 'cipher'); } });
            }
        }
        if (type === 'counter' && agent === 'sentinel') {
            interactions.push({ delay: 500, fn: function () { addReaction(msgId, '🤔', 'oracle'); } });
        }
        if (type === 'z3' && agent === 'prover') {
            if (msg.proven) {
                interactions.push({ delay: 400, fn: function () { addReaction(msgId, '⚡', 'cipher'); } });
                interactions.push({ delay: 700, fn: function () { addReaction(msgId, '⚡', 'oracle'); } });
                interactions.push({ delay: 900, fn: function () { addReaction(msgId, '⚡', 'arbiter'); } });
                interactions.push({
                    delay: 1200, fn: function () {
                        addComment(msgId, 'arbiter', '**Key evidence.** Formal proof elevates this from heuristic to mathematical certainty.');
                    }
                });
            } else {
                interactions.push({ delay: 500, fn: function () { addReaction(msgId, '⚠️', 'sentinel'); } });
                interactions.push({
                    delay: 800, fn: function () {
                        addComment(msgId, 'sentinel', 'Inconclusive proof supports my earlier severity reduction argument.');
                    }
                });
            }
        }
        if (type === 'kani' && agent === 'prover') {
            interactions.push({ delay: 400, fn: function () { addReaction(msgId, '🎯', 'cipher'); } });
            interactions.push({ delay: 600, fn: function () { addReaction(msgId, '🎯', 'arbiter'); } });
        }
        if (type === 'concede' && agent === 'sentinel') {
            interactions.push({ delay: 400, fn: function () { addReaction(msgId, '🤝', 'cipher'); } });
            interactions.push({ delay: 700, fn: function () { addReaction(msgId, '🤝', 'prover'); } });
            interactions.push({
                delay: 900, fn: function () {
                    addComment(msgId, 'cipher', 'Appreciate the intellectual honesty. The constraint gap was a real blind spot.');
                }
            });
        }
        if (type === 'react' && agent === 'cipher') {
            interactions.push({ delay: 500, fn: function () { addReaction(msgId, '👍', 'prover'); } });
        }
        if (type === 'deliberation' && agent === 'arbiter') {
            interactions.push({ delay: 600, fn: function () { addReaction(msgId, '📋', 'cipher'); } });
            interactions.push({ delay: 800, fn: function () { addReaction(msgId, '📋', 'sentinel'); } });
            interactions.push({ delay: 1000, fn: function () { addReaction(msgId, '📋', 'oracle'); } });
            interactions.push({ delay: 1200, fn: function () { addReaction(msgId, '📋', 'prover'); } });
        }
        if (type === 'verdict' && agent === 'arbiter') {
            interactions.push({ delay: 500, fn: function () { addReaction(msgId, '⚖️', 'cipher'); } });
            interactions.push({ delay: 700, fn: function () { addReaction(msgId, '⚖️', 'sentinel'); } });
            interactions.push({ delay: 900, fn: function () { addReaction(msgId, '⚖️', 'oracle'); } });
            interactions.push({ delay: 1100, fn: function () { addReaction(msgId, '⚖️', 'prover'); } });
        }

        return interactions;
    }

    function renderThinking(agent) {
        var phrase = agent.thinkingPhrases[Math.floor(Math.random() * agent.thinkingPhrases.length)];
        return '<div id="wr-thinking" class="wr-thinking" style="border-left-color:' + agent.color + '30;">' +
            '<div class="wr-msg-avi" style="background:' + agent.gradient + ';opacity:.7;">' + agent.avatar + '</div>' +
            '<div style="display:flex;align-items:center;gap:10px;">' +
            '<span class="wr-msg-name" style="color:' + agent.color + ';font-size:.76rem;">' + agent.name + '</span>' +
            '<span class="wr-thinking-dots">' +
            '<span style="background:' + agent.color + ';animation-delay:0s;"></span>' +
            '<span style="background:' + agent.color + ';animation-delay:.2s;"></span>' +
            '<span style="background:' + agent.color + ';animation-delay:.4s;"></span>' +
            '</span>' +
            '<span class="wr-thinking-phrase">' + esc(phrase) + '</span>' +
            '</div></div>';
    }

    function renderRound(round) {
        return '<div class="wr-round">' +
            '<span class="wr-round-num">ROUND ' + round.round + '</span>' +
            '<span class="wr-round-title">' + esc(round.title) + '</span>' +
            '<span class="wr-round-line"></span>' +
            '</div>';
    }

    /* ── Update Sidebar Stats ── */
    function updateStats() {
        var el;
        el = document.getElementById('wr-stat-analyzed');
        if (el) { el.textContent = state.analyzed; el.style.animation = 'wrCountUp .3s ease'; }
        el = document.getElementById('wr-stat-critical');
        if (el) el.textContent = state.verdicts.critical;
        el = document.getElementById('wr-stat-high');
        if (el) el.textContent = state.verdicts.high;
        el = document.getElementById('wr-stat-medium');
        if (el) el.textContent = state.verdicts.medium;
        el = document.getElementById('wr-stat-queue');
        if (el) el.textContent = Math.max(0, state.findings.length - state.currentFindingIdx - 1);

        /* Update agent message counts */
        AGENT_ORDER.forEach(function (id) {
            el = document.getElementById('wr-ac-' + id);
            if (el) el.textContent = state.agentStats[id].messages;
        });
    }

    function setAgentActive(agentId) {
        AGENT_ORDER.forEach(function (id) {
            var row = document.getElementById('wr-ar-' + id);
            if (row) {
                if (id === agentId) {
                    row.classList.add('is-active');
                    row.querySelector('.wr-agent-dot').style.boxShadow = '0 0 12px ' + AGENTS[id].color + '80';
                } else {
                    row.classList.remove('is-active');
                    row.querySelector('.wr-agent-dot').style.boxShadow = 'none';
                }
            }
        });
    }

    function highlightQueueItem(idx) {
        var items = document.querySelectorAll('.wr-queue-item');
        items.forEach(function (item, i) {
            item.classList.toggle('is-active', i === idx);
        });
    }

    function markQueueDone(idx) {
        var items = document.querySelectorAll('.wr-queue-item');
        if (items[idx]) {
            items[idx].classList.add('is-done');
            items[idx].classList.remove('is-active');
            var check = items[idx].querySelector('.wr-queue-check');
            if (check) check.textContent = '✅';
        }
    }

    /* ── Debate Engine ── */
    async function runDebateForFinding(finding, feedEl, statusEl) {
        state.aborted = false;

        /* Show finding context bar */
        var sev = (finding._severity_norm || 'medium').toUpperCase();
        var ctx = document.getElementById('wr-context');
        if (ctx) {
            ctx.innerHTML = '<span class="wr-context-tag" style="background:' + sevColor(sev) + '22;color:' + sevColor(sev) + ';">' + sev + '</span>' +
                '<span class="wr-context-detail"><strong>' + esc(finding.vulnerability_type || 'Unknown') + '</strong> in <code style="background:var(--bg-card);padding:2px 6px;border-radius:3px;font-size:.8em;">' + esc(finding._program_name || 'unknown') + '</code></span>' +
                '<span class="wr-context-detail" style="margin-left:auto;font-family:var(--font-mono);font-size:.72rem;color:var(--text-muted);">' + esc(finding.id || '') + '</span>';
        }

        if (statusEl) {
            statusEl.innerHTML = '<span style="color:var(--accent-primary);">▸ Computing analysis for ' + esc(finding.vulnerability_type || 'finding') + '...</span>';
        }

        /* Call real backend API */
        var script = await fetchDebateScript(finding);

        if (statusEl) {
            statusEl.innerHTML = '<span style="color:var(--accent-primary);">▸ Presenting analysis...</span>';
        }

        for (var r = 0; r < script.length && !state.aborted; r++) {
            var round = script[r];
            feedEl.insertAdjacentHTML('beforeend', renderRound(round));
            feedEl.scrollTop = feedEl.scrollHeight;
            await sleep(400);

            for (var m = 0; m < round.messages.length && !state.aborted; m++) {
                while (state.isPaused && !state.aborted) {
                    await sleep(200);
                }
                var msg = round.messages[m];
                var agent = AGENTS[msg.agent];

                /* Set agent active in sidebar */
                setAgentActive(msg.agent);

                /* Show thinking */
                feedEl.insertAdjacentHTML('beforeend', renderThinking(agent));
                feedEl.scrollTop = feedEl.scrollHeight;

                var thinkTime = Math.min(500 + (msg.text || '').length * 2, 2200);
                await sleep(thinkTime);

                /* Remove thinking, add message */
                var thinkEl = document.getElementById('wr-thinking');
                if (thinkEl) thinkEl.remove();

                feedEl.insertAdjacentHTML('beforeend', renderMsg(msg, agent));
                var currentMsgId = 'wr-m-' + _msgIdCounter; /* renderMsg just incremented this */
                feedEl.scrollTop = feedEl.scrollHeight;

                /* Fire reactions & comments for this message */
                var interactions = computeInteractions(msg, currentMsgId, script.flatMap ? script.flatMap(function (r) { return r.messages; }) : [], m);
                interactions.forEach(function (ix) {
                    setTimeout(function () {
                        ix.fn();
                        feedEl.scrollTop = feedEl.scrollHeight;
                    }, ix.delay);
                });

                /* Update stats */
                state.agentStats[msg.agent].messages++;
                updateStats();

                await sleep(300);
            }

            if (r < script.length - 1) await sleep(500);
        }

        /* Record verdict from real API response */
        if (!state.aborted) {
            var verdictSev = (finding._apiSeverity || finding._severity_norm || 'medium').toLowerCase();
            if (state.verdicts[verdictSev] !== undefined) state.verdicts[verdictSev]++;
            state.analyzed++;
            if (finding._apiRejected) state.rejected = (state.rejected || 0) + 1;
            updateStats();
            markQueueDone(state.currentFindingIdx);
        }

        setAgentActive(null);
    }

    /* ── Auto-play Loop ── */
    async function autoPlayLoop(feedEl, statusEl) {
        state.isRunning = true;

        while (state.currentFindingIdx < state.findings.length && !state.aborted && state.autoPlay) {
            var finding = state.findings[state.currentFindingIdx];
            highlightQueueItem(state.currentFindingIdx);

            /* Add separator between debates */
            if (state.currentFindingIdx > 0) {
                feedEl.insertAdjacentHTML('beforeend',
                    '<div style="text-align:center;padding:20px;margin:8px 0;">' +
                    '<div style="width:60%;margin:0 auto;height:1px;background:linear-gradient(90deg,transparent,var(--border-subtle),transparent);"></div>' +
                    '<div style="font-size:.7rem;color:var(--text-muted);margin-top:8px;font-family:var(--font-mono);">NEXT FINDING ▸ #' + (state.currentFindingIdx + 1) + ' of ' + state.findings.length + '</div>' +
                    '</div>'
                );
                feedEl.scrollTop = feedEl.scrollHeight;
                await sleep(800);
            }

            await runDebateForFinding(finding, feedEl, statusEl);

            state.currentFindingIdx++;

            /* Pause between findings */
            if (state.currentFindingIdx < state.findings.length && !state.aborted) {
                if (statusEl) statusEl.innerHTML = '<span style="color:var(--text-muted);">Moving to next finding in 2s...</span>';
                await sleep(2000);
            }
        }

        state.isRunning = false;
        if (statusEl && !state.aborted) {
            statusEl.innerHTML = '<span style="color:var(--low);">✅ Queue complete — ' + state.analyzed + ' findings analyzed</span>';
        }

        /* Update play/pause button */
        var btn = document.getElementById('wr-play-btn');
        if (btn) btn.innerHTML = '▸ Restart';
    }

    /* ── Build the Queue ── */
    function buildQueue(findings) {
        /* Pick the most interesting: sort by severity desc, then shuffle within each tier */
        var sorted = findings.slice().sort(function (a, b) {
            var order = { critical: 0, high: 1, medium: 2, low: 3 };
            var sa = order[(a._severity_norm || 'medium').toLowerCase()] || 2;
            var sb = order[(b._severity_norm || 'medium').toLowerCase()] || 2;
            return sa - sb;
        });
        /* Take top criticals, some highs, a few mediums for variety */
        var criticals = sorted.filter(function (f) { return (f._severity_norm || '').toLowerCase() === 'critical'; });
        var highs = sorted.filter(function (f) { return (f._severity_norm || '').toLowerCase() === 'high'; });
        var mediums = sorted.filter(function (f) { return (f._severity_norm || '').toLowerCase() === 'medium'; });

        /* Deduplicate by vulnerability_type + program to avoid repetition */
        var seen = {};
        function dedupe(arr) {
            return arr.filter(function (f) {
                var key = (f._program_name || '') + '::' + (f.vulnerability_type || '');
                if (seen[key]) return false;
                seen[key] = true;
                return true;
            });
        }

        var queue = [];
        queue = queue.concat(dedupe(criticals).slice(0, 6));
        queue = queue.concat(dedupe(highs).slice(0, 4));
        queue = queue.concat(dedupe(mediums).slice(0, 2));

        /* Ensure at least something */
        if (queue.length === 0 && findings.length > 0) {
            queue = findings.slice(0, 5);
        }

        return queue;
    }

    /* ── Public: Render War Room ── */
    window.renderWarRoom = function () {
        var allFindings = window.ALL_FINDINGS_REF || [];
        var pageEl = document.getElementById('page-content');
        if (!pageEl) return;

        injectStyles();

        /* Reset state */
        state.isRunning = false;
        state.isPaused = false;
        state.aborted = true; /* stop any previous loop */
        state.currentFindingIdx = 0;
        state.analyzed = 0;
        state.verdicts = { critical: 0, high: 0, medium: 0, low: 0 };
        AGENT_ORDER.forEach(function (id) { state.agentStats[id] = { messages: 0, active: false }; });

        var queue = buildQueue(allFindings);
        state.findings = queue;
        state.aborted = false;

        /* Compute insight stats from ALL findings */
        var totalCritical = allFindings.filter(function (f) { return (f._severity_norm || '') === 'critical'; }).length;
        var totalHigh = allFindings.filter(function (f) { return (f._severity_norm || '') === 'high'; }).length;
        var totalPrograms = (window.PROGRAMS || []).length;

        var html = '<div class="wr-grid">';

        /* ═══ LEFT SIDEBAR ═══ */
        html += '<div class="wr-sidebar">';

        /* Session stats */
        html += '<div class="wr-sb-section">';
        html += '<div class="wr-sb-title">Session Stats</div>';
        html += '<div class="wr-stat-grid">';
        html += '<div class="wr-stat"><div class="wr-stat-val" style="color:var(--accent-primary);" id="wr-stat-analyzed">0</div><div class="wr-stat-lbl">Analyzed</div></div>';
        html += '<div class="wr-stat"><div class="wr-stat-val" style="color:var(--text-muted);" id="wr-stat-queue">' + queue.length + '</div><div class="wr-stat-lbl">In Queue</div></div>';
        html += '<div class="wr-stat"><div class="wr-stat-val" style="color:var(--critical);" id="wr-stat-critical">0</div><div class="wr-stat-lbl">Critical</div></div>';
        html += '<div class="wr-stat"><div class="wr-stat-val" style="color:var(--high);" id="wr-stat-high">0</div><div class="wr-stat-lbl">High</div></div>';
        html += '</div>';
        html += '</div>';

        /* Intelligence overview */
        html += '<div class="wr-sb-section">';
        html += '<div class="wr-sb-title">Intel Overview</div>';
        html += '<div style="font-size:.78rem;color:var(--text-secondary);line-height:1.6;">';
        html += '<div style="display:flex;justify-content:space-between;margin-bottom:4px;"><span>Programs Scanned</span><strong style="color:var(--text-primary);">' + totalPrograms + '</strong></div>';
        html += '<div style="display:flex;justify-content:space-between;margin-bottom:4px;"><span>Total Findings</span><strong style="color:var(--text-primary);">' + formatNum(allFindings.length) + '</strong></div>';
        html += '<div style="display:flex;justify-content:space-between;margin-bottom:4px;"><span>Critical Vulns</span><strong style="color:var(--critical);">' + totalCritical + '</strong></div>';
        html += '<div style="display:flex;justify-content:space-between;"><span>High Severity</span><strong style="color:var(--high);">' + totalHigh + '</strong></div>';
        html += '</div>';
        html += '</div>';

        /* Agent Roster */
        html += '<div class="wr-sb-section" style="flex-shrink:0;">';
        html += '<div class="wr-sb-title">Agent Council</div>';
        AGENT_ORDER.forEach(function (id) {
            var a = AGENTS[id];
            html += '<div class="wr-agent-row" id="wr-ar-' + id + '" style="--agent-color:' + a.color + ';">';
            html += '<div class="wr-agent-dot" style="background:' + a.gradient + ';">' + a.avatar + '</div>';
            html += '<div class="wr-agent-meta">';
            html += '<div class="wr-agent-name" style="color:' + a.color + ';">' + a.name + '</div>';
            html += '<div class="wr-agent-role">' + a.role + '</div>';
            html += '</div>';
            html += '<div class="wr-agent-count" id="wr-ac-' + id + '" title="Messages sent">0</div>';
            html += '</div>';
        });
        html += '</div>';

        /* Finding Queue */
        html += '<div class="wr-sb-section" style="flex:1;display:flex;flex-direction:column;overflow:hidden;padding-bottom:0;">';
        html += '<div class="wr-sb-title">Analysis Queue (' + queue.length + ')</div>';
        html += '<div class="wr-queue">';
        queue.forEach(function (f, i) {
            var sev = (f._severity_norm || 'medium').toUpperCase();
            html += '<div class="wr-queue-item" data-idx="' + i + '">';
            html += '<span class="wr-queue-sev" style="background:' + sevColor(sev) + '22;color:' + sevColor(sev) + ';">' + sev.slice(0, 4) + '</span>';
            html += '<span class="wr-queue-text">' + esc((f.vulnerability_type || 'Unknown') + ' — ' + (f._program_name || '')) + '</span>';
            html += '<span class="wr-queue-check"></span>';
            html += '</div>';
        });
        html += '</div>';
        html += '</div>';

        /* Controls */
        html += '<div class="wr-controls">';
        html += '<button class="wr-btn is-primary" id="wr-play-btn">▸ Auto-Play</button>';
        html += '<button class="wr-btn" id="wr-pause-btn">⏸ Pause</button>';
        html += '<select id="wr-speed" class="wr-btn" style="padding:6px 8px;">';
        html += '<option value="0.5">0.5×</option>';
        html += '<option value="1" selected>1×</option>';
        html += '<option value="2">2×</option>';
        html += '<option value="4">4×</option>';
        html += '</select>';
        html += '</div>';

        html += '</div>'; /* end sidebar */

        /* ═══ MAIN PANEL ═══ */
        html += '<div class="wr-main">';

        /* Top header bar */
        html += '<div class="wr-feed-header">';
        html += '<span style="width:8px;height:8px;background:#2ed573;border-radius:50%;animation:wrPulse 2s ease-in-out infinite;box-shadow:0 0 6px #2ed57380;"></span>';
        html += '<span style="font-weight:700;font-size:.88rem;color:var(--text-primary);">🏛️ Security War Room</span>';
        html += '<span style="font-size:.7rem;padding:2px 8px;background:var(--critical);color:#fff;border-radius:10px;font-weight:700;animation:wrPulse 2s ease-in-out infinite;">LIVE</span>';
        html += '<span style="flex:1;"></span>';
        html += '<span id="wr-status" style="font-size:.74rem;color:var(--text-muted);font-family:var(--font-mono);">Initializing...</span>';
        html += '</div>';

        /* Finding context bar (updates per-finding) */
        html += '<div id="wr-context" class="wr-context">';
        html += '<span style="font-size:.78rem;color:var(--text-muted);">Preparing analysis queue...</span>';
        html += '</div>';

        /* Message feed */
        html += '<div id="wr-feed" class="wr-feed-scroll"></div>';

        html += '</div>'; /* end main */
        html += '</div>'; /* end grid */

        pageEl.innerHTML = html;

        /* ── Wire up events ── */
        var feedEl = document.getElementById('wr-feed');
        var statusEl = document.getElementById('wr-status');
        var playBtn = document.getElementById('wr-play-btn');
        var pauseBtn = document.getElementById('wr-pause-btn');
        var speedSelect = document.getElementById('wr-speed');

        /* Play/Restart button */
        playBtn.addEventListener('click', function () {
            if (state.isRunning) {
                /* Stop */
                state.aborted = true;
                state.isRunning = false;
                playBtn.innerHTML = '▸ Restart';
                statusEl.innerHTML = '<span style="color:var(--critical);">Aborted</span>';
                return;
            }
            /* (Re)start from beginning */
            state.currentFindingIdx = 0;
            state.analyzed = 0;
            state.verdicts = { critical: 0, high: 0, medium: 0, low: 0 };
            AGENT_ORDER.forEach(function (id) { state.agentStats[id].messages = 0; });
            state.aborted = false;
            state.isPaused = false;
            state.autoPlay = true;
            feedEl.innerHTML = '';
            playBtn.innerHTML = '■ Stop';
            pauseBtn.innerHTML = '⏸ Pause';
            /* Reset queue item visuals */
            document.querySelectorAll('.wr-queue-item').forEach(function (el) { el.classList.remove('is-done', 'is-active'); });
            updateStats();
            autoPlayLoop(feedEl, statusEl);
        });

        /* Pause/Resume */
        pauseBtn.addEventListener('click', function () {
            if (!state.isRunning) return;
            state.isPaused = !state.isPaused;
            pauseBtn.innerHTML = state.isPaused ? '▸ Resume' : '⏸ Pause';
            if (statusEl) {
                statusEl.innerHTML = state.isPaused
                    ? '<span style="color:var(--medium);">⏸ Paused</span>'
                    : '<span style="color:var(--accent-primary);">▸ Running...</span>';
            }
        });

        /* Speed control */
        speedSelect.addEventListener('change', function () {
            state.speed = parseFloat(speedSelect.value);
        });

        /* Queue item click: jump to that finding */
        document.querySelector('.wr-queue').addEventListener('click', function (e) {
            var item = e.target.closest('.wr-queue-item');
            if (!item || state.isRunning) return;
            var idx = parseInt(item.dataset.idx, 10);
            state.currentFindingIdx = idx;
            state.aborted = false;
            state.isPaused = false;
            state.autoPlay = false; /* one-shot */
            feedEl.innerHTML = '';
            playBtn.innerHTML = '■ Stop';
            state.isRunning = true;
            highlightQueueItem(idx);
            runDebateForFinding(state.findings[idx], feedEl, statusEl).then(function () {
                state.isRunning = false;
                playBtn.innerHTML = '▸ Auto-Play';
                statusEl.innerHTML = '<span style="color:var(--low);">✅ Analysis complete</span>';
            });
        });

        /* ── AUTO-START after 800ms ── */
        setTimeout(function () {
            if (queue.length > 0) {
                state.autoPlay = true;
                playBtn.innerHTML = '■ Stop';
                autoPlayLoop(feedEl, statusEl);
            } else {
                statusEl.innerHTML = '<span style="color:var(--text-muted);">No findings to analyze</span>';
            }
        }, 800);
    };

})();
