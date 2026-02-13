(function () {
  'use strict';

  function esc(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function truncateAddr(addr, chars) {
    chars = chars || 4;
    if (!addr || addr.length <= chars * 2 + 3) return addr || '';
    return addr.slice(0, chars) + '...' + addr.slice(-chars);
  }

  function formatTimestamp(iso) {
    if (!iso) return '\u2014';
    try {
      var d = new Date(iso);
      return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) +
        ' ' + d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch (e) {
      return iso;
    }
  }

  function sectionHeader(opts) {
    return '<div class="section-header"><h2 class="section-header__title">' + esc(opts.title) + '</h2>' +
      (opts.subtitle ? '<p class="section-header__subtitle">' + esc(opts.subtitle) + '</p>' : '') + '</div>';
  }

  function statCard(opts) {
    var variant = opts.variant || '';
    var cls = variant ? ' stat-card--' + variant : '';
    var icon = opts.iconName && window.Icons ? window.Icons.svg(opts.iconName, 22) : '';
    return '<div class="stat-card' + cls + '">' +
      (icon ? '<div class="stat-card__icon">' + icon + '</div>' : '') +
      '<div class="stat-card__value">' + opts.value + '</div>' +
      '<div class="stat-card__label">' + esc(opts.label) + '</div>' +
      (opts.context ? '<div class="stat-card__context">' + esc(opts.context) + '</div>' : '') +
      '</div>';
  }

  function statGrid(cards) {
    return '<div class="stat-grid">' + cards.join('') + '</div>';
  }

  function card(opts) {
    var header = opts.title ? '<div class="card__header"><div><div class="card__title">' + opts.title + '</div>' +
      (opts.subtitle ? '<div class="card__subtitle">' + opts.subtitle + '</div>' : '') +
      '</div>' + (opts.actions || '') + '</div>' : '';
    return '<div class="card">' + header + '<div class="card__body">' + (opts.body || '') + '</div></div>';
  }

  function severityBadge(level) {
    var l = (level || 'medium').toLowerCase();
    return '<span class="severity-badge severity-badge--' + l + '"><span class="severity-badge__dot"></span>' + l.toUpperCase() + '</span>';
  }

  function findingCard(ex) {
    var I = window.Icons;
    return '<div class="finding-card" data-uid="' + (ex._uid || '') + '">' +
      '<div class="finding-card__header">' + severityBadge(ex._severity_norm || ex.severity_label || 'MEDIUM') +
      '<span style="font-family:var(--font-mono,monospace);font-size:0.75rem;color:var(--text-muted);">' + esc(ex.id || '') + '</span></div>' +
      '<div class="finding-card__title">' + esc(ex.vulnerability_type || 'Unknown') + '</div>' +
      '<div class="finding-card__meta">' +
      '<span>' + (I ? I.svg('folder', 12) : '') + ' ' + esc(ex.category || 'General') + '</span>' +
      '<span>' + (I ? I.svg('code', 12) : '') + ' ' + esc(ex.instruction || 'N/A') + '</span>' +
      '<span>' + (I ? I.svg('mapPin', 12) : '') + ' ' + truncateAddr(ex._program_id, 4) + '</span></div>' +
      '<div class="finding-card__desc">' + esc(ex.description || '') + '</div></div>';
  }

  function findingDetail(ex) {
    var I = window.Icons;
    return '<div class="finding-detail">' +
      '<div style="display:flex;align-items:center;gap:12px;margin-bottom:24px;">' +
      severityBadge(ex._severity_norm || ex.severity_label || 'MEDIUM') +
      '<span style="font-family:monospace;font-size:0.8rem;color:var(--text-muted);">' + esc(ex.id) + '</span></div>' +
      '<h3 style="font-size:1.3rem;font-weight:700;color:var(--text-pure);margin-bottom:8px;">' + esc(ex.vulnerability_type) + '</h3>' +
      '<div style="display:flex;gap:16px;font-size:0.8rem;color:var(--text-muted);margin-bottom:24px;">' +
      '<span>' + esc(ex.category) + '</span><span>Instruction: <code>' + esc(ex.instruction) + '</code></span>' +
      '<span>Program: <code>' + truncateAddr(ex._program_id, 6) + '</code></span></div>' +
      '<div class="finding-detail__section"><div class="finding-detail__section-title">' + (I ? I.svg('info', 14) : '') + ' Description</div>' +
      '<div class="finding-detail__section-body">' + esc(ex.description) + '</div></div>' +
      '<div class="finding-detail__section"><div class="finding-detail__section-title">' + (I ? I.svg('sword', 14) : '') + ' Attack Scenario</div>' +
      '<div class="finding-detail__section-body">' + esc(ex.attack_scenario) + '</div></div>' +
      '<div class="finding-detail__section"><div class="finding-detail__section-title">' + (I ? I.svg('check', 14) : '') + ' Recommended Fix</div>' +
      '<div class="code-block"><code>' + esc(ex.secure_fix) + '</code></div></div>' +
      '<div class="finding-detail__section"><div class="finding-detail__section-title">' + (I ? I.svg('trendDown', 14) : '') + ' Economic Impact</div>' +
      '<div class="finding-detail__section-body">' + esc(ex.economic_impact) + '</div></div></div>';
  }

  function dataTable(opts) {
    var cols = opts.columns || [];
    var rows = opts.rows || [];
    if (rows.length === 0) return '<div style="padding:48px 0;text-align:center;"><p class="text-muted">No data matching current filters.</p></div>';
    var ths = cols.map(function(c) { return '<th class="data-table__th">' + esc(c.label) + '</th>'; }).join('');
    var trs = rows.map(function(row) {
      var tds = cols.map(function(c) {
        var val = row[c.key];
        var rendered = c.render ? c.render(val, row) : esc(val);
        return '<td class="data-table__td">' + rendered + '</td>';
      }).join('');
      return '<tr class="data-table__tr" data-uid="' + (row._uid || '') + '" style="cursor:pointer;">' + tds + '</tr>';
    }).join('');
    return '<div class="data-table-wrapper"><table class="data-table"><thead><tr>' + ths + '</tr></thead><tbody>' + trs + '</tbody></table></div>';
  }

  function searchInput(opts) {
    var I = window.Icons;
    return '<div class="search-field"><span class="search-field__icon">' + (I ? I.svg('search', 16) : '') +
      '</span><input type="text" id="' + (opts.id || '') + '" class="search-field__input" placeholder="' + esc(opts.placeholder || 'Search...') + '" /></div>';
  }

  function filterGroup(opts) {
    var options = (opts.options || []).map(function(o) {
      return '<option value="' + esc(o.value) + '">' + esc(o.label) + '</option>';
    }).join('');
    return '<div class="filter-group"><label class="filter-group__label">' + esc(opts.label) +
      '</label><select id="' + (opts.id || '') + '" class="filter-group__select">' + options + '</select></div>';
  }

  function progressBar(value, max, opts) {
    opts = opts || {};
    var pct = Math.min((value / (max || 1)) * 100, 100);
    var color = opts.color || 'var(--accent-primary)';
    return '<div class="progress-bar" title="' + pct.toFixed(1) + '%"><div class="progress-bar__fill" style="width:' + pct + '%;background:' + color + ';"></div></div>';
  }

  function kvRow(label, value) {
    return '<div class="kv-row"><span class="kv-row__label">' + esc(label) + '</span><span class="kv-row__value">' + value + '</span></div>';
  }

  function statusDot(status) {
    var colors = { pass: 'var(--low)', fail: 'var(--critical)', warn: 'var(--medium)', running: 'var(--info)', unknown: 'var(--text-muted)' };
    var c = colors[status] || colors.unknown;
    return '<span class="status-dot" style="background:' + c + ';box-shadow:0 0 6px ' + c + ';"></span>';
  }

  function miniCard(opts) {
    var I = window.Icons;
    var statusHtml = opts.status ? statusDot(opts.status) : '';
    return '<div class="mini-card ' + (opts.className || '') + '">' +
      '<div class="mini-card__header">' +
      (opts.icon ? '<span class="mini-card__icon">' + (I ? I.svg(opts.icon, 18) : '') + '</span>' : '') +
      '<span class="mini-card__title">' + esc(opts.title) + '</span>' + statusHtml + '</div>' +
      (opts.value !== undefined ? '<div class="mini-card__value">' + opts.value + '</div>' : '') +
      (opts.body || '') + '</div>';
  }

  function codeOutput(lines) {
    var content = (lines || []).map(function(l) { return esc(l); }).join('\n');
    return '<div class="terminal-output"><pre><code>' + content + '</code></pre></div>';
  }

  window.Components = {
    sectionHeader: sectionHeader,
    statGrid: statGrid,
    statCard: statCard,
    card: card,
    severityBadge: severityBadge,
    findingCard: findingCard,
    findingDetail: findingDetail,
    dataTable: dataTable,
    searchInput: searchInput,
    filterGroup: filterGroup,
    truncateAddr: truncateAddr,
    formatTimestamp: formatTimestamp,
    progressBar: progressBar,
    kvRow: kvRow,
    statusDot: statusDot,
    miniCard: miniCard,
    codeOutput: codeOutput,
    esc: esc
  };

})();
