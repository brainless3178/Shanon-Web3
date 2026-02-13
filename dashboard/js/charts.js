(function () {
  'use strict';

  const NS = 'http://www.w3.org/2000/svg';
  const COLORS = {
    critical: '#ff3355',
    high: '#ff8833',
    medium: '#ffcc33',
    low: '#33dd99',
    info: '#3399ff',
    accent: '#14f195',
    secondary: '#9945ff',
    grid: 'rgba(255, 255, 255, 0.05)',
    text: '#a0a0a0',
    dimText: '#555555',
    bg: '#0c0c0c',
    surface: '#161616',
    proven: '#14f195',
    unknown: '#ffcc33',
    violated: '#ff3355'
  };

  function createEl(tag, attrs = {}) {
    const el = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    return el;
  }

  function clear(container) {
    if (typeof container === 'string') container = document.querySelector(container);
    if (container) container.innerHTML = '';
    return container;
  }

  function donut(container, data, size = 200) {
    const el = clear(container);
    if (!el) return;

    // Normalize data: accept both array [{label, value, color}] and object {critical: N}
    let slices = [];
    if (Array.isArray(data)) {
      slices = data.filter(d => d.value > 0).map(d => ({
        label: d.label || '',
        value: d.value,
        color: d.color || COLORS.accent
      }));
    } else {
      const sortedKeys = ['critical', 'high', 'medium', 'low'];
      sortedKeys.forEach(key => {
        const val = data[key] || 0;
        if (val > 0) slices.push({ label: key, value: val, color: COLORS[key] });
      });
    }

    const total = slices.reduce((s, d) => s + d.value, 0);
    if (total === 0) return;

    /* Wrapper for chart + legend side by side (or stacked on small containers) */
    const wrapper = document.createElement('div');
    wrapper.style.cssText = 'display:flex;align-items:center;gap:20px;flex-wrap:wrap;justify-content:center;';

    const svg = createEl('svg', {
      width: size, height: size,
      viewBox: `0 0 ${size} ${size}`,
      style: `max-width:${size}px;flex-shrink:0;`
    });

    const cx = size / 2;
    const cy = size / 2;
    const r = (size * 0.4);
    const strokeWidth = size * 0.12;
    const circumference = 2 * Math.PI * r;

    let offset = 0;
    const circles = [];

    slices.forEach((slice, idx) => {
      const percentage = slice.value / total;
      const sliceLen = percentage * circumference;
      const color = slice.color;

      const circle = createEl('circle', {
        cx, cy, r,
        fill: 'none',
        stroke: color,
        'stroke-width': strokeWidth,
        'stroke-dasharray': `${sliceLen} ${circumference}`,
        'stroke-dashoffset': -offset,
        'stroke-linecap': 'butt',
        transform: `rotate(-90 ${cx} ${cy})`,
        style: 'transition: stroke-width 0.2s ease, filter 0.2s ease;',
        'data-index': idx
      });

      circle.addEventListener('mouseenter', () => {
        circle.setAttribute('stroke-width', strokeWidth * 1.25);
        circle.style.filter = 'drop-shadow(0 0 8px ' + color + ')';
        /* Highlight corresponding legend item */
        const legendItems = el.querySelectorAll('.donut-legend-item');
        if (legendItems[idx]) legendItems[idx].style.background = 'rgba(255,255,255,0.08)';
      });
      circle.addEventListener('mouseleave', () => {
        circle.setAttribute('stroke-width', strokeWidth);
        circle.style.filter = 'none';
        const legendItems = el.querySelectorAll('.donut-legend-item');
        if (legendItems[idx]) legendItems[idx].style.background = 'transparent';
      });

      svg.appendChild(circle);
      circles.push(circle);
      offset += sliceLen;
    });

    const textGroup = createEl('g', { transform: `translate(${cx}, ${cy})` });
    const countText = createEl('text', {
      'text-anchor': 'middle',
      'dominant-baseline': 'middle',
      fill: '#ffffff',
      'font-size': size * 0.15,
      'font-weight': '700'
    });
    countText.textContent = total;
    textGroup.appendChild(countText);

    const labelText = createEl('text', {
      y: size * 0.1,
      'text-anchor': 'middle',
      fill: COLORS.text,
      'font-size': size * 0.06,
      'text-transform': 'uppercase',
      'letter-spacing': '0.1em'
    });
    labelText.textContent = 'Results';
    textGroup.appendChild(labelText);

    svg.appendChild(textGroup);
    wrapper.appendChild(svg);

    /* Legend */
    if (slices.length > 0) {
      const legend = document.createElement('div');
      legend.style.cssText = 'display:flex;flex-direction:column;gap:4px;min-width:120px;max-height:' + size + 'px;overflow-y:auto;';

      slices.forEach((slice, idx) => {
        const pct = ((slice.value / total) * 100).toFixed(1);
        const item = document.createElement('div');
        item.className = 'donut-legend-item';
        item.style.cssText = 'display:flex;align-items:center;gap:8px;padding:4px 8px;border-radius:4px;cursor:pointer;transition:background 0.2s;font-size:0.75rem;';

        item.innerHTML =
          '<span style="display:inline-block;width:10px;height:10px;border-radius:2px;flex-shrink:0;background:' + slice.color + ';"></span>' +
          '<span style="color:#e0e0e0;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">' + slice.label + '</span>' +
          '<span style="color:#888;font-size:0.7rem;white-space:nowrap;">' + slice.value + ' (' + pct + '%)</span>';

        item.addEventListener('mouseenter', () => {
          item.style.background = 'rgba(255,255,255,0.08)';
          circles[idx].setAttribute('stroke-width', strokeWidth * 1.25);
          circles[idx].style.filter = 'drop-shadow(0 0 8px ' + slice.color + ')';
        });
        item.addEventListener('mouseleave', () => {
          item.style.background = 'transparent';
          circles[idx].setAttribute('stroke-width', strokeWidth);
          circles[idx].style.filter = 'none';
        });

        legend.appendChild(item);
      });

      wrapper.appendChild(legend);
    }

    el.appendChild(wrapper);
  }

  function groupedBar(container, programs, height = 240) {
    const el = clear(container);
    if (!el || programs.length === 0) return;

    /* Sort by total findings descending, cap at top 15 */
    const sorted = [...programs]
      .map(p => ({ ...p, _total: (p.critical || 0) + (p.high || 0) + (p.medium || 0) }))
      .sort((a, b) => b._total - a._total);

    const MAX_DISPLAY = 15;
    const overflow = sorted.length > MAX_DISPLAY ? sorted.length - MAX_DISPLAY : 0;
    const visible = sorted.slice(0, MAX_DISPLAY);

    const padL = 44;
    const padB = 80;    /* extra room for rotated labels */
    const padR = 20;
    const padT = 20;
    const width = el.clientWidth || 600;
    const chartW = width - padL - padR;
    const chartH = height - padB - padT;
    const maxVal = Math.max(...visible.map(p => Math.max(p.critical || 0, p.high || 0, p.medium || 0)), 1);

    const svg = createEl('svg', {
      width: '100%', height,
      viewBox: `0 0 ${width} ${height}`
    });

    /* Grid lines + y-axis labels */
    for (let i = 0; i <= 4; i++) {
      const y = padT + chartH - (i * chartH / 4);
      const val = Math.round((maxVal / 4) * i);
      svg.appendChild(createEl('line', {
        x1: padL, y1: y, x2: width - padR, y2: y,
        stroke: COLORS.grid, 'stroke-width': 1
      }));
      const yLabel = createEl('text', {
        x: padL - 8, y: y + 3,
        fill: COLORS.dimText, 'font-size': 9, 'text-anchor': 'end'
      });
      yLabel.textContent = val;
      svg.appendChild(yLabel);
    }

    const groupW = chartW / visible.length;
    const barW = Math.min(Math.max(groupW * 0.22, 6), 18);
    const barGap = barW * 0.25;

    visible.forEach((p, i) => {
      const groupCenter = padL + (i * groupW) + (groupW / 2);
      const barSetW = 3 * barW + 2 * barGap;
      const barStartX = groupCenter - barSetW / 2;

      /* Tooltip group */
      const g = createEl('g', { style: 'cursor:pointer;' });

      /* Invisible hover area */
      const hoverRect = createEl('rect', {
        x: padL + i * groupW, y: padT,
        width: groupW, height: chartH,
        fill: 'transparent', opacity: 0
      });
      g.appendChild(hoverRect);

      ['critical', 'high', 'medium'].forEach((sev, si) => {
        const val = p[sev] || 0;
        const bH = Math.max((val / maxVal) * chartH, val > 0 ? 2 : 0);
        const x = barStartX + si * (barW + barGap);
        const y = padT + chartH - bH;

        const rect = createEl('rect', {
          x, y, width: barW, height: bH,
          fill: COLORS[sev], rx: 2,
          style: 'transition: opacity 0.2s ease;'
        });
        g.appendChild(rect);
      });

      /* Hover effects */
      g.addEventListener('mouseenter', () => {
        g.querySelectorAll('rect:not([fill="transparent"])').forEach(r => r.setAttribute('opacity', '0.85'));
        /* Show tooltip */
        let tt = el.querySelector('.bar-tooltip');
        if (!tt) {
          tt = document.createElement('div');
          tt.className = 'bar-tooltip';
          tt.style.cssText = 'position:absolute;padding:8px 12px;background:rgba(0,0,0,0.9);border:1px solid rgba(255,255,255,0.15);border-radius:6px;font-size:0.75rem;color:#fff;pointer-events:none;z-index:50;white-space:nowrap;backdrop-filter:blur(8px);';
          el.style.position = 'relative';
          el.appendChild(tt);
        }
        tt.innerHTML = '<strong>' + p.name + '</strong><br>' +
          '<span style="color:' + COLORS.critical + '">● Critical: ' + (p.critical || 0) + '</span>  ' +
          '<span style="color:' + COLORS.high + '">● High: ' + (p.high || 0) + '</span>  ' +
          '<span style="color:' + COLORS.medium + '">● Medium: ' + (p.medium || 0) + '</span>';
        tt.style.display = 'block';
        const pct = (groupCenter / width) * 100;
        tt.style.left = pct + '%';
        tt.style.top = '0';
        tt.style.transform = 'translateX(-50%)';
      });
      g.addEventListener('mouseleave', () => {
        g.querySelectorAll('rect:not([fill="transparent"])').forEach(r => r.setAttribute('opacity', '1'));
        const tt = el.querySelector('.bar-tooltip');
        if (tt) tt.style.display = 'none';
      });

      svg.appendChild(g);

      /* Rotated x-axis label */
      const truncName = p.name.length > 14 ? p.name.slice(0, 12) + '..' : p.name;
      const label = createEl('text', {
        x: 0, y: 0,
        fill: COLORS.text, 'font-size': 9.5,
        'text-anchor': 'end',
        transform: `translate(${groupCenter + 4}, ${padT + chartH + 12}) rotate(-45)`
      });
      label.textContent = truncName;
      svg.appendChild(label);
    });

    /* Overflow indicator */
    if (overflow > 0) {
      const moreText = createEl('text', {
        x: width - padR, y: padT + chartH + 14,
        fill: COLORS.accent, 'font-size': 10, 'font-weight': '600',
        'text-anchor': 'end'
      });
      moreText.textContent = '+' + overflow + ' more';
      svg.appendChild(moreText);
    }

    /* Legend at top right */
    const legendY = padT + 8;
    const legendX = width - padR - 10;
    [['Critical', COLORS.critical], ['High', COLORS.high], ['Medium', COLORS.medium]].forEach((pair, i) => {
      const lx = legendX - (2 - i) * 72;
      svg.appendChild(createEl('rect', { x: lx, y: legendY - 5, width: 8, height: 8, fill: pair[1], rx: 2 }));
      const lt = createEl('text', { x: lx + 12, y: legendY + 2, fill: COLORS.text, 'font-size': 9 });
      lt.textContent = pair[0];
      svg.appendChild(lt);
    });

    el.appendChild(svg);
  }

  function heatmap(container, matrix, opts) {
    const el = clear(container);
    if (!el) return;

    // Support matrix as {rows, cols, cells} object or raw 2D array
    let rows, cols, cells;
    if (matrix && typeof matrix === 'object' && !Array.isArray(matrix) && matrix.rows) {
      rows = matrix.rows || [];
      cols = matrix.cols || [];
      cells = matrix.cells || [];
    } else {
      rows = opts.rows || [];
      cols = opts.cols || [];
      cells = Array.isArray(matrix) ? matrix : [];
    }

    if (rows.length === 0 || cols.length === 0) return;

    const cellS = 40;
    const padL = 120;
    const padT = 50;

    const svg = createEl('svg', {
      width: '100%', height: padT + (rows.length * cellS) + 20,
      viewBox: `0 0 ${padL + (cols.length * cellS) + 20} ${padT + (rows.length * cellS) + 20}`
    });

    cols.forEach((col, ci) => {
      const t = createEl('text', {
        x: padL + (ci * cellS) + cellS / 2,
        y: padT - 15,
        fill: COLORS.text,
        'font-size': 9,
        'text-anchor': 'middle'
      });
      const label = typeof col === 'string' ? col : String(col);
      t.textContent = label.length > 12 ? label.slice(0, 10) + '..' : label;
      svg.appendChild(t);
    });

    // Flatten all cell values to find max
    let allVals = [];
    cells.forEach(row => {
      if (Array.isArray(row)) {
        row.forEach(c => {
          allVals.push(typeof c === 'object' ? (c.value || 0) : (c || 0));
        });
      }
    });
    const maxVal = Math.max(...allVals, 1);

    rows.forEach((row, ri) => {
      const rt = createEl('text', {
        x: padL - 15,
        y: padT + (ri * cellS) + cellS / 2,
        fill: COLORS.text,
        'font-size': 10,
        'text-anchor': 'end',
        'dominant-baseline': 'middle'
      });
      rt.textContent = typeof row === 'string' ? row : String(row);
      svg.appendChild(rt);

      cols.forEach((col, ci) => {
        const cellData = cells[ri] ? cells[ri][ci] : 0;
        const val = typeof cellData === 'object' ? (cellData.value || 0) : (cellData || 0);
        const cellColor = (typeof cellData === 'object' && cellData.color) ? cellData.color : COLORS.accent;
        const opacity = 0.1 + (val / maxVal) * 0.9;
        const fill = val > 0 ? cellColor : 'rgba(255,255,255,0.02)';

        const rect = createEl('rect', {
          x: padL + (ci * cellS) + 2,
          y: padT + (ri * cellS) + 2,
          width: cellS - 4,
          height: cellS - 4,
          fill: fill,
          opacity: opacity,
          rx: 4
        });
        svg.appendChild(rect);

        if (val > 0) {
          const vt = createEl('text', {
            x: padL + (ci * cellS) + cellS / 2,
            y: padT + (ri * cellS) + cellS / 2,
            fill: '#fff',
            'font-size': 10,
            'font-weight': '700',
            'text-anchor': 'middle',
            'dominant-baseline': 'middle'
          });
          vt.textContent = val;
          svg.appendChild(vt);
        }
      });
    });

    el.appendChild(svg);
  }

  function gauge(container, value, max, opts = {}) {
    const el = clear(container);
    if (!el) return;

    const size = opts.size || 180;
    const label = opts.label || '';
    const color = opts.color || COLORS.accent;
    const bgColor = opts.bgColor || 'rgba(255,255,255,0.06)';
    const thickness = opts.thickness || 12;

    const svg = createEl('svg', {
      width: '100%', height: size,
      viewBox: `0 0 ${size} ${size}`,
      style: 'max-width: 100%;'
    });

    const cx = size / 2;
    const cy = size / 2;
    const r = (size / 2) - thickness - 8;
    const circumference = 2 * Math.PI * r;
    const startAngle = 135;
    const sweepAngle = 270;
    const fraction = Math.min(value / max, 1);
    const arcLen = (sweepAngle / 360) * circumference;
    const filledLen = fraction * arcLen;

    const bgCircle = createEl('circle', {
      cx, cy, r,
      fill: 'none',
      stroke: bgColor,
      'stroke-width': thickness,
      'stroke-dasharray': `${arcLen} ${circumference}`,
      'stroke-dashoffset': 0,
      'stroke-linecap': 'round',
      transform: `rotate(${startAngle} ${cx} ${cy})`
    });
    svg.appendChild(bgCircle);

    const fgCircle = createEl('circle', {
      cx, cy, r,
      fill: 'none',
      stroke: color,
      'stroke-width': thickness,
      'stroke-dasharray': `${filledLen} ${circumference}`,
      'stroke-dashoffset': 0,
      'stroke-linecap': 'round',
      transform: `rotate(${startAngle} ${cx} ${cy})`,
      style: `transition: stroke-dasharray 1s ease-out; filter: drop-shadow(0 0 6px ${color});`
    });
    svg.appendChild(fgCircle);

    const valText = createEl('text', {
      x: cx, y: cy - 4,
      'text-anchor': 'middle',
      'dominant-baseline': 'middle',
      fill: '#fff',
      'font-size': size * 0.2,
      'font-weight': '700'
    });
    valText.textContent = typeof value === 'number' && value % 1 === 0 ? value : value.toFixed(1);
    svg.appendChild(valText);

    if (label) {
      const labelText = createEl('text', {
        x: cx, y: cy + size * 0.13,
        'text-anchor': 'middle',
        fill: COLORS.text,
        'font-size': size * 0.065,
        'letter-spacing': '0.08em'
      });
      labelText.textContent = label.toUpperCase();
      svg.appendChild(labelText);
    }

    el.appendChild(svg);
  }

  function sparkline(container, data, opts = {}) {
    const el = clear(container);
    if (!el || !data || data.length < 2) return;

    const width = opts.width || el.clientWidth || 200;
    const height = opts.height || 40;
    const color = opts.color || COLORS.accent;
    const filled = opts.filled !== false;

    const svg = createEl('svg', {
      width: '100%', height,
      viewBox: `0 0 ${width} ${height}`,
      style: 'max-width: 100%;'
    });

    const min = Math.min(...data);
    const max = Math.max(...data);
    const range = max - min || 1;
    const pad = 2;

    const points = data.map((v, i) => {
      const x = pad + (i / (data.length - 1)) * (width - pad * 2);
      const y = pad + (1 - (v - min) / range) * (height - pad * 2);
      return `${x},${y}`;
    });

    if (filled) {
      const areaPath = `M${pad},${height - pad} L${points.join(' L')} L${width - pad},${height - pad} Z`;
      const area = createEl('path', {
        d: areaPath,
        fill: color,
        opacity: '0.1'
      });
      svg.appendChild(area);
    }

    const polyline = createEl('polyline', {
      points: points.join(' '),
      fill: 'none',
      stroke: color,
      'stroke-width': 1.5,
      'stroke-linecap': 'round',
      'stroke-linejoin': 'round'
    });
    svg.appendChild(polyline);

    const lastIdx = data.length - 1;
    const lastX = pad + (lastIdx / (data.length - 1)) * (width - pad * 2);
    const lastY = pad + (1 - (data[lastIdx] - min) / range) * (height - pad * 2);
    const dot = createEl('circle', {
      cx: lastX, cy: lastY, r: 2.5,
      fill: color,
      style: `filter: drop-shadow(0 0 4px ${color});`
    });
    svg.appendChild(dot);

    el.appendChild(svg);
  }

  function timeline(container, events, opts = {}) {
    const el = clear(container);
    if (!el || !events || events.length === 0) return;

    const wrapper = document.createElement('div');
    wrapper.className = 'chart-timeline';

    events.forEach((evt, i) => {
      const isLast = i === events.length - 1;
      const color = evt.color || COLORS.accent;
      const node = document.createElement('div');
      node.className = 'chart-timeline__item' + (isLast ? ' chart-timeline__item--last' : '');
      node.innerHTML = `
        <div class="chart-timeline__line" style="--line-color: ${color};"></div>
        <div class="chart-timeline__dot" style="background: ${color}; box-shadow: 0 0 8px ${color};"></div>
        <div class="chart-timeline__content">
          <div class="chart-timeline__time">${evt.time || ''}</div>
          <div class="chart-timeline__title">${evt.title || evt.label || ''}</div>
          ${evt.description ? `<div class="chart-timeline__desc">${evt.description}</div>` : ''}
        </div>
      `;
      wrapper.appendChild(node);
    });

    el.appendChild(wrapper);
  }

  function flowGraph(container, nodes, edges, opts = {}) {
    const el = clear(container);
    if (!el) return;

    const width = opts.width || el.clientWidth || 600;
    const height = opts.height || 400;
    const nodeW = opts.nodeWidth || 140;
    const nodeH = opts.nodeHeight || 44;

    const svg = createEl('svg', {
      width: '100%', height,
      viewBox: `0 0 ${width} ${height}`,
      style: 'max-width: 100%;'
    });

    const defs = createEl('defs');
    const marker = createEl('marker', {
      id: 'flow-arrow',
      viewBox: '0 0 10 10',
      refX: '8', refY: '5',
      markerWidth: '6', markerHeight: '6',
      orient: 'auto-start-reverse'
    });
    const arrowPath = createEl('path', {
      d: 'M 0 0 L 10 5 L 0 10 z',
      fill: COLORS.accent
    });
    marker.appendChild(arrowPath);
    defs.appendChild(marker);

    const taintMarker = createEl('marker', {
      id: 'flow-arrow-taint',
      viewBox: '0 0 10 10',
      refX: '8', refY: '5',
      markerWidth: '6', markerHeight: '6',
      orient: 'auto-start-reverse'
    });
    const taintArrow = createEl('path', {
      d: 'M 0 0 L 10 5 L 0 10 z',
      fill: COLORS.critical
    });
    taintMarker.appendChild(taintArrow);
    defs.appendChild(taintMarker);
    svg.appendChild(defs);

    // Auto-layout nodes if x,y not provided
    const needsLayout = nodes.some(n => n.x === undefined || n.y === undefined);
    if (needsLayout) {
      // Group by type: sources on top, process in middle, sinks at bottom
      const layers = { source: [], process: [], sink: [], other: [] };
      nodes.forEach(n => {
        const t = (n.type || 'other').toLowerCase();
        if (layers[t]) layers[t].push(n);
        else layers.other.push(n);
      });
      // Merge other into process
      layers.process = layers.process.concat(layers.other);
      const layerOrder = [layers.source, layers.process, layers.sink].filter(l => l.length > 0);
      const vGap = layerOrder.length > 1 ? (height - 40 - nodeH) / (layerOrder.length - 1) : 0;
      layerOrder.forEach((layer, li) => {
        const y = 20 + li * vGap;
        const totalW = layer.length * nodeW + (layer.length - 1) * 20;
        const startX = Math.max(10, (width - totalW) / 2);
        layer.forEach((node, ni) => {
          node.x = startX + ni * (nodeW + 20);
          node.y = y;
        });
      });
    }

    edges.forEach(edge => {
      const fromNode = nodes.find(n => n.id === edge.from);
      const toNode = nodes.find(n => n.id === edge.to);
      if (!fromNode || !toNode) return;

      const x1 = fromNode.x + nodeW / 2;
      const y1 = fromNode.y + nodeH;
      const x2 = toNode.x + nodeW / 2;
      const y2 = toNode.y;

      const midY = (y1 + y2) / 2;
      const edgeColor = edge.tainted ? COLORS.critical : (edge.color || COLORS.accent);
      const markerId = edge.tainted ? 'flow-arrow-taint' : 'flow-arrow';

      const path = createEl('path', {
        d: `M ${x1} ${y1} C ${x1} ${midY}, ${x2} ${midY}, ${x2} ${y2}`,
        fill: 'none',
        stroke: edgeColor,
        'stroke-width': edge.tainted ? 2 : 1.5,
        'stroke-dasharray': edge.tainted ? '' : '4 2',
        opacity: edge.tainted ? 1 : 0.5,
        'marker-end': `url(#${markerId})`,
        style: edge.tainted ? `filter: drop-shadow(0 0 4px ${edgeColor});` : ''
      });
      svg.appendChild(path);

      if (edge.label) {
        const lbl = createEl('text', {
          x: (x1 + x2) / 2 + 8,
          y: midY - 4,
          fill: COLORS.dimText,
          'font-size': 9,
          'text-anchor': 'middle'
        });
        lbl.textContent = edge.label;
        svg.appendChild(lbl);
      }
    });

    nodes.forEach(node => {
      const color = node.tainted ? COLORS.critical : (node.color || COLORS.accent);
      const bgColor = node.tainted ? 'rgba(255,51,85,0.12)' : 'rgba(20,241,149,0.08)';

      const rect = createEl('rect', {
        x: node.x, y: node.y,
        width: nodeW, height: nodeH,
        rx: 8,
        fill: bgColor,
        stroke: color,
        'stroke-width': node.tainted ? 2 : 1,
        style: node.tainted ? `filter: drop-shadow(0 0 6px ${color});` : ''
      });
      svg.appendChild(rect);

      const text = createEl('text', {
        x: node.x + nodeW / 2,
        y: node.y + nodeH / 2 - 4,
        fill: '#fff',
        'font-size': 11,
        'font-weight': '600',
        'text-anchor': 'middle',
        'dominant-baseline': 'middle'
      });
      text.textContent = node.label || node.id;
      svg.appendChild(text);

      if (node.sublabel) {
        const sub = createEl('text', {
          x: node.x + nodeW / 2,
          y: node.y + nodeH / 2 + 10,
          fill: COLORS.dimText,
          'font-size': 8,
          'text-anchor': 'middle'
        });
        sub.textContent = node.sublabel;
        svg.appendChild(sub);
      }
    });

    el.appendChild(svg);
  }

  function coverageBar(container, data, opts = {}) {
    const el = clear(container);
    if (!el || !data) return;

    const height = opts.height || 28;
    const total = data.reduce((s, d) => s + d.value, 0) || 1;

    const wrapper = document.createElement('div');
    wrapper.className = 'coverage-bar';
    wrapper.style.height = height + 'px';

    data.forEach(segment => {
      const pct = (segment.value / total) * 100;
      if (pct <= 0) return;
      const seg = document.createElement('div');
      seg.className = 'coverage-bar__segment';
      seg.style.width = pct + '%';
      seg.style.background = segment.color || COLORS.accent;
      seg.title = `${segment.label}: ${segment.value} (${pct.toFixed(1)}%)`;
      wrapper.appendChild(seg);
    });

    el.appendChild(wrapper);

    const legend = document.createElement('div');
    legend.className = 'coverage-bar__legend';
    data.forEach(segment => {
      const item = document.createElement('span');
      item.className = 'coverage-bar__legend-item';
      item.innerHTML = `<span class="coverage-bar__legend-dot" style="background:${segment.color || COLORS.accent};"></span>${segment.label}: ${segment.value}`;
      legend.appendChild(item);
    });
    el.appendChild(legend);
  }

  function treemap(container, data, opts = {}) {
    const el = clear(container);
    if (!el || !data || data.length === 0) return;

    const width = opts.width || el.clientWidth || 500;
    const height = opts.height || 260;
    const total = data.reduce((s, d) => s + d.value, 0) || 1;

    const sorted = [...data].sort((a, b) => b.value - a.value);
    const wrapper = document.createElement('div');
    wrapper.className = 'treemap';
    wrapper.style.width = '100%';
    wrapper.style.height = height + 'px';

    let x = 0;
    const gap = 3;
    sorted.forEach((item, i) => {
      const pct = item.value / total;
      const w = Math.max(pct * (width - gap * (sorted.length - 1)), 30);
      const cell = document.createElement('div');
      cell.className = 'treemap__cell';
      cell.style.width = w + 'px';
      cell.style.height = '100%';
      cell.style.background = item.color || COLORS.accent;
      cell.style.opacity = 0.15 + (pct * 0.85);
      cell.title = `${item.label}: ${item.value}`;
      cell.innerHTML = `
        <span class="treemap__cell-label">${item.label}</span>
        <span class="treemap__cell-value">${item.value}</span>
      `;
      wrapper.appendChild(cell);
    });

    el.appendChild(wrapper);
  }

  window.Charts = {
    donut,
    groupedBar,
    heatmap,
    gauge,
    sparkline,
    timeline,
    flowGraph,
    coverageBar,
    treemap,
    COLORS
  };

})();


