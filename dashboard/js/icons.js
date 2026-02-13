(function () {
  'use strict';

  function open(s, className) {
    const cls = className ? ` class="${className}"` : '';
    return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"${cls}>`;
  }

  const C = '</svg>';

  const lib = {
    overview: (size = 20) => open(size) +
      '<rect x="3" y="3" width="7" height="7" rx="1"/>' +
      '<rect x="14" y="3" width="7" height="7" rx="1"/>' +
      '<rect x="3" y="14" width="7" height="7" rx="1"/>' +
      '<rect x="14" y="14" width="7" height="7" rx="1"/>' + C,

    programs: (size = 20) => open(size) +
      '<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>' +
      '<polyline points="3.27 6.96 12 12.01 20.73 6.96"/>' +
      '<line x1="12" y1="22.08" x2="12" y2="12"/>' + C,

    findings: (size = 20) => open(size) +
      '<circle cx="12" cy="12" r="10"/>' +
      '<circle cx="12" cy="12" r="6"/>' +
      '<circle cx="12" cy="12" r="2"/>' +
      '<line x1="12" y1="2" x2="12" y2="4"/>' +
      '<line x1="12" y1="20" x2="12" y2="22"/>' +
      '<line x1="2" y1="12" x2="4" y2="12"/>' +
      '<line x1="20" y1="12" x2="22" y2="12"/>' + C,

    'risk-matrix': (size = 20) => open(size) +
      '<rect x="3" y="3" width="18" height="18" rx="2"/>' +
      '<line x1="3" y1="9" x2="21" y2="9"/>' +
      '<line x1="3" y1="15" x2="21" y2="15"/>' +
      '<line x1="9" y1="3" x2="9" y2="21"/>' +
      '<line x1="15" y1="3" x2="15" y2="21"/>' +
      '<line x1="3" y1="21" x2="21" y2="3"/>' + C,

    'taint-analysis': (size = 20) => open(size) +
      '<line x1="6" y1="3" x2="6" y2="15"/>' +
      '<circle cx="18" cy="6" r="3"/>' +
      '<circle cx="6" cy="18" r="3"/>' +
      '<path d="M6 6a9 9 0 0 0 9 9"/>' + C,

    triage: (size = 20) => open(size) +
      '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>' +
      '<polyline points="14 2 14 8 20 8"/>' +
      '<line x1="9" y1="15" x2="15" y2="15"/>' +
      '<line x1="9" y1="11" x2="13" y2="11"/>' +
      '<path d="M9 19l2 2 4-4"/>' + C,

    dataflow: (size = 20) => open(size) +
      '<circle cx="5" cy="6" r="3"/>' +
      '<circle cx="19" cy="6" r="3"/>' +
      '<circle cx="12" cy="18" r="3"/>' +
      '<path d="M5 9v3a3 3 0 0 0 3 3h8a3 3 0 0 0 3-3V9"/>' +
      '<line x1="12" y1="15" x2="12" y2="15"/>' + C,

    verification: (size = 20) => open(size) +
      '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>' +
      '<path d="M9 12l2 2 4-4"/>' + C,

    fuzzing: (size = 20) => open(size) +
      '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>' + C,

    analyzers: (size = 20) => open(size) +
      '<rect x="4" y="4" width="16" height="16" rx="2"/>' +
      '<rect x="9" y="9" width="6" height="6"/>' +
      '<line x1="9" y1="2" x2="9" y2="4"/>' +
      '<line x1="15" y1="2" x2="15" y2="4"/>' +
      '<line x1="9" y1="20" x2="9" y2="22"/>' +
      '<line x1="15" y1="20" x2="15" y2="22"/>' +
      '<line x1="20" y1="9" x2="22" y2="9"/>' +
      '<line x1="20" y1="15" x2="22" y2="15"/>' +
      '<line x1="2" y1="9" x2="4" y2="9"/>' +
      '<line x1="2" y1="15" x2="4" y2="15"/>' + C,

    audit: (size = 20) => open(size) +
      '<circle cx="12" cy="12" r="10"/>' +
      '<polyline points="12 6 12 12 16 14"/>' + C,

    monitoring: (size = 20) => open(size) +
      '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>' + C,

    explorer: (size = 20) => open(size) +
      '<circle cx="11" cy="11" r="8"/>' +
      '<line x1="21" y1="21" x2="16.65" y2="16.65"/>' +
      '<line x1="8" y1="11" x2="14" y2="11"/>' +
      '<line x1="11" y1="8" x2="11" y2="14"/>' + C,

    registry: (size = 20) => open(size) +
      '<path d="M4 7l8-4 8 4"/>' +
      '<path d="M4 7v10l8 4 8-4V7"/>' +
      '<path d="M4 12l8 4 8-4"/>' + C,

    export: (size = 20) => open(size) +
      '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>' +
      '<polyline points="7 10 12 15 17 10"/>' +
      '<line x1="12" y1="15" x2="12" y2="3"/>' + C,

    critical: (size = 6) => `<svg width="${size}" height="${size}" viewBox="0 0 10 10" fill="currentColor"><circle cx="5" cy="5" r="5"/></svg>`,

    criticalAlert: (size = 20) => open(size) +
      '<polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/>' +
      '<line x1="12" y1="8" x2="12" y2="12"/>' +
      '<line x1="12" y1="16" x2="12.01" y2="16"/>' + C,

    securityScore: (size = 20) => open(size) +
      '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>' +
      '<polyline points="9 12 11 14 15 10"/>' + C,

    shield: (size = 20) => open(size) +
      '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>' + C,

    search: (size = 20) => open(size) +
      '<circle cx="11" cy="11" r="8"/>' +
      '<line x1="21" y1="21" x2="16.65" y2="16.65"/>' + C,

    bell: (size = 20) => open(size) +
      '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>' +
      '<path d="M13.73 21a2 2 0 0 1-3.46 0"/>' + C,

    account: (size = 20) => open(size) +
      '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>' +
      '<circle cx="12" cy="7" r="4"/>' + C,

    x: (size = 20) => open(size) +
      '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>' + C,

    code: (size = 16) => open(size) +
      '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>' + C,

    brain: (size = 16) => open(size) +
      '<path d="M12 2a5 5 0 0 1 4.9 4 4.5 4.5 0 0 1 2.1 3.8 4.5 4.5 0 0 1-1.8 3.6A4 4 0 0 1 14 18h-4a4 4 0 0 1-3.2-4.6A4.5 4.5 0 0 1 5 9.8 4.5 4.5 0 0 1 7.1 6 5 5 0 0 1 12 2z"/>' +
      '<path d="M12 2v20"/><path d="M8 8c1.5 0 3 1 4 2"/><path d="M16 8c-1.5 0-3 1-4 2"/><path d="M8 14c1.5 0 3-1 4-2"/><path d="M16 14c-1.5 0-3-1-4-2"/>' + C,

    sword: (size = 16) => open(size) +
      '<line x1="4" y1="4" x2="18" y2="18"/><polyline points="15 4 18 4 18 7"/><line x1="20" y1="4" x2="4" y2="20"/><polyline points="9 4 6 4 6 7"/><polyline points="15 20 18 20 18 17"/><polyline points="9 20 6 20 6 17"/>' + C,

    folder: (size = 14) => open(size) +
      '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>' + C,

    mapPin: (size = 14) => open(size) +
      '<path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/>' + C,

    activity: (size = 20) => open(size) +
      '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>' + C,

    check: (size = 20) => open(size) +
      '<polyline points="20 6 9 17 4 12"/>' + C,

    checkCircle: (size = 20) => open(size) +
      '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>' +
      '<polyline points="22 4 12 14.01 9 11.01"/>' + C,

    xCircle: (size = 20) => open(size) +
      '<circle cx="12" cy="12" r="10"/>' +
      '<line x1="15" y1="9" x2="9" y2="15"/>' +
      '<line x1="9" y1="9" x2="15" y2="15"/>' + C,

    alertTriangle: (size = 20) => open(size) +
      '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>' +
      '<line x1="12" y1="9" x2="12" y2="13"/>' +
      '<line x1="12" y1="17" x2="12.01" y2="17"/>' + C,

    info: (size = 20) => open(size) +
      '<circle cx="12" cy="12" r="10"/>' +
      '<line x1="12" y1="16" x2="12" y2="12"/>' +
      '<line x1="12" y1="8" x2="12.01" y2="8"/>' + C,

    clock: (size = 20) => open(size) +
      '<circle cx="12" cy="12" r="10"/>' +
      '<polyline points="12 6 12 12 16 14"/>' + C,

    terminal: (size = 20) => open(size) +
      '<polyline points="4 17 10 11 4 5"/>' +
      '<line x1="12" y1="19" x2="20" y2="19"/>' + C,

    zap: (size = 20) => open(size) +
      '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>' + C,

    layers: (size = 20) => open(size) +
      '<polygon points="12 2 2 7 12 12 22 7 12 2"/>' +
      '<polyline points="2 17 12 22 22 17"/>' +
      '<polyline points="2 12 12 17 22 12"/>' + C,

    cpu: (size = 20) => open(size) +
      '<rect x="4" y="4" width="16" height="16" rx="2" ry="2"/>' +
      '<rect x="9" y="9" width="6" height="6"/>' +
      '<line x1="9" y1="1" x2="9" y2="4"/>' +
      '<line x1="15" y1="1" x2="15" y2="4"/>' +
      '<line x1="9" y1="20" x2="9" y2="23"/>' +
      '<line x1="15" y1="20" x2="15" y2="23"/>' +
      '<line x1="20" y1="9" x2="23" y2="9"/>' +
      '<line x1="20" y1="14" x2="23" y2="14"/>' +
      '<line x1="1" y1="9" x2="4" y2="9"/>' +
      '<line x1="1" y1="14" x2="4" y2="14"/>' + C,

    globe: (size = 20) => open(size) +
      '<circle cx="12" cy="12" r="10"/>' +
      '<line x1="2" y1="12" x2="22" y2="12"/>' +
      '<path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>' + C,

    download: (size = 20) => open(size) +
      '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>' +
      '<polyline points="7 10 12 15 17 10"/>' +
      '<line x1="12" y1="15" x2="12" y2="3"/>' + C,

    upload: (size = 20) => open(size) +
      '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>' +
      '<polyline points="17 8 12 3 7 8"/>' +
      '<line x1="12" y1="3" x2="12" y2="15"/>' + C,

    play: (size = 20) => open(size) +
      '<polygon points="5 3 19 12 5 21 5 3"/>' + C,

    pause: (size = 20) => open(size) +
      '<rect x="6" y="4" width="4" height="16"/>' +
      '<rect x="14" y="4" width="4" height="16"/>' + C,

    refresh: (size = 20) => open(size) +
      '<polyline points="23 4 23 10 17 10"/>' +
      '<path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>' + C,

    filter: (size = 20) => open(size) +
      '<polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/>' + C,

    chevronRight: (size = 20) => open(size) +
      '<polyline points="9 18 15 12 9 6"/>' + C,

    chevronDown: (size = 20) => open(size) +
      '<polyline points="6 9 12 15 18 9"/>' + C,

    file: (size = 20) => open(size) +
      '<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/>' +
      '<polyline points="13 2 13 9 20 9"/>' + C,

    database: (size = 20) => open(size) +
      '<ellipse cx="12" cy="5" rx="9" ry="3"/>' +
      '<path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>' +
      '<path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>' + C,

    server: (size = 20) => open(size) +
      '<rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>' +
      '<rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>' +
      '<line x1="6" y1="6" x2="6.01" y2="6"/>' +
      '<line x1="6" y1="18" x2="6.01" y2="18"/>' + C,

    link: (size = 20) => open(size) +
      '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>' +
      '<path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>' + C,

    externalLink: (size = 20) => open(size) +
      '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>' +
      '<polyline points="15 3 21 3 21 9"/>' +
      '<line x1="10" y1="14" x2="21" y2="3"/>' + C,

    copy: (size = 20) => open(size) +
      '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>' +
      '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>' + C,

    trash: (size = 20) => open(size) +
      '<polyline points="3 6 5 6 21 6"/>' +
      '<path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>' + C,

    edit: (size = 20) => open(size) +
      '<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>' +
      '<path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>' + C,

    save: (size = 20) => open(size) +
      '<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>' +
      '<polyline points="17 21 17 13 7 13 7 21"/>' +
      '<polyline points="7 3 7 8 15 8"/>' + C,

    git: (size = 20) => open(size) +
      '<circle cx="12" cy="18" r="3"/>' +
      '<circle cx="6" cy="6" r="3"/>' +
      '<circle cx="18" cy="6" r="3"/>' +
      '<path d="M18 9a9 9 0 0 1-9 9"/>' +
      '<path d="M6 9v3a3 3 0 0 0 3 3"/>' + C,

    hash: (size = 20) => open(size) +
      '<line x1="4" y1="9" x2="20" y2="9"/>' +
      '<line x1="4" y1="15" x2="20" y2="15"/>' +
      '<line x1="10" y1="3" x2="8" y2="21"/>' +
      '<line x1="16" y1="3" x2="14" y2="21"/>' + C,

    lock: (size = 20) => open(size) +
      '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>' +
      '<path d="M7 11V7a5 5 0 0 1 10 0v4"/>' + C,

    unlock: (size = 20) => open(size) +
      '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>' +
      '<path d="M7 11V7a5 5 0 0 1 9.9-1"/>' + C,

    eye: (size = 20) => open(size) +
      '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>' +
      '<circle cx="12" cy="12" r="3"/>' + C,

    eyeOff: (size = 20) => open(size) +
      '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>' +
      '<line x1="1" y1="1" x2="23" y2="23"/>' + C,

    settings: (size = 20) => open(size) +
      '<circle cx="12" cy="12" r="3"/>' +
      '<path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>' + C,

    trendUp: (size = 20) => open(size) +
      '<polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/>' +
      '<polyline points="17 6 23 6 23 12"/>' + C,

    trendDown: (size = 20) => open(size) +
      '<polyline points="23 18 13.5 8.5 8.5 13.5 1 6"/>' +
      '<polyline points="17 18 23 18 23 12"/>' + C,

    barChart: (size = 20) => open(size) +
      '<line x1="12" y1="20" x2="12" y2="10"/>' +
      '<line x1="18" y1="20" x2="18" y2="4"/>' +
      '<line x1="6" y1="20" x2="6" y2="16"/>' + C,

    pieChart: (size = 20) => open(size) +
      '<path d="M21.21 15.89A10 10 0 1 1 8 2.83"/>' +
      '<path d="M22 12A10 10 0 0 0 12 2v10z"/>' + C,

    plus: (size = 20) => open(size) +
      '<line x1="12" y1="5" x2="12" y2="19"/>' +
      '<line x1="5" y1="12" x2="19" y2="12"/>' + C,

    minus: (size = 20) => open(size) +
      '<line x1="5" y1="12" x2="19" y2="12"/>' + C,

    arrowRight: (size = 20) => open(size) +
      '<line x1="5" y1="12" x2="19" y2="12"/>' +
      '<polyline points="12 5 19 12 12 19"/>' + C,

    arrowLeft: (size = 20) => open(size) +
      '<line x1="19" y1="12" x2="5" y2="12"/>' +
      '<polyline points="12 19 5 12 12 5"/>' + C,

    target: (size = 20) => open(size) +
      '<circle cx="12" cy="12" r="10"/>' +
      '<circle cx="12" cy="12" r="6"/>' +
      '<circle cx="12" cy="12" r="2"/>' + C,

    taintAnalysis: (size = 20) => open(size) +
      '<line x1="6" y1="3" x2="6" y2="15"/>' +
      '<circle cx="18" cy="6" r="3"/>' +
      '<circle cx="6" cy="18" r="3"/>' +
      '<path d="M6 6a9 9 0 0 0 9 9"/>' + C,

    wifi: (size = 20) => open(size) +
      '<path d="M5 12.55a11 11 0 0 1 14.08 0"/>' +
      '<path d="M1.42 9a16 16 0 0 1 21.16 0"/>' +
      '<path d="M8.53 16.11a6 6 0 0 1 6.95 0"/>' +
      '<line x1="12" y1="20" x2="12.01" y2="20"/>' + C,

    crosshair: (size = 20) => open(size) +
      '<circle cx="12" cy="12" r="10"/>' +
      '<line x1="22" y1="12" x2="18" y2="12"/>' +
      '<line x1="6" y1="12" x2="2" y2="12"/>' +
      '<line x1="12" y1="6" x2="12" y2="2"/>' +
      '<line x1="12" y1="22" x2="12" y2="18"/>' + C,

    fileText: (size = 20) => open(size) +
      '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>' +
      '<polyline points="14 2 14 8 20 8"/>' +
      '<line x1="16" y1="13" x2="8" y2="13"/>' +
      '<line x1="16" y1="17" x2="8" y2="17"/>' +
      '<polyline points="10 9 9 9 8 9"/>' + C,

    box: (size = 20) => open(size) +
      '<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>' + C
  };

  window.Icons = {
    svg: (name, size, className) => {
      const fn = lib[name];
      if (!fn) return '';
      let res = fn(size);
      if (className) res = res.replace('<svg ', `<svg class="${className}" `);
      return res;
    }
  };

})();
