/* Supply Chain Guardian dashboard. Talks only to the same-origin /api served by `guardian serve`. */
'use strict';
const API = '/api';
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const short = id => { if (!id) return ''; if (!String(id).startsWith('pkg:')) return String(id).split(':').slice(1).join(':') || id;
  try { return decodeURIComponent(String(id).split('/').slice(1).join('/')); } catch { return id; } };
const SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const SEVRANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const STAGES = [['discover', 'Discover'], ['investigate', 'Investigate'], ['analyze', 'Analyze'], ['remediate', 'Remediate'],
  ['awaiting_approval', 'Approval'], ['validate', 'Validate'], ['apply', 'Apply'], ['report', 'Report'], ['done', 'Done']];

async function get(path) { const r = await fetch(API + path); if (!r.ok) throw new Error(`${path}: ${r.status}`); return r.headers.get('content-type')?.includes('json') ? r.json() : r.text(); }
async function post(path, body) {
  const r = await fetch(API + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || `${r.status}`);
  return data;
}
const chip = (text, cls = '') => text ? `<span class="chip c ${cls}"><span class="dot"></span>${esc(text)}</span>` : '';
const sevChip = s => chip(s, `sev-${s || 'UNKNOWN'}`);
function banner(msg, kind = '') { const b = $('#banner'); if (!msg) { b.hidden = true; return; } b.className = `banner ${kind}`; b.innerHTML = msg; b.hidden = false; }
function countUp(el, to) {
  if (matchMedia('(prefers-reduced-motion: reduce)').matches || !isFinite(to)) { el.textContent = to; return; }
  const t0 = performance.now(), d = 600;
  const step = t => { const k = Math.min(1, (t - t0) / d); el.textContent = Math.round(to * (1 - Math.pow(1 - k, 3))).toLocaleString(); if (k < 1) requestAnimationFrame(step); };
  requestAnimationFrame(step);
}

/* ---------------- state ---------------- */
const S = { status: {}, overview: null, graph: null, matrix: [], findings: [], inv: [], pri: [], props: [], vals: [], escs: [],
  gaps: [], changes: [], inventory: {}, events: [], lastT: 0, view: 'overview', selNode: null, selFinding: null, mLimit: 200 };

/* ---------------- navigation ---------------- */
function show(view) {
  S.view = view;
  $$('.rail a').forEach(a => a.classList.toggle('on', a.dataset.view === view));
  $$('.view').forEach(v => v.classList.toggle('on', v.id === `v-${view}`));
  if (view === 'network') drawNetwork();
  if (view === 'report') renderReport();
  history.replaceState(null, '', `#${view}`);
}
$$('.rail a').forEach(a => a.addEventListener('click', () => show(a.dataset.view)));

/* ---------------- pipeline + polling ---------------- */
function renderPipeline() {
  const st = S.status, stage = st.stage, running = st.running;
  const idx = STAGES.findIndex(s => s[0] === stage);
  $('#pipeline').innerHTML = STAGES.map(([k, label], i) => {
    let cls = '';
    const paused = !running && !S.vals.length && S.props.length > 0;      // stopped at the approval gate
    if (running && st.phase === 'cloning') cls = i === 0 ? 'active' : '';
    else if (idx >= 0) cls = i < idx || (i === idx && !running) ? 'done' : i === idx ? 'active' : '';
    if (paused && k === 'awaiting_approval') cls = 'wait';
    if (paused && (k === 'validate' || k === 'apply' || k === 'done')) cls = '';
    return `<div class="stage ${cls}">${String(i + 1).padStart(2, '0')} ${label}</div>`;
  }).join('');
  const mode = st.llm_mode;
  $('#modeChip').textContent = mode ? (mode === 'none' ? 'Rule-based agents' : `${mode} agents`) : 'No run yet';
  $('#repoName').textContent = st.repo || st.target || '';
  $('#runBtn').disabled = !!running;
  $('#runBtn').textContent = running ? (st.phase === 'cloning' ? 'Cloning…' : 'Running…') : 'Analyse';
}
let polling = null;
async function poll() {
  try {
    const st = await get('/status');
    const wasRunning = S.status.running;
    S.status = st; renderPipeline();
    const ev = await get(`/events?since=${S.lastT}`);
    if (ev.length) { S.events.push(...ev); S.lastT = ev[ev.length - 1].t; renderEvents(); }
    if (st.error) banner(`Run failed: ${esc(st.error)}`);
    if (wasRunning && !st.running) { await loadAll(); if (!st.error) banner(''); }
    if (st.running) {
      const last = S.events[S.events.length - 1];
      const elapsed = st.elapsed_seconds != null ? ` · <code>${Math.round(st.elapsed_seconds)}s</code>` : '';
      const stepHint = last ? `${last.actor} · ${last.kind}` : (st.phase || 'starting');
      banner(`Running: <b>${esc(stepHint)}</b>${elapsed} <span class="muted">(live progress in Activity tab)</span>`, 'info');
    }
  } catch (e) { banner(`Cannot reach the Guardian API (${esc(e.message)}). Start it with <code>guardian serve</code>.`); }
  clearTimeout(polling); polling = setTimeout(poll, S.status.running ? 1500 : 5000);
}

$('#runForm').addEventListener('submit', async e => {
  e.preventDefault();
  const target = $('#target').value.trim();
  if (!target) { $('#target').focus(); return; }
  const auto_merge = !!$('#autoMergeToggle')?.checked;
  const smoke = $('#dockerToggle') ? $('#dockerToggle').checked : true;
  try {
    await post('/runs', { target, llm: $('#llm').value, auto_merge, smoke });
    S.events = []; S.lastT = 0; renderEvents();
    banner(auto_merge ? 'Autonomous run started: cloning, analysing, generating tests & auto-merging passing fixes…' : 'Run started: cloning and analysing…', 'info'); poll();
  } catch (err) { banner(esc(err.message)); }
});

/* ---------------- load all data ---------------- */
async function loadAll() {
  const safe = p => get(p).catch(() => null);
  const [ov, graph, matrix, findings, inv, pri, props, vals, escs, gaps, changes, inventory, integrity] = await Promise.all([
    safe('/overview'), safe('/graph'), safe('/matrix?limit=5000'), safe('/findings?limit=5000'), safe('/investigations'),
    safe('/priorities'), safe('/proposals'), safe('/validations'), safe('/escalations'), safe('/coverage'), safe('/changes'), safe('/inventory'), safe('/integrity')]);
  Object.assign(S, { overview: ov, graph, matrix: matrix?.rows || [], findings: findings?.findings || [], inv: inv || [],
    pri: pri || [], props: props || [], vals: vals || [], escs: escs || [], gaps: gaps || [], changes: changes || [], inventory: inventory || {}, integrity: integrity || {} });
  S.compIndex = Object.fromEntries(S.matrix.map(r => [r.component_id, r]));
  S.findByComp = {}; S.findings.forEach(f => (S.findByComp[f.component_id] ||= []).push(f));
  fillEcoSelects(); renderOverview(); renderMatrix(); renderFindings(); renderAgents(); renderRemediation(); renderValidation(); renderCoverage();
  S.netDirty = true; if (S.view === 'network') drawNetwork(); if (S.view === 'report') renderReport();
  renderPipeline();
}

function fillEcoSelects() {
  const ecos = [...new Set(S.matrix.map(r => r.ecosystem))].sort();
  ['#nEco', '#mEco'].forEach(sel => { const cur = $(sel).value; $(sel).innerHTML = '<option value="">All ecosystems</option>' + ecos.map(e => `<option>${esc(e)}</option>`).join(''); $(sel).value = cur; });
  $('#nList').innerHTML = S.matrix.slice(0, 3000).map(r => `<option value="${esc(r.name + '@' + r.version)}">`).join('');
}

/* ---------------- overview ---------------- */
function renderOverview() {
  const o = S.overview;
  if (!o) { $('#kpis').innerHTML = '<div class="kpi"><b>–</b><span>No run yet</span><small>Paste a GitHub URL above and press Analyse</small></div>'; return; }
  const r = o.relationship || {}, sc = o.scope || {}, rs = o.risk_status || {};
  const k = [['Components', o.components, `${r.direct || 0} direct · ${r.transitive || 0} transitive`], ['Prod', sc.prod || 0, `${sc.dev || 0} dev-only`],
    ['Vulnerable', rs.vulnerable || 0, 'components with OSV advisories'], ['Advisories', o.advisories, 'verified (OSV)'],
    ['Indicators', o.indicators, 'rule-based supply-chain signals'], ['Not scanned', rs['not-scanned'] || 0, 'no exact version / no advisory DB'],
    ['Fix proposals', o.proposals, `${Object.values(o.validations || {}).reduce((a, b) => a + b, 0)} validated`], ['Coverage gaps', o.coverage_gaps, 'reported, not guessed']];
  $('#kpis').innerHTML = k.map(([l, v, s]) => `<div class="kpi"><b data-n="${+v || 0}">0</b><span>${esc(l)}</span><small>${esc(s)}</small></div>`).join('');
  $$('#kpis b').forEach(b => countUp(b, +b.dataset.n));
  const bs = o.by_risk_severity || {}, total = SEV.reduce((a, s) => a + (bs[s] || 0), 0) || 1;
  $('#sevBar').innerHTML = SEV.map(s => `<i class="sev-${s}" data-w="${(bs[s] || 0) / total * 100}" title="${s}: ${bs[s] || 0}"></i>`).join('');
  requestAnimationFrame(() => $$('#sevBar i').forEach(i => i.style.width = i.dataset.w + '%'));
  $('#sevLegend').innerHTML = SEV.map(s => `<span class="sev-${s}"><i class="dot" style="background:var(--c)"></i>${s} ${bs[s] || 0}</span>`).join('');
  const pj = S.inventory.projects || [];
  $('#projects').innerHTML = '<tr><th>Manifest</th><th>Ecosystem</th><th>Components</th></tr>' +
    pj.map(p => `<tr><td class="mono">${esc(p.manifest)}</td><td>${esc(p.ecosystem)}</td><td class="mono">${p.components}</td></tr>`).join('');
  $('#topPri').innerHTML = S.pri.slice(0, 6).map(p => `<li>${esc(p.headline)} <span>· ${esc(p.recommendation.replace('_', ' '))}</span></li>`).join('') || '<li class="muted">No priorities yet.</li>';
  $('#changes').innerHTML = S.changes.length ? S.changes.slice(0, 12).map(c => `<div><span class="chip">${esc(c.date || '')}</span><code>${esc(c.commit)}</code><b>${esc(c.subject || '')}</b>
      <span class="muted">${c.note ? esc(c.note) : `+${c.added} / −${c.removed} / ~${c.version_changed}${c.hash_algorithm_upgrades ? ` · ${c.hash_algorithm_upgrades} hash upgrades (benign)` : ''}`}</span></div>`).join('')
    : '<p class="muted">No lockfile history (only npm lockfiles are diffed across commits).</p>';
  const ig = S.integrity || {};
  if ($('#integrityBox')) {
    const baseChip = ig.has_baseline ? chip(ig.baseline_ok ? 'Merkle Baseline OK' : `Merkle Tamper (${(ig.anomalies || []).length})`, ig.baseline_ok ? 'v-verified' : 'v-failed') : chip('No Merkle baseline yet', 'ghost');
    const ledChip = ig.has_ledger ? chip(ig.ledger_ok ? 'Hash-Chained Ledger OK' : 'Ledger Chain Broken', ig.ledger_ok ? 'v-verified' : 'v-failed') : chip('No Ledger yet', 'ghost');
    $('#integrityBox').innerHTML = `${baseChip} ${ledChip} <span class="muted" style="font-size:12px">${esc(ig.ledger_message || '')}</span>
      <input id="signKeyInput" type="password" placeholder="Signing passphrase (or uses .env)" style="margin-left:auto;max-width:200px;padding:4px 8px;font-size:12px">
      <button class="btn" id="signBaselineBtn">Sign Merkle Baseline</button>
      <select id="simScenario" aria-label="Simulate attack scenario" style="padding:4px 8px;font-size:12px">
        <option value="shadow">Attack: Shadow &amp; Malicious Dep</option>
        <option value="merkle-tamper">Attack: Merkle Code Tamper (IT1)</option>
        <option value="typosquat">Attack: Typosquat Package (SC9)</option>
        <option value="provenance">Attack: 404 / New Release (SC10/11)</option>
        <option value="dev-edit">Edit: Legitimate Dev Edit</option>
        <option value="all">Attack: Run All Scenarios</option>
        <option value="reset">Reset: Restore Clean Git HEAD</option>
      </select>
      <button class="btn" id="simRunBtn">Simulate</button>`;
    $('#signBaselineBtn')?.addEventListener('click', async () => {
      try {
        const key = $('#signKeyInput')?.value.trim() || null;
        const res = await post('/integrity/baseline', { key, signer: 'developer (dashboard)' });
        banner(`Signed 4096B Merkle baseline (${res.files} files, HMAC ${String(res.hmac || '').slice(0, 14)}…)`, 'info');
        await loadAll();
      } catch (e) { banner(esc(e.message)); }
    });
    $('#simRunBtn')?.addEventListener('click', async () => {
      try {
        const scenario = $('#simScenario')?.value || 'shadow';
        const res = await post('/integrity/simulate', { scenario });
        banner(`Simulation "${res.scenario}" applied to ${res.repo}. Click Analyse to scan or Sign Merkle Baseline to bless.`, 'info');
        await loadAll();
      } catch (e) { banner(esc(e.message)); }
    });
  }
}

/* ---------------- network ---------------- */
let FG = null, netShow = 'all';
const nodeColor = n => {
  if (n.type === 'root') return css('--accent');
  if (n.type === 'project') return css('--text');
  if (n.risk_status === 'malicious') return css('--critical');
  if (n.risk_status === 'vulnerable') return css({ CRITICAL: '--critical', HIGH: '--high', MEDIUM: '--medium', LOW: '--low' }[n.severity] || '--info');
  if (n.risk_status === 'suspicious') return css('--suspicious');
  if (n.risk_status === 'maintenance') return css('--maintenance');
  if (n.risk_status === 'not-scanned') return css('--unscanned');
  return css('--clean');
};
$$('#nShow button').forEach(b => b.addEventListener('click', () => { netShow = b.dataset.v; S.netDirty = true; drawNetwork(); }));
['#nEco', '#nLabels'].forEach(s => $(s).addEventListener('input', () => { S.netDirty = true; drawNetwork(); }));
$('#nFit').addEventListener('click', () => FG && FG.zoomToFit(500, 40));
$('#nSearch').addEventListener('change', e => {
  const q = e.target.value.trim(); const r = S.matrix.find(x => `${x.name}@${x.version}` === q) || S.matrix.find(x => x.name === q);
  if (r) focusNode(r.component_id);
});

function bfsParents(nodes, links, roots) {
  const adj = {}; links.forEach(l => (adj[l.source.id || l.source] ||= []).push(l.target.id || l.target));
  const prev = {}; const q = [...roots]; roots.forEach(r => prev[r] = null);
  while (q.length) { const n = q.shift(); for (const m of adj[n] || []) if (!(m in prev)) { prev[m] = n; q.push(m); } }
  return prev;
}

function buildGraphData() {
  const g = S.graph; if (!g) return null;
  const eco = $('#nEco').value;
  let nodes = g.nodes.map(n => ({ ...n }));
  const keep = new Set(nodes.filter(n => n.type || ((!eco || n.ecosystem === eco) && (netShow !== 'prod' || n.scope === 'prod'))).map(n => n.id));
  let links = g.edges.filter(e => keep.has(e.source) && keep.has(e.target)).map(e => ({ source: e.source, target: e.target }));
  const roots = nodes.filter(n => n.type).map(n => n.id);
  if (netShow === 'vuln') {
    const prev = bfsParents(nodes, links, roots), on = new Set(roots);
    nodes.filter(n => ['vulnerable', 'suspicious'].includes(n.risk_status) && keep.has(n.id)).forEach(n => { let x = n.id; while (x != null && !on.has(x)) { on.add(x); x = prev[x]; } });
    keep.forEach(id => { if (!on.has(id)) keep.delete(id); });
    links = links.filter(l => keep.has(l.source) && keep.has(l.target));
  }
  nodes = nodes.filter(n => keep.has(n.id));
  const deg = {}; links.forEach(l => { deg[l.source] = (deg[l.source] || 0) + 1; });
  nodes.forEach(n => n.val = n.type === 'root' ? 14 : n.type === 'project' ? 9 : n.relationship === 'direct' ? 3.2 + Math.min(4, (deg[n.id] || 0) / 4) : 1.2 + Math.min(3, (deg[n.id] || 0) / 5));
  return { nodes, links, roots };
}

function drawNetwork() {
  if (!S.graph || typeof ForceGraph === 'undefined') { $('#net').innerHTML = `<div class="empty">${S.graph ? 'Graph library failed to load (offline?).' : 'Run an analysis to see the dependency network.'}</div>`; return; }
  if (!S.netDirty && FG) return;
  S.netDirty = false;
  const data = buildGraphData(); S.netData = data;
  $('#nStats').textContent = `${data.nodes.length.toLocaleString()} nodes · ${data.links.length.toLocaleString()} edges`;
  const el = $('#net'); el.innerHTML = '';
  const big = data.nodes.length > 1500;
  S.hlNodes = new Set(); S.hlLinks = new Set();
  FG = ForceGraph()(el)
    .width(el.clientWidth).height(el.clientHeight).backgroundColor(css('--bg'))
    .graphData(data).nodeId('id').nodeVal('val').nodeRelSize(3)
    .nodeLabel(n => `<div class="mono" style="background:${css('--raised')};border:1px solid ${css('--border')};padding:6px 8px;border-radius:4px;color:${css('--text')}">
        <b>${esc(n.type ? (n.name || short(n.id)) : `${n.name}@${n.version}`)}</b><br>${esc(n.type || `${n.ecosystem} · ${n.relationship} · ${n.scope}`)}${n.risk_status ? `<br>${esc(n.risk_status)}${n.severity ? ' · ' + esc(n.severity) : ''}` : ''}</div>`)
    .linkColor(l => S.hlLinks.size ? (S.hlLinks.has(l) ? css('--accent') : 'rgba(110,115,120,0.08)') : 'rgba(110,115,120,0.22)')
    .linkWidth(l => S.hlLinks.has(l) ? 2 : 0.6)
    .linkDirectionalArrowLength(l => S.hlLinks.has(l) ? 4 : 0).linkDirectionalArrowRelPos(1)
    .linkDirectionalParticles(l => S.hlLinks.has(l) ? 3 : 0).linkDirectionalParticleWidth(2.4).linkDirectionalParticleSpeed(0.008)
    .linkDirectionalParticleColor(() => css('--accent'))
    .nodeCanvasObject((n, ctx, scale) => {
      const r = Math.sqrt(n.val) * 3, dim = S.hlNodes.size && !S.hlNodes.has(n.id);
      ctx.globalAlpha = dim ? 0.18 : 1;
      ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, 2 * Math.PI); ctx.fillStyle = nodeColor(n); ctx.fill();
      if (n.type || S.selNode === n.id) { ctx.lineWidth = 2 / scale; ctx.strokeStyle = S.selNode === n.id ? css('--accent') : css('--bg'); ctx.stroke(); }
      const manyProjects = (S.netData?.roots.length || 0) > 9;
      const showLabel = n.type === 'root' || (n.type === 'project' && (!manyProjects || scale > 2.2)) || S.hlNodes.has(n.id) || ($('#nLabels').checked && scale > 1.6) || scale > 4.5;
      if (showLabel) {
        const label = n.type ? (n.name || short(n.id)) : n.name;
        ctx.font = `${(n.type ? 12 : 10) / Math.max(scale, 0.6)}px IBM Plex Mono, monospace`;
        ctx.fillStyle = css('--text'); ctx.textAlign = 'center'; ctx.fillText(label, n.x, n.y + r + 10 / scale);
      }
      ctx.globalAlpha = 1;
    })
    .nodePointerAreaPaint((n, color, ctx) => { ctx.fillStyle = color; ctx.beginPath(); ctx.arc(n.x, n.y, Math.sqrt(n.val) * 3 + 2, 0, 2 * Math.PI); ctx.fill(); })
    .onNodeClick(n => selectNode(n.id))
    .onBackgroundClick(() => { S.selNode = null; S.hlNodes = new Set(); S.hlLinks = new Set(); refreshLinks(); renderSide(); })
    .cooldownTicks(big ? 120 : 250).warmupTicks(big ? 40 : 10);
  FG.d3Force('charge').strength(big ? -14 : -38);
  FG.d3Force('link').distance(l => (l.source.type === 'root' ? 110 : l.source.type ? 50 : 22)).strength(l => (l.source.type === 'root' ? 0.25 : 0.6));
  FG.onEngineStop(() => { if (!S.fitted) { FG.zoomToFit(600, 40); S.fitted = true; } });
  S.fitted = false;
  renderLegend();
  if (S.selNode) selectNode(S.selNode);
  new ResizeObserver(() => FG && FG.width(el.clientWidth).height(el.clientHeight)).observe(el);
}
function refreshLinks() { if (!FG) return; FG.linkColor(FG.linkColor()).linkWidth(FG.linkWidth()).linkDirectionalParticles(FG.linkDirectionalParticles()); }
function selectNode(id) {
  S.selNode = id; const d = S.netData; if (!d) return;
  const prev = bfsParents(d.nodes, d.links, d.roots), path = [];
  let x = id; while (x != null) { path.unshift(x); x = prev[x]; }
  S.hlNodes = new Set(path); S.hlLinks = new Set(d.links.filter(l => { const i = path.indexOf(l.target.id || l.target); return i > 0 && path[i - 1] === (l.source.id || l.source); }));
  refreshLinks(); renderSide(path);
}
function focusNode(id) {
  show('network');
  setTimeout(() => {
    if (!S.netData?.nodes.find(n => n.id === id)) { netShow = 'all'; $('#nEco').value = ''; S.netDirty = true; drawNetwork(); }
    const n = S.netData.nodes.find(n => n.id === id); selectNode(id);
    if (n && n.x != null) { FG.centerAt(n.x, n.y, 600); FG.zoom(4, 600); }
  }, 60);
}
function renderSide(path) {
  const id = S.selNode, side = $('#nSide');
  if (!id) { side.innerHTML = '<p class="muted">Click a node to trace its path from the project root.</p>'; return; }
  const r = S.compIndex[id], fs = (S.findByComp[id] || []).slice().sort((a, b) => (b.risk?.score || 0) - (a.risk?.score || 0));
  if (!r) { side.innerHTML = `<h4>${esc(short(id) || id)}</h4><p class="muted">Project root.</p>`; return; }
  side.innerHTML = `<h4>${esc(r.name)}<span class="muted">@${esc(r.version || '?')}</span></h4>
    <div class="row2">${chip(r.risk_status)} ${r.severity ? sevChip(r.severity) : ''}</div>
    <dl class="kv"><dt>Ecosystem</dt><dd>${esc(r.ecosystem)}</dd><dt>Type</dt><dd>${esc(r.relationship)} · ${esc(r.scope)}</dd>
    <dt>CVSS</dt><dd class="mono">${esc(r.cvss || '–')}</dd><dt>Fixed in</dt><dd class="mono">${esc(r.fixed_version || '–')}</dd>
    <dt>License</dt><dd>${esc(r.license || '–')}</dd><dt>Source</dt><dd class="mono" style="font-size:11px">${esc(r.source || '–')}</dd></dl>
    <h3>Path from root</h3><div class="crumbs">${(path || []).map((p, i) => `${i ? '<i>›</i>' : ''}<code>${esc(S.compIndex[p] ? S.compIndex[p].name : short(p))}</code>`).join('')}</div>
    <h3 class="mt">Findings (${fs.length})</h3>${fs.slice(0, 12).map(f => `<div class="fitem ${'sev-' + (f.risk?.severity || f.severity)}" style="--c:var(--c)" data-f="${esc(f.finding_id)}"><div class="t">${esc(f.title)}</div><div class="m"><span>${esc(f.rule_id)}</span><span>risk ${f.risk?.score ?? '–'}</span></div></div>`).join('') || '<p class="muted">None.</p>'}`;
  side.querySelectorAll('[data-f]').forEach(el => el.addEventListener('click', () => { show('findings'); selectFinding(el.dataset.f); }));
}
function renderLegend() {
  const items = [['Critical', '--critical'], ['High', '--high'], ['Medium', '--medium'], ['Low', '--low'], ['Suspicious', '--suspicious'], ['Maintenance', '--maintenance'], ['Clean', '--clean'], ['Not scanned', '--unscanned'], ['Root', '--accent']];
  $('#nLegend').innerHTML = items.map(([l, v]) => `<span><i class="dot" style="background:var(${v})"></i>${l}</span>`).join('');
}

/* ---------------- matrix ---------------- */
let mSort = ['severity', -1];
['#mQ', '#mStatus', '#mRel', '#mScope', '#mEco'].forEach(s => $(s).addEventListener('input', () => { S.mLimit = 200; renderMatrix(); }));
$('#mMore').addEventListener('click', () => { S.mLimit += 300; renderMatrix(); });
function matrixRows() {
  const q = $('#mQ').value.toLowerCase(), st = $('#mStatus').value, rl = $('#mRel').value, sc = $('#mScope').value, ec = $('#mEco').value;
  const rows = S.matrix.filter(r => (!q || r.name.toLowerCase().includes(q)) && (!st || r.risk_status === st) && (!rl || r.relationship === rl) && (!sc || r.scope === sc) && (!ec || r.ecosystem === ec));
  const [k, d] = mSort;
  rows.sort((a, b) => { let x = a[k], y = b[k]; if (k === 'severity') { x = SEVRANK[x] ?? -1; y = SEVRANK[y] ?? -1; } if (k === 'cvss') { x = +x || 0; y = +y || 0; } return (x > y ? 1 : x < y ? -1 : 0) * d; });
  return rows;
}
function renderMatrix() {
  const rows = matrixRows(), cols = [['name', 'Package'], ['version', 'Version'], ['ecosystem', 'Eco'], ['relationship', 'Type'], ['scope', 'Scope'], ['risk_status', 'Status'], ['severity', 'Severity'], ['cvss', 'CVSS'], ['fixed_version', 'Fixed in'], ['license', 'License'], ['advisory_ids', 'Advisories']];
  $('#mCount').textContent = `${rows.length.toLocaleString()} of ${S.matrix.length.toLocaleString()}`;
  $('#mTable').innerHTML = `<tr>${cols.map(([k, l]) => `<th data-k="${k}">${l}${mSort[0] === k ? (mSort[1] > 0 ? ' ↑' : ' ↓') : ''}</th>`).join('')}</tr>` +
    rows.slice(0, S.mLimit).map(r => `<tr class="row" data-id="${esc(r.component_id)}"><td class="mono">${esc(r.name)}</td><td class="mono">${esc(r.version || '–')}</td><td>${esc(r.ecosystem)}</td>
      <td>${esc(r.relationship)}</td><td>${esc(r.scope)}</td><td>${esc(r.risk_status)}</td><td>${r.severity ? sevChip(r.severity) : ''}</td><td class="mono">${esc(r.cvss)}</td>
      <td class="mono">${esc(r.fixed_version)}</td><td>${esc(r.license)}</td><td class="mono">${r.advisory_ids ? r.advisory_ids.split(';').length : ''}</td></tr>`).join('');
  $('#mMore').hidden = rows.length <= S.mLimit;
  $$('#mTable th').forEach(th => th.addEventListener('click', () => { mSort = [th.dataset.k, mSort[0] === th.dataset.k ? -mSort[1] : -1]; renderMatrix(); }));
  $$('#mTable tr.row').forEach(tr => tr.addEventListener('click', () => toggleRow(tr)));
}
function toggleRow(tr) {
  const nx = tr.nextElementSibling;
  if (nx && nx.classList.contains('exp')) { nx.remove(); tr.classList.remove('sel'); return; }
  const r = S.compIndex[tr.dataset.id]; tr.classList.add('sel');
  const ex = document.createElement('tr'); ex.className = 'exp';
  ex.innerHTML = `<td colspan="11"><div class="crumbs">${r.dependency_path.split(' > ').map((p, i) => `${i ? '<i>›</i>' : ''}<code>${esc(p)}</code>`).join('')}</div>
    <div class="muted" style="margin-top:6px">source: <span class="mono">${esc(r.source || '–')}</span> · install script: ${r.has_install_script ? 'yes' : 'no'} · ${esc(r.advisory_ids || 'no advisories')}</div>
    <div class="actions"><button class="btn" data-net>Show in network</button></div></td>`;
  tr.after(ex); ex.querySelector('[data-net]').addEventListener('click', () => focusNode(r.component_id));
}
$('#mCsv').addEventListener('click', e => {
  e.preventDefault(); const rows = matrixRows(); const keys = Object.keys(rows[0] || {});
  const csv = [keys.join(',')].concat(rows.map(r => keys.map(k => `"${String(r[k] ?? '').replace(/"/g, '""')}"`).join(','))).join('\n');
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' })); a.download = 'dependency-matrix.csv'; a.click();
});

/* ---------------- findings ---------------- */
['#fCat', '#fSev', '#fQ'].forEach(s => $(s).addEventListener('input', renderFindings));
function renderFindings() {
  const c = $('#fCat').value, sv = $('#fSev').value, q = $('#fQ').value.toLowerCase();
  const fs = S.findings.filter(f => (!c || f.category === c) && (!sv || f.risk?.severity === sv) && (!q || `${f.title} ${f.rule_id} ${f.component_id || ''}`.toLowerCase().includes(q)));
  $('#fCount').textContent = `${fs.length.toLocaleString()} findings`;
  $('#fList').innerHTML = fs.slice(0, 600).map(f => `<div class="fitem sev-${f.waived ? 'LOW' : (f.risk?.severity || 'UNKNOWN')} ${S.selFinding === f.finding_id ? 'on' : ''}" style="${f.waived ? 'opacity:0.65' : ''}" data-f="${esc(f.finding_id)}">
      <div class="t">${f.waived ? '[BYPASSED] ' : ''}${esc(f.title)}</div><div class="m"><span class="ev-${esc(f.evidence_class)}">${esc(f.evidence_class === 'verified' ? 'VERIFIED' : 'INDICATOR')}</span>
      <span>${esc(f.rule_id)}</span><span>${esc(short(f.component_id) || f.evidence?.path || '')}</span><span>risk ${f.risk?.score ?? '–'}</span></div></div>`).join('') || '<div class="empty">No findings match.</div>';
  $$('#fList .fitem').forEach(el => el.addEventListener('click', () => selectFinding(el.dataset.f)));
}
const FACTOR_COLORS = ['--critical', '--high', '--medium', '--low', '--suspicious', '--info'];
function selectFinding(id) {
  S.selFinding = id; $$('#fList .fitem').forEach(el => el.classList.toggle('on', el.dataset.f === id));
  const f = S.findings.find(x => x.finding_id === id); if (!f) return;
  const r = f.risk || {}, fac = Object.entries(r.factors || {}), pos = fac.filter(([, v]) => v.points > 0), sum = pos.reduce((a, [, v]) => a + v.points, 0) || 1;
  const ev = f.evidence || {};
  const w = f.waiver;
  $('#fDetail').innerHTML = `<div class="row2"><span class="ev-${esc(f.evidence_class)} chip ghost">${f.evidence_class === 'verified' ? 'Verified · OSV' : 'Indicator · rule ' + esc(f.rule_id)}</span>${sevChip(r.severity)}<span class="chip ghost">${esc(f.category)}</span>${f.waived ? chip('Bypassed by Human', 'v-verified') : ''}</div>
    <h4 style="font-size:17px;margin:4px 0 14px">${esc(f.title)}</h4>
    ${f.waived && w ? `<div class="note" style="margin-bottom:12px"><b>Human Bypass Active:</b> ${esc(w.reason)} <span class="muted">(${esc(w.by)} · ledger <code>${esc((w.ledger_hash || '').slice(0, 12))}</code>)</span>
      <button class="btn" id="unwaiveBtn" style="margin-left:10px">Restore Warning</button></div>` : `
      <div class="row2" style="margin-bottom:12px;padding:8px;border:1px solid var(--border);border-radius:6px">
        <input id="waiveReason" placeholder="Reason to bypass/accept this warning after reviewing detail…" style="flex:1;padding:4px 8px;font-size:12px">
        <button class="btn" id="waiveBtn">Bypass / Dismiss Warning</button>
      </div>`}
    <div style="display:flex;gap:28px;align-items:flex-end"><div><div class="score">${r.score ?? '–'}</div><span class="muted" style="font-size:11px">RISK SCORE (FORMULA)</span></div>
      <div><span class="meter"><i style="width:${(r.confidence || 0) * 100}%"></i></span> <span class="muted" style="font-size:12px">confidence ${Math.round((r.confidence || 0) * 100)}%</span></div></div>
    <div class="factors">${pos.map(([k, v], i) => `<i title="${esc(k)}: +${v.points} (${esc(v.why)})" style="width:${v.points / sum * 100}%;background:var(${FACTOR_COLORS[i % 6]})"></i>`).join('')}</div>
    <ul class="flist">${fac.map(([k, v]) => `<li><b>${esc(k)}</b> ${v.points >= 0 ? '+' : ''}${v.points} · ${esc(v.why)}</li>`).join('')}</ul>
    <dl class="kv">${f.component_id ? `<dt>Component</dt><dd class="mono"><a href="#" data-net>${esc(short(f.component_id))}</a></dd>` : ''}
      ${f.cves?.length || f.advisory_id ? `<dt>Advisories</dt><dd>${[f.advisory_id, ...(f.cves || [])].filter(Boolean).map(a => `<a class="mono" target="_blank" rel="noopener" href="https://osv.dev/vulnerability/${encodeURIComponent(a)}">${esc(a)}</a>`).join(' · ')}</dd>` : ''}
      ${f.cvss_vector ? `<dt>CVSS</dt><dd class="mono">${esc(f.cvss)} · ${esc(f.cvss_vector)}</dd>` : ''}
      ${f.affected_range ? `<dt>Affected</dt><dd class="mono">${esc(f.affected_range)}</dd><dt>Fixed in</dt><dd class="mono">${esc(f.fixed_version || 'no fix')}</dd>` : ''}
      ${f.dependency_path?.length ? `<dt>Path</dt><dd><div class="crumbs">${f.dependency_path.map((p, i) => `${i ? '<i>›</i>' : ''}<code>${esc(short(p) || p)}</code>`).join('')}</div></dd>` : ''}
      ${f.detail ? `<dt>Detail</dt><dd>${esc(f.detail)}</dd>` : ''}${f.recommendation ? `<dt>Fix</dt><dd>${esc(f.recommendation)}</dd>` : ''}</dl>
    <h3>Evidence</h3><dl class="kv"><dt>Source</dt><dd>${esc(ev.source)}${ev.commit ? ` · commit <code>${esc(ev.commit.slice(0, 10))}</code> ${esc(ev.commit_subject || '')}` : ''}</dd>
      ${ev.path ? `<dt>Location</dt><dd class="mono">${esc(ev.path)}${ev.line ? ':' + esc(ev.line) : ''}</dd>` : ''}
      ${ev.sha256 ? `<dt>SHA-256</dt><dd class="mono" style="font-size:11px">${esc(ev.sha256)}</dd>` : ''}</dl>
    ${ev.excerpt ? `<pre class="ev">${esc(ev.excerpt)}</pre>` : ''}`;
  $('#fDetail [data-net]')?.addEventListener('click', e => { e.preventDefault(); focusNode(f.component_id); });
  $('#waiveBtn')?.addEventListener('click', async () => {
    const reason = $('#waiveReason')?.value.trim() || 'Verified safe / accepted risk after inspecting finding detail';
    try {
      const updated = await post(`/findings/${encodeURIComponent(f.finding_id)}/waive`, { reason, action: 'waive' });
      Object.assign(f, updated);
      banner(`Bypassed warning ${esc(f.finding_id)} (recorded in tamper-evident ledger)`, 'info');
      renderFindings(); selectFinding(f.finding_id);
    } catch (e) { banner(esc(e.message)); }
  });
  $('#unwaiveBtn')?.addEventListener('click', async () => {
    try {
      await post(`/findings/${encodeURIComponent(f.finding_id)}/waive`, { action: 'unwaive' });
      delete f.waived; delete f.waiver;
      banner(`Restored warning ${esc(f.finding_id)}`, 'info');
      renderFindings(); selectFinding(f.finding_id);
    } catch (e) { banner(esc(e.message)); }
  });
}

/* ---------------- agents ---------------- */
function renderAgents() {
  $('#riskMode').textContent = S.pri[0]?.mode || ''; $('#redMode').textContent = S.inv[0]?.mode || '';
  $('#priTable').innerHTML = '<tr><th>#</th><th>Issue</th><th>Recommendation</th><th>Why</th></tr>' + S.pri.map(p => `<tr><td class="mono">${p.rank}</td><td>${esc(p.headline)}${p.escalate ? ' ' + chip('escalate', 'v-failed') : ''}</td>
      <td>${chip(p.recommendation.replace('_', ' '), p.recommendation === 'fix_now' ? 'sev-HIGH' : p.recommendation === 'fix_soon' ? 'sev-MEDIUM' : 'sev-LOW')}</td><td class="muted" style="font-size:12.5px">${esc(p.rationale)}</td></tr>`).join('');
  $('#invs').innerHTML = S.inv.map((v, i) => `<div class="card ${v.verdict === 'confirmed_risk' ? 'v-failed' : v.verdict === 'likely_benign' ? 'v-verified' : 'v-partial'}" style="--c:var(--c);animation-delay:${i * 40}ms">
      <div class="row2">${chip(v.verdict.replace(/_/g, ' '), v.verdict === 'confirmed_risk' ? 'v-failed' : v.verdict === 'likely_benign' ? 'v-verified' : 'v-partial')}<span class="muted" style="font-size:12px">confidence ${Math.round(v.confidence * 100)}%</span></div>
      <h4>${esc(v.title)}</h4><p class="muted" style="margin:0 0 6px">${esc(v.hypothesis)}</p>
      ${v.attack_path?.length ? `<div class="steps">${v.attack_path.map((s, j) => `${j ? '<i>→</i>' : ''}<span>${j + 1}. ${esc(s)}</span>`).join('')}</div>` : ''}
      <div class="cols"><div><h3>Verified facts</h3><ul>${v.verified_facts.map(f => `<li>${esc(f.claim)} ${f.evidence_ids.map(e => `<span class="evid" data-e="${esc(e)}">${esc(e)}</span>`).join(' ')}</li>`).join('')}</ul></div>
      <div><h3>Inference (not verified)</h3><ul class="inf">${(v.inferences || []).map(x => `<li>${esc(x)}</li>`).join('') || '<li>None</li>'}</ul></div></div></div>`).join('') || '<div class="empty">No investigations in this run.</div>';
  $$('#invs .evid').forEach(el => el.addEventListener('click', () => openEvidence(el.dataset.e)));
}
async function openEvidence(id) {
  if (id.startsWith('EV-')) { try { const d = await get(`/evidence/${encodeURIComponent(id)}`); drawer(id, JSON.stringify(d, null, 2)); } catch (e) { drawer(id, e.message); } }
  else { show('findings'); selectFinding(id); }
}
function drawer(title, body) { $('#dTitle').textContent = title; $('#dBody').textContent = body; $('#drawer').hidden = false; }
$('#dClose').addEventListener('click', () => $('#drawer').hidden = true);

/* ---------------- remediation ---------------- */
function renderRemediation() {
  const vmap = Object.fromEntries(S.vals.map(v => [v.candidate_id, v.verdict]));
  const mmap = Object.fromEntries(S.vals.map(v => [v.candidate_id, v]));
  const pending = S.props.filter(p => (p.approval || {}).status === 'pending').length;
  $('#pendingCount').textContent = pending || '';
  $('#props').innerHTML = S.props.map((p, i) => {
    const st = (p.approval || {}).status || 'pending', verdict = vmap[p.candidate_id], valObj = mmap[p.candidate_id], ap = p.applied;
    const mergedChip = valObj?.merged ? chip('Auto-Merged', 'v-verified') : (ap ? chip(ap.status === 'applied' ? 'applied' : 'not applied: ' + ap.status, ap.status === 'applied' ? 'v-verified' : 'v-partial') : '');
    const testChip = valObj?.test_info ? chip(valObj.test_info.kind === 'generated' ? 'LLM/Smoke Test Generated' : 'Existing Tests', 'ghost') : '';
    const canDecide = st === 'pending' || (verdict === 'failed' && !valObj?.merged && ap?.status !== 'applied');
    return `<div class="card ${verdict ? 'v-' + verdict : 'v-' + st}" style="--c:var(--c);animation-delay:${i * 40}ms" data-id="${esc(p.candidate_id)}">
      <div class="row2">${chip(p.change_risk + ' risk', p.change_risk === 'high' ? 'sev-HIGH' : p.change_risk === 'medium' ? 'sev-MEDIUM' : 'sev-LOW')}${chip(st, 'v-' + st)}${verdict ? chip(verdict, 'v-' + verdict) : ''}${mergedChip}${testChip}<span class="mono muted" style="font-size:11px">${esc(p.candidate_id)}</span></div>
      <h4>${esc(p.summary)}</h4><p style="margin:0 0 8px">${esc(p.rationale)}</p>
      <dl class="kv"><dt>Compatibility</dt><dd>${esc(p.compat_assessment)}</dd><dt>Expected</dt><dd>${esc(p.expected_risk_reduction)}${/prediction/i.test(p.expected_risk_reduction || '') ? '' : ' <span class="muted">(prediction)</span>'}</dd><dt>Rollback</dt><dd>${esc(p.rollback)}</dd></dl>
      <div class="actions">${canDecide ? `<button class="btn ok" data-a="approve">Approve</button><button class="btn no" data-a="reject">Reject</button>` : ''}<button class="btn" data-diff>View diff</button></div><div class="diffbox"></div></div>`;
  }).join('') || '<div class="empty">No remediation proposals yet.</div>';
  $('#escs').innerHTML = S.escs.length ? `<h3 class="sect">Escalated to a human</h3>${S.escs.map(e => `<div class="note">${esc(e.reason)} <span class="muted">(${e.finding_ids.length} finding${e.finding_ids.length > 1 ? 's' : ''})</span></div>`).join('')}` : '';
  $$('#props [data-a]').forEach(b => b.addEventListener('click', () => decide(b.closest('.card').dataset.id, b.dataset.a, b)));
  $$('#props [data-diff]').forEach(b => b.addEventListener('click', () => toggleDiff(b.closest('.card'))));
  const approved = S.props.filter(p => (p.approval || {}).status === 'approved' && !vmap[p.candidate_id]).length;
  const toApply = S.props.filter(p => p.applicable && !mmap[p.candidate_id]?.merged && (!p.applied || p.applied.status !== 'applied')).length;
  const mergedCnt = S.props.filter(p => mmap[p.candidate_id]?.merged).length;
  $('#approvedCount').textContent = (mergedCnt ? `${mergedCnt} auto-merged · ` : '') + `${approved} approved and not yet validated` + (toApply ? ` · ${toApply} validated and not yet applied` : '');
  $('#validateBtn').disabled = !(approved || toApply) || S.status.running;
}
async function decide(id, decision, btn) {
  btn.disabled = true;
  try { const res = await post(`/proposals/${encodeURIComponent(id)}/approval`, { decision, comment: '' }); const p = S.props.find(x => x.candidate_id === id); p.approval = res; renderRemediation(); renderPipeline(); }
  catch (e) { btn.disabled = false; banner(esc(e.message)); }
}
async function toggleDiff(card) {
  const box = card.querySelector('.diffbox'); if (box.innerHTML) { box.innerHTML = ''; return; }
  try {
    const p = await get(`/proposals/${encodeURIComponent(card.dataset.id)}`);
    box.innerHTML = `<div class="diff">${(p.diff || 'No file changes (manual action).').split('\n').map(l => `<div class="${l.startsWith('+++') || l.startsWith('---') || l.startsWith('@@') ? 'h' : l[0] === '+' ? 'a' : l[0] === '-' ? 'd' : ''}">${esc(l) || ' '}</div>`).join('')}</div>`;
  } catch (e) { box.textContent = e.message; }
}
$('#validateBtn').addEventListener('click', async () => {
  const smoke = $('#dockerToggle') ? $('#dockerToggle').checked : true;
  try { await post('/resume', { llm: $('#llm').value, smoke }); banner(`Independent validation started (${smoke ? 'Docker Sandbox' : 'static only'}). Fixes that pass are then committed to a local branch of the repository.`, 'info'); show('validation'); poll(); }
  catch (e) { banner(esc(e.message)); }
});

/* ---------------- validation ---------------- */
function renderValidation() {
  const amap = Object.fromEntries(S.props.filter(p => p.applied).map(p => [p.candidate_id, p.applied]));
  const applied = Object.values(amap).filter(a => a.status === 'applied');
  const head = applied.length ? `<div class="note">${applied.length} validated fix${applied.length > 1 ? 'es were' : ' was'} written to <span class="mono">${esc(S.status.repo || '')}</span>${applied[0].branch ? ` on local branch <span class="mono">${esc(applied[0].branch)}</span> (one commit per fix, not pushed)` : ''}. Re-run Analyse to continue with the remaining fixes. <a href="/api/remediation.patch" target="_blank" rel="noopener">Download patch</a></div>` : '';
  $('#vals').innerHTML = head + S.vals.map((v, i) => {
    const ap = amap[v.candidate_id];
    const c = v.comparison || {}, b = c.before || {}, a = c.after || {};
    const delta = (x, y) => { const d = (y ?? 0) - (x ?? 0); return d ? `<span class="${d < 0 ? 'delta-down' : 'delta-up'}">${d > 0 ? '+' : ''}${d}</span>` : '<span class="muted">±0</span>'; };
    const runtimeLabel = x => x === null || x === undefined ? 'n/a' : x ? 'pass' : 'fail';
    const ti = v.test_info;
    return `<div class="vcard v-${esc(v.verdict)}" style="animation-delay:${i * 60}ms"><div class="vhead"><div><h4 style="margin:0 0 4px;font-size:15px;font-weight:500">${esc(v.summary)}</h4><span class="mono muted" style="font-size:11px">${esc(v.candidate_id)} · ${esc(c.runtime_check || v.validated_by || '')}</span></div><div class="row2">${v.merged ? chip('Auto-Merged', 'v-verified') : ''}${chip(v.verdict, 'v-' + v.verdict)}</div></div>
      ${ap ? `<p class="${ap.status === 'applied' ? '' : 'muted'}" style="margin:0 0 10px">${ap.status === 'applied' ? '<b>Applied</b>' : '<b>Not applied</b>'}${ap.commit ? ` · commit <span class="mono">${esc(ap.commit)}</span>` : ''} · ${esc(ap.detail)}${ap.validation && ap.validation !== 'verified' ? `<br><span class="muted">${esc(ap.validation)}</span>` : ''}</p>` : (!v.merged && !(S.props.find(p => p.candidate_id === v.candidate_id) || {}).applicable) ? '<p class="muted" style="margin:0 0 10px">Not applied: failed, runtime-failing or incomplete fixes are never written to the repository.</p>' : ''}
      ${(c.introduced_high || []).length ? `<div class="note" style="border-color:var(--failed);margin:0 0 10px"><b>Issue raised:</b> this upgrade introduced ${c.introduced_high.length} new HIGH/CRITICAL finding(s) and was blocked from applying.${(c.introduced_details || []).length ? `<ul style="margin:6px 0 0 18px;padding:0;font-size:12px">${c.introduced_details.map(d => `<li><span class="mono">${esc(d.severity || 'HIGH')}</span> ${esc(d.title || d.key)}</li>`).join('')}</ul>` : ''}</div>` : ''}
      <div class="vgrid"><ul class="tl">${v.steps.map(s => `<li class="${s.rc === 0 ? (s.name === 'runtime_check' || s.name === 'app_logs' ? 'neutral' : 'ok') : 'bad'}"><b>${esc(s.name.replace(/_/g, ' '))}</b> ${s.seconds ? `<span class="muted">${s.seconds}s</span>` : ''}
          ${s.detail ? `<div class="muted">${esc(s.detail)}</div>` : ''}${s.log_tail && s.name !== 'generate_smoke_test' ? `<details ${s.rc !== 0 || s.name === 'app_logs' ? 'open' : ''}><summary>view log</summary><pre class="ev" style="max-height:140px">${esc(s.log_tail)}</pre></details>` : ''}</li>`).join('')}</ul>
        <div>${v.comparison ? `<div class="nums"><div><span>Findings</span><b>${b.findings} → ${a.findings}</b> ${delta(b.findings, a.findings)}</div><div><span>Vulnerable comps</span><b>${b.vulnerable_components} → ${a.vulnerable_components}</b> ${delta(b.vulnerable_components, a.vulnerable_components)}</div>
          <div><span>Targets resolved</span><b>${(c.resolved || []).length}/${c.targets}</b></div><div><span>Newly introduced</span><b>${c.introduced_count}</b> ${(c.introduced_high || []).length ? chip(`${c.introduced_high.length} high`, 'sev-HIGH') : ''}</div>
          <div><span>SBOM diff</span><b>+${c.sbom_diff.added_count} / −${c.sbom_diff.removed_count}</b></div><div><span>Runtime check</span><b>${c.smoke ? runtimeLabel(c.smoke.after_ok) : '–'}</b> <span class="muted">baseline ${c.smoke ? runtimeLabel(c.smoke.baseline_ok) : '–'}</span></div></div>`
          : ti ? `<div class="nums"><div><span>Test source</span><b>${esc(ti.kind)}</b></div><div><span>Generator</span><b>${esc(ti.generator || 'existing')}</b></div><div><span>Test file</span><b class="mono">${esc((ti.files || []).join(', '))}</b></div><div><span>Auto-merged</span><b>${v.merged ? 'yes (' + (v.merged_files || []).join(', ') + ')' : 'no'}</b></div></div>
            ${ti.code ? `<details style="margin-top:8px"><summary class="muted" style="cursor:pointer;font-size:12px">View generated smoke test (${esc((ti.files || [])[0] || '')})</summary><pre class="ev" style="max-height:180px">${esc(ti.code)}</pre></details>` : ''}`
          : '<p class="muted">Stopped before the rescan.</p>'}</div></div></div>`;
  }).join('') || '<div class="empty">No validations yet. Approve fixes under Remediation, then run independent validation.</div>';
}

/* ---------------- activity ---------------- */
$('#aActor').addEventListener('input', renderEvents);
function renderEvents() {
  const actors = [...new Set(S.events.map(e => e.actor))]; const cur = $('#aActor').value;
  $('#aActor').innerHTML = '<option value="">All actors</option>' + actors.map(a => `<option>${esc(a)}</option>`).join(''); $('#aActor').value = cur;
  const ev = S.events.filter(e => !cur || e.actor === cur).slice(-400);
  // Group consecutive events with the same (stage, actor) into one clean summary row with an evidence dropdown
  const groups = [];
  for (const e of ev) {
    const last = groups[groups.length - 1];
    if (last && last.stage === e.stage && last.actor === e.actor) {
      last.items.push(e);
    } else {
      groups.push({ stage: e.stage, actor: e.actor, items: [e] });
    }
  }
  $('#events').innerHTML = '<tr><th>Time</th><th>Stage</th><th>Actor</th><th>Summary &amp; Evidence</th></tr>' + groups.reverse().map(g => {
    const last = g.items[g.items.length - 1];
    const counts = {};
    g.items.forEach(x => { counts[x.kind] = (counts[x.kind] || 0) + 1; });
    const summary = Object.entries(counts).map(([k, n]) => `${n} ${k.replace(/_/g, ' ')}`).join(' · ');
    const hasRej = g.items.some(x => x.kind === 'submit' && x.detail && x.detail.accepted === false);
    const rowsHtml = g.items.slice().reverse().map(x => {
      const rej = x.kind === 'submit' && x.detail && x.detail.accepted === false;
      return `<div style="padding:3px 0;border-top:1px solid var(--border);${rej ? 'color:var(--failed)' : ''}"><b>${esc(x.kind)}</b> <span class="muted">${new Date(x.t * 1000).toLocaleTimeString()}</span> — ${esc(JSON.stringify(x.detail))}</div>`;
    }).join('');
    return `<tr ${hasRej ? 'style="background:color-mix(in srgb,var(--failed) 12%,transparent)"' : ''}>
      <td style="white-space:nowrap">${new Date(last.t * 1000).toLocaleTimeString()}</td>
      <td>${esc(g.stage)}</td><td>${esc(g.actor)}</td>
      <td><details><summary style="cursor:pointer"><b>${esc(summary)}</b> <span class="muted">(${g.items.length} event${g.items.length > 1 ? 's' : ''})</span></summary><div style="margin-top:6px;max-height:220px;overflow:auto">${rowsHtml}</div></details></td></tr>`;
  }).join('');
}

/* ---------------- report (small markdown renderer for our own report format) ---------------- */
function md(src) {
  const inline = s => esc(s).replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>').replace(/\*([^*]+)\*/g, '<i>$1</i>');
  const out = []; let table = null, list = false;
  const flush = () => { if (table) { out.push(`<table>${table.map((r, i) => `<tr>${r.map(c => i ? `<td>${inline(c)}</td>` : `<th>${inline(c)}</th>`).join('')}</tr>`).join('')}</table>`); table = null; } if (list) { out.push('</ul>'); list = false; } };
  for (const line of src.split('\n')) {
    if (/^\|.*\|$/.test(line.trim())) { const cells = line.trim().slice(1, -1).split('|').map(c => c.trim()); if (cells.every(c => /^-+$/.test(c))) continue; (table ||= []).push(cells); continue; }
    if (table) flush();
    if (/^#{1,3} /.test(line)) { flush(); const n = line.match(/^#+/)[0].length; out.push(`<h${n}>${inline(line.slice(n + 1))}</h${n}>`); }
    else if (/^- /.test(line)) { if (!list) { out.push('<ul>'); list = true; } out.push(`<li>${inline(line.slice(2))}</li>`); }
    else { flush(); if (line.trim()) out.push(`<p>${inline(line)}</p>`); }
  }
  flush(); return out.join('');
}
async function renderReport() {
  try {
    const [mdText, rj] = await Promise.all([get('/report.md'), get('/report.json').catch(() => null)]);
    $('#report').innerHTML = md(mdText);
    const pr = rj?.pull_request;
    if (pr && pr.pr_url) {
      $('#prBanner').hidden = false;
      $('#prBanner').innerHTML = `<b>GitHub Pull Request Raised:</b> <a href="${esc(pr.pr_url)}" target="_blank" rel="noopener">${esc(pr.pr_url)}</a> · Branch <code>${esc(pr.branch)}</code> → <code>${esc(pr.upstream)}</code>`;
      $('#prStatus').textContent = `PR #${pr.pr_number || ''} created`;
    } else {
      $('#prBanner').hidden = true;
    }
  } catch {
    $('#report').innerHTML = '<p class="muted">No report yet.</p>';
  }
}
$('#raisePrBtn')?.addEventListener('click', async () => {
  const btn = $('#raisePrBtn');
  btn.disabled = true; btn.textContent = 'Forking & Raising PR…';
  try {
    const res = await post('/report/pr', {});
    banner(`Pull Request #${esc(res.pr_number)} created: <a href="${esc(res.pr_url)}" target="_blank" rel="noopener">${esc(res.pr_url)}</a>`, 'info');
    await renderReport();
  } catch (e) {
    banner(`GitHub PR failed: ${esc(e.message)}`);
  } finally {
    btn.disabled = false; btn.textContent = 'Raise GitHub PR (App)';
  }
});

/* ---------------- coverage ---------------- */
function renderCoverage() {
  $('#gaps').innerHTML = S.gaps.map(g => `<div class="gap"><b>${esc(g.kind)}</b> <span class="mono muted">${esc(g.path)}</span><div>${esc(g.detail)}</div></div>`).join('') || '<p class="muted">No coverage gaps reported.</p>';
}

/* ---------------- boot ---------------- */
renderPipeline();
show((location.hash || '#overview').slice(1).split('?')[0] || 'overview');
loadAll().then(poll);
