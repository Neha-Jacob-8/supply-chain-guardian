// Reads ../output/*.json produced by: py -m guardian.cli scan targets/NodeGoat
// Serve from the REPO ROOT:  py -m http.server 8000  ->  http://localhost:8000/frontend/
const DIR = '../output/';
const RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const label = id => { try { return decodeURIComponent(String(id).replace(/^pkg:npm\//, '')); } catch { return id; } };
const badge = (t, c) => t ? `<span class="badge ${esc(c || t)}">${esc(t)}</span>` : '';
const load = async f => { try { const r = await fetch(DIR + f); if (!r.ok) throw 0; return await r.json(); } catch { return null; } };

let M = [], F = [], C = [], gaps = [], changes = null;
let P = {};      // component_id -> path from root
let SEV = {};    // component_id -> severity
let sel = null, selF = -1, mSort = ['cvss', -1];

(async function init() {
  const [m, f, c, g, ch] = await Promise.all(['matrix.json', 'findings.json', 'components.json', 'coverage_gaps.json', 'lockfile_changes.json'].map(load));
  if (!m || !f) {
    const e = $('#err'); e.hidden = false;
    e.textContent = 'Could not load ../output/matrix.json or findings.json. Run the scan first, and serve from the repo root: py -m http.server 8000, then open http://localhost:8000/frontend/';
    return;
  }
  M = m; F = f.sort((a, b) => (b.cvss || 0) - (a.cvss || 0)); C = c || []; gaps = g || []; changes = ch;
  C.forEach(x => { if (x.path) P[x.component_id] = x.path; });
  F.forEach(x => { if (!P[x.component_id] && x.dependency_path) P[x.component_id] = x.dependency_path; });
  M.forEach(x => { SEV[x.component_id] = x.severity || ''; });
  overview(); renderMatrix(); drawGraph(); renderFindings(); timeline(); gapList();
  ['mQ', 'mSev', 'mRel', 'mScope', 'mVuln'].forEach(i => $('#' + i).addEventListener('input', renderMatrix));
  ['gSev', 'gScope'].forEach(i => $('#' + i).addEventListener('input', drawGraph));
  ['fEv', 'fSev'].forEach(i => $('#' + i).addEventListener('input', renderFindings));
})();

function overview() {
  const cnt = (a, fn) => a.filter(fn).length;
  const vul = M.filter(x => x.risk_status === 'vulnerable');
  const bySev = s => cnt(F, x => x.severity === s);
  const cards = [
    ['Components', M.length, `${cnt(M, x => x.relationship === 'direct')} direct, ${cnt(M, x => x.relationship === 'transitive')} transitive`],
    ['Vulnerable', vul.length, `${cnt(vul, x => x.relationship === 'direct')} direct, ${cnt(vul, x => x.scope === 'prod')} prod`],
    ['Advisories', F.length, 'component × advisory'],
    ['Critical', bySev('CRITICAL'), ''], ['High', bySev('HIGH'), ''], ['Medium', bySev('MEDIUM'), ''], ['Low', bySev('LOW'), ''],
    ['Verified', cnt(F, x => x.evidence_class === 'verified'), 'evidence-backed'],
    ['Indicators', cnt(F, x => x.evidence_class !== 'verified'), 'needs review'],
    ['Install scripts', cnt(M, x => x.has_install_script), ''],
    ['Coverage gaps', gaps.length, '']
  ];
  $('#cards').innerHTML = cards.map(c => `<div class="card"><b>${c[1]}</b>${esc(c[0])}<br><span>${esc(c[2])}</span></div>`).join('');
}

function renderMatrix() {
  const q = $('#mQ').value.toLowerCase(), sv = $('#mSev').value, rl = $('#mRel').value, sc = $('#mScope').value, vo = $('#mVuln').checked;
  let rows = M.filter(x => (!q || x.name.toLowerCase().includes(q)) && (!sv || x.severity === sv) && (!rl || x.relationship === rl) && (!sc || x.scope === sc) && (!vo || x.risk_status === 'vulnerable'));
  const [k, d] = mSort;
  rows.sort((a, b) => {
    let x = a[k], y = b[k];
    if (k === 'cvss') { x = +x || 0; y = +y || 0; }
    if (k === 'severity') { x = RANK[x] ?? -1; y = RANK[y] ?? -1; }
    return (x > y ? 1 : x < y ? -1 : 0) * d;
  });
  $('#mCount').textContent = `${rows.length} of ${M.length}` + (rows.length > 400 ? ' (showing 400)' : '');
  const cols = [['name', 'Name'], ['version', 'Version'], ['relationship', 'Type'], ['scope', 'Scope'], ['severity', 'Severity'], ['cvss', 'CVSS'], ['fixed_version', 'Fixed in'], ['risk_status', 'Status']];
  $('#mTable').innerHTML = '<thead><tr>' + cols.map(c => `<th data-k="${c[0]}">${c[1]}</th>`).join('') + '</tr></thead><tbody>' +
    rows.slice(0, 400).map(x => `<tr class="row ${x.component_id === sel ? 'sel' : ''}" data-id="${esc(x.component_id)}"><td>${esc(x.name)}</td><td>${esc(x.version)}</td><td>${esc(x.relationship)}</td><td>${esc(x.scope)}</td><td>${badge(x.severity)}</td><td>${esc(x.cvss)}</td><td>${esc(x.fixed_version)}</td><td>${esc(x.risk_status)}</td></tr>`).join('') + '</tbody>';
  $('#mTable').querySelectorAll('th').forEach(th => th.onclick = () => { mSort = [th.dataset.k, mSort[0] === th.dataset.k ? -mSort[1] : -1]; renderMatrix(); });
  $('#mTable').querySelectorAll('tr.row').forEach(tr => tr.onclick = () => select(tr.dataset.id));
}

function select(id, fi) {
  sel = id;
  selF = fi ?? F.findIndex(x => x.component_id === id);
  const p = P[id];
  $('#pathBar').innerHTML = p ? '<b>Path:</b> ' + p.map(label).map(esc).join(' → ') : 'No path data for this component.';
  document.querySelectorAll('#mTable tr.row').forEach(tr => tr.classList.toggle('sel', tr.dataset.id === id));
  drawGraph(); renderFindings(); showEvidence();
}

function drawGraph() {
  const minR = RANK[$('#gSev').value], scope = $('#gScope').value;
  const nodes = new Map(), edges = new Set();
  const add = p => p.forEach((id, i) => { if (!nodes.has(id)) nodes.set(id, { id, d: i }); if (i) edges.add(p[i - 1] + '|' + id); });
  M.filter(x => x.risk_status === 'vulnerable' && (scope === 'all' || x.scope === scope) && (RANK[x.severity] ?? 0) >= minR).forEach(x => P[x.component_id] && add(P[x.component_id]));
  if (sel && P[sel]) add(P[sel]);
  const hot = new Set(sel && P[sel] ? P[sel] : []), hotE = new Set();
  if (sel && P[sel]) P[sel].forEach((id, i) => i && hotE.add(P[sel][i - 1] + '|' + id));
  const cols = {};
  [...nodes.values()].forEach(n => (cols[n.d] = cols[n.d] || []).push(n));
  const CW = 210, RH = 18;
  let H = 40;
  Object.values(cols).forEach(c => { c.sort((a, b) => label(a.id).localeCompare(label(b.id))); c.forEach((n, i) => { n.x = 20 + n.d * CW; n.y = 20 + i * RH; }); H = Math.max(H, 40 + c.length * RH); });
  const W = 40 + (Object.keys(cols).length) * CW + 60;
  const colr = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)' };
  let s = '';
  edges.forEach(e => {
    const [a, b] = e.split('|'), A = nodes.get(a), B = nodes.get(b);
    s += `<path class="e ${hotE.has(e) ? 'on' : ''}" d="M${A.x + 6},${A.y} C${A.x + 100},${A.y} ${B.x - 100},${B.y} ${B.x - 6},${B.y}"/>`;
  });
  nodes.forEach(n => {
    const sv = SEV[n.id], dim = sel && !hot.has(n.id) ? 'dim' : '';
    const fill = n.d === 0 ? 'var(--acc)' : colr[sv] || 'var(--unk)';
    s += `<g class="n ${dim}" data-id="${esc(n.id)}"><circle cx="${n.x}" cy="${n.y}" r="5" fill="${fill}"/>${n.id === sel ? `<circle class="ring" cx="${n.x}" cy="${n.y}" r="9"/>` : ''}<text x="${n.x + 10}" y="${n.y + 4}">${esc(label(n.id).slice(0, 28))}</text><title>${esc(label(n.id))}</title></g>`;
  });
  const svg = $('#svg');
  svg.setAttribute('width', W); svg.setAttribute('height', H);
  svg.innerHTML = s || '<text x="20" y="30">No vulnerable paths for this filter.</text>';
  svg.querySelectorAll('g.n').forEach(g => g.onclick = () => select(g.dataset.id));
}

function renderFindings() {
  const ev = $('#fEv').value, sv = $('#fSev').value;
  const rows = F.map((x, i) => [x, i]).filter(([x]) => (!ev || x.evidence_class === ev) && (!sv || x.severity === sv));
  $('#fCount').textContent = `${rows.length} of ${F.length}` + (rows.length > 400 ? ' (showing 400)' : '');
  $('#fList').innerHTML = rows.slice(0, 400).map(([x, i]) => `<div class="item ${i === selF ? 'sel' : ''}" data-i="${i}">${badge(x.severity)}${badge(x.evidence_class)}<b>${esc(label(x.component_id))}</b><span class="muted">${esc(x.advisory_id)}</span></div>`).join('') || '<p class="muted" style="padding:12px">No findings.</p>';
  $('#fList').querySelectorAll('.item').forEach(d => d.onclick = () => select(F[+d.dataset.i].component_id, +d.dataset.i));
}

function showEvidence() {
  const x = F[selF], el = $('#evidence');
  if (!x) { el.innerHTML = '<p class="muted">No findings for this component.</p>'; return; }
  const e = x.evidence || {};
  const note = x.evidence_class === 'verified' ? 'Confirmed against a source record (hash below).' : 'Indicator only: not independently confirmed. Review manually.';
  el.innerHTML = `<h3>${esc(x.advisory_id)} ${badge(x.severity)} ${badge(x.evidence_class)}</h3><p>${esc(x.summary)}</p><p class="muted">${note}</p>
  <dl><dt>Component</dt><dd>${esc(label(x.component_id))}</dd>
  <dt>CVSS</dt><dd>${esc(x.cvss)} <code>${esc(x.cvss_vector)}</code></dd>
  <dt>Aliases</dt><dd>${esc((x.aliases || []).join(', '))}</dd>
  <dt>Affected</dt><dd>${esc(x.affected_range)}</dd><dt>Fixed in</dt><dd>${esc(x.fixed_version || 'none')}</dd>
  <dt>Type / scope</dt><dd>${esc(x.relationship)} / ${esc(x.scope)}</dd>
  <dt>Path</dt><dd>${esc((x.dependency_path || []).map(label).join(' → '))}</dd>
  <dt>Source</dt><dd>${esc(e.source)}</dd>
  <dt>URL</dt><dd>${e.url ? `<a href="${esc(e.url)}" target="_blank" rel="noopener">${esc(e.url)}</a>` : ''}</dd>
  <dt>Saved file</dt><dd><code>${esc(e.path)}</code></dd><dt>SHA-256</dt><dd><code>${esc(e.sha256)}</code></dd></dl>`;
}

// lockfile_changes.json: one entry per commit that touched the lockfile (newest first):
// {commit, date, author, subject, added, removed, version_changed, hash_algorithm_upgrades} or {commit, date, subject, note}
function timeline() {
  const el = $('#timeline');
  if (!changes) { el.innerHTML = '<p class="muted">No lockfile_changes.json found in output/ yet.</p>'; return; }
  if (!changes.length) { el.innerHTML = '<p class="muted">No lockfile commits in the analysed history.</p>'; return; }
  el.innerHTML = '<div class="tl">' + changes.map(c => {
    const counts = c.note ? `<span class="muted">${esc(c.note)}</span>`
      : `<span class="muted">+${c.added} / -${c.removed} / ~${c.version_changed} versions${c.hash_algorithm_upgrades ? `, ${c.hash_algorithm_upgrades} hash-algorithm upgrades (benign)` : ''}</span>`;
    return `<div><span class="badge">${esc(c.date || '')}</span> <code>${esc(c.commit)}</code> <b>${esc(c.subject || '')}</b> ${c.author ? `<span class="muted">${esc(c.author)}</span>` : ''} ${counts}</div>`;
  }).join('') + '</div>';
}

function gapList() {
  $('#gapList').innerHTML = gaps.length ? gaps.map(g => `<div class="panel" style="margin-bottom:8px;max-height:none"><b>${esc(g.kind)}</b> <span class="muted">${esc(g.path)}</span><p style="margin:4px 0 0">${esc(g.detail)}</p></div>`).join('') : '<p class="muted">No coverage gaps reported.</p>';
}
