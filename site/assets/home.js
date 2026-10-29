/* hypdmz.com: fills every figure from site-data.js (the page's own HypGraph record, built by dev/site_record.py
   from what the pod printed) and runs the HypGraph app on that record, or on a swarm that ran inside the pod. */
'use strict';
(() => {
  const P = window.SITE_DATA || { facts: {}, standing: {}, lint: { findings: [] }, data_ok: [], runs: [] };
  const $ = (s) => document.querySelector(s), $$ = (s) => [...document.querySelectorAll(s)];
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const root = document.documentElement;
  const theme = () => root.dataset.theme || 'light';

  // ── figures, from the record ──
  $$('[data-fact]').forEach((el) => { const v = P.facts[el.dataset.fact]; if (v != null) el.textContent = v; });
  const REVIEW = { replicated: ['ok', 'replicated'], checked: ['ok', 'checked'], contested: ['bad', 'contested'],
    objection: ['bad', 'objection'], unchecked: ['', 'unchecked'] };
  const badge = (k) => {
    const st = P.standing[k]; if (!st) return '';
    const [cls, word] = REVIEW[st.review] || ['', st.review || 'unchecked'];
    return `<button type="button" class="pill ${cls}" data-open-claim="${esc(k)}" title="${esc(st.summary)}">${esc(st.code)} · ${esc(word)} ↗</button>`;
  };
  $$('[data-claim]').forEach((el) => { el.innerHTML = badge(el.dataset.claim); });

  // ── the stage: the app on one bundle at a time ──
  const SOURCES = [['page', 'This page’s record', 'data/site-record.bundle.json',
    'The record behind the figures on this page: each claim bound to what the pod printed, and re-measured another way by a reviewer.']]
    .concat((P.runs || []).map((r) => [r.key, r.label, r.path, r.foot]));
  const tabs = $('#stage-tabs'), app = $('#app');
  if (!tabs || !app) return;
  let view = null, current = null;
  tabs.innerHTML = SOURCES.map(([k, label]) => `<button type="button" data-src="${k}" aria-pressed="false">${esc(label)}</button>`).join('');
  async function show(key, then) {
    const src = SOURCES.find((s) => s[0] === key); if (!src || !window.HypGraph) return;
    tabs.querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.src === key)));
    $('#stage-foot').textContent = src[3];
    if (key !== current) {
      $('#stage-chain').textContent = 'verifying…'; $('#stage-chain').className = 'pill';
      if (view) view.destroy();
      current = key;
      const bundle = await (await fetch(src[2])).json();
      view = HypGraph.mount(app, { source: HypGraph.BundleSource(bundle), theme: theme(), play: key !== 'page', embed: true,
        onTheme: (t) => { root.dataset.theme = t; try { localStorage.setItem('hg-theme', t); } catch { /* private */ } } });
      await view.ready;
      const v = await HypGraph.verifyBundle(bundle);
      $('#stage-chain').textContent = v.ok ? `⛓ chain verified in your browser · ${v.checked} events` : `✗ chain broken at #${v.broken_at}`;
      $('#stage-chain').className = 'pill ' + (v.ok ? 'ok' : 'bad');
    }
    if (then) then(view);
  }
  window.addEventListener('hg-theme', (e) => { if (view) view.setTheme(e.detail); });
  tabs.addEventListener('click', (e) => { const b = e.target.closest('[data-src]'); if (b) show(b.dataset.src); });
  document.addEventListener('click', (e) => {
    const w = e.target.closest('[data-show]');
    if (w) { e.preventDefault(); $('#stage').scrollIntoView({ block: 'start' }); show(w.dataset.show); return; }
    const c = e.target.closest('[data-open-claim]');
    if (c) {
      const st = P.standing[c.dataset.openClaim];
      $('#stage').scrollIntoView({ block: 'start' });
      show('page', (v) => { v.setView('evidence'); if (st) v.show(st.id);
        setTimeout(() => $('#stage').scrollIntoView({ block: 'start', behavior: 'instant' }), 400); });
    }
  });
  show('page');

  // ── the page's own record, as a table ──
  const rows = Object.entries(P.standing).map(([k, st]) => {
    const [cls, word] = REVIEW[st.review] || ['', st.review || 'unchecked'];
    return `<tr><td>${badge(k)}</td><td>${esc(st.statement)}<div style="font-size:12.5px;color:var(--ink2);margin-top:2px">${esc(st.summary)}</div></td><td><span class="pill ${cls}">${esc(word)}</span><div style="font-size:12px;color:var(--ink2);margin-top:4px">${esc((st.verdicts || []).join(', '))}</div></td></tr>`;
  }).join('');
  const L = P.lint || { findings: [] };
  const lintRows = (L.findings || []).map((f) => `<li><code>${esc(f.code)}</code> ${esc(f.level)} · ${esc(f.excerpt)} — ${esc(f.message)}</li>`).join('');
  const okRows = (P.data_ok || []).map((d) => `<li>“${esc(d.text)}” — ${esc(d.why)}</li>`).join('');
  const rc = $('#record-claims');
  if (rc) rc.innerHTML = `<div class="tbl-wrap"><table class="tbl"><thead><tr><th>claim</th><th>the claim, and what the record derives about it</th><th>review</th></tr></thead><tbody>${rows}</tbody></table></div>
    <div class="grid2" style="margin-top:16px">
      <div class="card"><h3>The text of this page, checked against the record</h3>
        <p><code>hypgraph check</code> on <a href="data/page-checked.md">the page as read</a>: ${L.errors ?? '—'} errors, ${L.warnings ?? '—'} warnings.</p>
        ${lintRows ? `<ul style="margin:8px 0 0;padding-left:18px;color:var(--ink2);font-size:14px">${lintRows}</ul>` : ''}</div>
      <div class="card"><h3>Phrases true by design</h3>
        <ul style="margin:0;padding-left:18px;color:var(--ink2);font-size:14px">${okRows || '<li>None.</li>'}</ul></div></div>
    <p class="note">Built ${esc(String(P.built || '').replace('T', ' ').replace('Z', ' UTC'))} · chain head <code>${esc(String(P.head || '').slice(0, 16))}…</code>${P.live ? ' · the reviewer re-ran egress-check against the live pod' : ''} · <a href="data/site-record.bundle.json">download the bundle</a> · <a href="data/evidence/README.md">the evidence files</a></p>`;
})();
