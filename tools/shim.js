/* In-page stand-in for `swarmlabre serve --replay`, used by the static demo (site/demo/index.html).
 *
 * It answers the page's api/* calls from one recorded run that build-demo.py embedded as JSON (#demo-data). Nothing leaves the page: window.fetch is wrapped, and only
 * urls under /api/ are handled here (anything else would fail the same way it fails with the network blocked).
 *
 * This is the same fold as swarmlabre/player.py (View, Replay.api, Replay.control) written a second time; tests/test_shim.py runs both over the same events in node and
 * compares what they answer, so the two cannot drift apart unnoticed. */
(function () {
  'use strict';
  const D = JSON.parse(document.getElementById('demo-data').textContent);
  const EVENTS = D.events, FINAL = D.final, RID = D.run, MAX_EVENTS = 5000;
  const EARLY = ['id', 'created', 'started', 'brief', 'roles', 'parallel', 'sample', 'model', 'report', 'limits', 'native', 'env', 'sampling'];
  const clone = x => JSON.parse(JSON.stringify(x));
  const isInt = Number.isInteger;

  function View() { this.reset(); }
  View.prototype.reset = function () {
    this.i = 0; this.status = 'queued'; this.reason = null; this.phase = null;
    this.steps = []; this.stepI = new Map(); this.tasks = []; this.taskI = new Map();
    this.f = new Map(); this.order = []; this.rejects = []; this.gate = { waiting: [], running: [] }; this.queue = {};
    this.layout = false; this.cov = new Map(); this.finished = null;
  };
  Object.defineProperty(View.prototype, 'cursor', { get() { return this.i ? EVENTS[this.i - 1].n : 0; } });
  Object.defineProperty(View.prototype, 'done', { get() { return this.finished !== null; } });
  View.prototype.advance = function (to) {
    to = Math.max(0, Math.min(Math.trunc(to), EVENTS.length));
    if (to < this.i) this.reset();
    while (this.i < to) { this.apply(EVENTS[this.i]); this.i++; }
  };
  View.prototype.task = function (n) { const j = this.taskI.get(n); return j === undefined ? null : this.tasks[j]; };
  View.prototype.addCov = function (role, o, n) {
    let m = this.cov.get(role); if (!m) { m = new Map(); this.cov.set(role, m); }
    m.set(o + ',' + n, [o, n]);
  };
  View.prototype.apply = function (e) {
    const k = e.k;
    if (k === 'waiting') this.status = (e.code || e.why) ? 'waiting' : 'preparing';
    else if (k === 'phase') { this.phase = e.phase; this.status = e.phase === 'prepare' ? 'preparing' : e.phase === 'merge' ? 'merging' : 'running'; }
    else if (k === 'step') {
      const row = { step: e.step, status: e.status, msg: e.msg === undefined ? '' : e.msg, t: e.t };
      const j = this.stepI.get(row.step);
      if (j === undefined) { this.stepI.set(row.step, this.steps.length); this.steps.push(row); } else this.steps[j] = row;
    } else if (k === 'layout') this.layout = true;
    else if (k === 'task_start') {
      const base = (FINAL.tasks || []).find(t => t.n === e.task) || {};
      const t = { n: e.task, role: e.role, uid: base.uid === undefined ? null : base.uid, state: 'running', started: e.t, ended: null, tokens: { in: 0, out: 0 }, tools: 0, findings: 0,
        model_ms: 0, tool_ms: 0, wait_ms: 0, retries: 0, round: e.round === undefined ? 1 : e.round, steers: 0, stop: null, notes: 0, text: '',
        goal: base.goal === undefined ? null : base.goal, scope: base.scope === undefined ? null : base.scope };
      this.taskI.set(t.n, this.tasks.length); this.tasks.push(t);
    } else if (k === 'tokens') {
      const t = this.task(e.task);
      if (t && t.state === 'running') {
        t.tokens = { in: t.tokens.in + Math.trunc(e.in || 0), out: t.tokens.out + Math.trunc(e.out || 0) };
        for (const key of ['model_ms', 'tool_ms', 'wait_ms']) t[key] += Math.trunc(e[key] || 0);
      }
    } else if (k === 'tool_start') {
      const t = this.task(e.task);
      if (t && t.state === 'running') t.tools++;
      if (e.off !== undefined && e.off !== null) this.addCov(e.role, Math.trunc(e.off), Math.trunc(e.len || 1));
    } else if (k === 'tool_end') {
      for (const p of (e.places || [])) this.addCov(e.role, Math.trunc(p[0]), Math.trunc(p[1]));
    } else if (k === 'task_end') {
      const j = this.taskI.get(e.task), base = (FINAL.tasks || []).find(t => t.n === e.task);
      if (j !== undefined && base) this.tasks[j] = clone(base);
    } else if ((k === 'finding' || k === 'resolution') && e.f && typeof e.f === 'object' && typeof e.f.id === 'string') {
      const f = e.f;
      if (!this.f.has(f.id)) this.order.push(f.id);
      this.f.set(f.id, f);
      const t = this.task(f.task);
      if (t && t.state === 'running' && k === 'finding' && e.op === 'add') t.findings++;
    } else if (k === 'reject' && e.x && typeof e.x === 'object') this.rejects.push(e.x);
    else if (k === 'gate') this.gate = { waiting: [...(e.waiting || [])], running: [...(e.running || [])] };
    else if (k === 'tool_queue') this.queue = Object.assign({}, e.queue || {});
    else if (k === 'done') { this.status = e.status || 'done'; this.reason = e.reason === undefined ? null : e.reason; this.finished = e.t; }
  };
  View.prototype.counts = function () {
    const c = { total: this.f.size, verified: 0, unconfirmed: 0, disputed: 0, refuted: 0, rejected: this.rejects.length, 'byte-checked': 0, 'call-cited': 0, claimed: 0 };
    for (const f of this.f.values()) { c[f.status] = (c[f.status] || 0) + 1; c[f.level] = (c[f.level] || 0) + 1; }
    return c;
  };
  View.prototype.board = function () {
    return { findings: this.order.map(i => Object.assign({}, this.f.get(i))), rejected: this.rejects.slice(), counts: this.counts(), attack: D.attack };
  };
  View.prototype.coverage = function () {
    const out = {};
    for (const [role, m] of this.cov) out[role] = [...m.values()].sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    return out;
  };
  View.prototype.run = function () {
    let r;
    if (this.done) {
      r = clone(FINAL);
      Object.assign(r, { status: this.status, reason: this.reason, waiting: null, finished: this.finished, phase: this.phase, counts: this.counts() });
    } else {
      r = {};
      for (const k of EARLY) if (k in FINAL) r[k] = clone(FINAL[k]);
      const began = (this.phase === 'round2' || this.phase === 'merge') ? 2 : this.phase === 'round1' ? 1 : 0;
      const rounds = (FINAL.rounds || []).filter(x => (x.n || 0) <= began).map(clone);
      for (const x of rounds) if ((x.n || 0) === began && this.phase !== 'merge') delete x.summary;
      Object.assign(r, { status: this.status, reason: null, waiting: null, finished: null, phase: this.phase, steps: clone(this.steps), tasks: clone(this.tasks), counts: this.counts(),
        peaks: { tools_mib: 0, agents_mib: 0 }, rounds });
    }
    Object.assign(r, { pausing: 0, why: this.done ? (D.why[this.reason || ''] || '') : '', seq: this.cursor, waiting_why: '', gate: Object.assign({}, this.gate), queue: Object.assign({}, this.queue),
      has_report: this.done, has_html: this.done, has_iocs: this.done && D.has_iocs, has_yara: this.done && D.has_yara });
    return r;
  };

  /* ---- the clock (same rules as player.Replay) ---- */
  const V = new View();
  const T0 = EVENTS[0].t, TOTAL = Math.round((EVENTS[EVENTS.length - 1].t - T0) * 10) / 10;
  const clk = { speed: D.speed || 8, paused: !!D.paused, baseV: 0, baseW: performance.now() };
  const waiters = [];
  const vnow = () => clk.baseV + (clk.paused ? 0 : (performance.now() - clk.baseW) / 1000 * clk.speed);
  const rebase = () => { clk.baseV = vnow(); clk.baseW = performance.now(); };
  function wake() { while (waiters.length) waiters.pop()(); }
  function tick() {
    const v = vnow(); let to = V.i;
    while (to < EVENTS.length && EVENTS[to].t - T0 <= v) to++;
    if (to !== V.i) { V.advance(to); wake(); }
  }
  tick();
  setInterval(tick, 100);
  function state() {
    return { speed: clk.speed, paused: clk.paused, events: EVENTS.length, played: V.i, finished: V.done, level: D.level, seconds: TOTAL, at: Math.round(Math.min(vnow(), TOTAL) * 1000) / 1000, t0: T0 };
  }
  function control(b) {
    rebase();
    if ('speed' in b) { const s = Number(b.speed); if (!isFinite(s)) return [400, { error: 'bad speed' }]; clk.speed = Math.max(0.1, Math.min(s, 10000)); }
    if ('paused' in b) clk.paused = !!b.paused;
    if (b.restart) { V.reset(); clk.baseV = 0; clk.paused = 'paused' in b ? !!b.paused : false; }
    if ('at' in b) {
      const a = Number(b.at); if (!isFinite(a)) return [400, { error: 'bad position' }];
      clk.baseV = Math.max(0, a);
      V.advance(EVENTS.filter(e => e.t - T0 <= clk.baseV).length);
    }
    if (b.end) { V.advance(EVENTS.length); clk.baseV = EVENTS[EVENTS.length - 1].t - T0; }
    clk.baseW = performance.now(); wake(); tick();
    return [200, state()];
  }

  /* ---- routes ---- */
  const ok = o => [200, o];
  const none = (code, msg) => [code, { error: msg }];
  function since(cursor, wait) {
    const run = () => {
      const played = EVENTS.slice(0, V.i).slice(-MAX_EVENTS), seq = V.cursor;
      const gap = (cursor + 1 < (played.length ? played[0].n : seq + 1) && cursor > 0) || cursor > seq;
      return [200, { seq, gap, events: played.filter(e => e.n > cursor), status: V.status, reason: V.reason }];
    };
    if (wait && cursor === V.cursor && !V.done) {
      return new Promise(res => { const t = setTimeout(() => res(run()), wait * 1000); waiters.push(() => { clearTimeout(t); res(run()); }); });
    }
    return run();
  }
  function listing() {
    const r = V.run();
    const row = {}; for (const k of ['id', 'status', 'reason', 'why', 'created', 'finished', 'sample', 'model', 'counts']) row[k] = r[k] === undefined ? null : r[k];
    return { enabled: true, facts: D.facts, stage: null, runs: [row], active: V.done ? null : RID };
  }
  function bytes(off, n) {
    const size = FINAL.sample.size;
    if (off < 0 || off >= size || n < 1) return none(400, 'offset outside the file (size ' + size + ')');
    n = Math.min(n, 4096, size - off);
    let data = null;
    if (D.sample) data = D.sample.slice(off, off + n);
    else for (const w of D.windows) { if (w.off <= off && off < w.off + w.bytes.length) { data = w.bytes.slice(off - w.off, off - w.off + n); break; } }
    if (!data || !data.length) return none(404, 'the sample was deleted after the run; only the bytes around findings are kept');
    const rows = [];
    for (let i = 0; i < data.length; i += 16) {
      const c = data.slice(i, i + 16);
      rows.push({ off: off + i, hex: c.map(b => b.toString(16).padStart(2, '0')), ascii: c.map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('') });
    }
    return ok({ off, len: data.length, size, rows });
  }
  const b64 = s => Array.from(atob(s), c => c.charCodeAt(0));
  if (D.sample) D.sample = b64(D.sample);
  D.windows = (D.windows || []).map(w => ({ off: w.off, bytes: b64(w.b64) }));
  const DOWNLOADS = { 'report.html': 'text/html; charset=utf-8', 'iocs.csv': 'text/csv; charset=utf-8', 'iocs.stix.json': 'application/stix+json;version=2.1', 'iocs.misp.json': 'application/json', 'detection.yar': 'text/plain; charset=utf-8' };

  function route(method, parts, q, body) {
    if (parts.length === 1 && parts[0] === 'mode') return ok({ mode: 'static', why: D.why_static, version: D.version, run: RID, replay: state() });
    if (parts.length === 1 && parts[0] === 'replay') return method === 'GET' ? ok(state()) : control(body || {});
    if (parts[0] !== 'swarm') return none(404, 'Unknown route.');
    const rest = parts.slice(1);
    if (rest.length === 0 && method === 'GET') return ok(listing());
    if (method === 'POST') return none(409, 'This is a recorded run. Nothing can be started, stopped or changed.');
    if (rest.length === 1 && rest[0] === 'model-stats') return none(404, 'Model statistics are not recorded in a bundle.');
    if (rest[0] !== RID) return none(404, 'unknown action');
    const r = rest.slice(1), v = V;
    if (r.length === 0) return ok(v.run());
    if (r[0] === 'events' && r.length === 1) {
      const cur = parseInt(q.get('since') || '0', 10), wait = Math.min(Math.max(parseFloat(q.get('wait') || '0'), 0), 25);
      if (!isInt(cur) || isNaN(wait)) return none(400, 'bad query');
      return since(cur, wait);
    }
    if (r[0] === 'layout') return v.layout ? ok(D.layout) : none(404, 'no layout yet');
    if (r[0] === 'coverage') return ok({ ranges: v.coverage() });
    if (r[0] === 'bytes') {
      const off = Number(q.get('off')), n = Number(q.get('len') || '64');
      if (!isInt(off) || !isInt(n)) return none(400, 'bad query');
      return bytes(off, n);
    }
    if (r[0] === 'thoughts') return ok({ thoughts: [] });
    if (r[0] === 'model') return none(404, "The model's request timings are not recorded in a bundle.");
    if (r[0] === 'board') return ok(v.board());
    if (r[0] === 'finding' && r.length === 2) { const f = v.f.get(r[1]); return f ? ok({ finding: Object.assign({}, f, { manifest: [] }) }) : none(404, 'no such finding'); }
    if (r[0] === 'task' && r.length === 2 && /^\d+$/.test(r[1])) {
      const t = v.tasks.find(t => t.n === parseInt(r[1], 10)); if (!t) return none(404, 'no such task');
      const keep = ['n', 'role', 'state', 'started', 'ended', 'tokens', 'model_ms', 'tool_ms', 'wait_ms', 'tools', 'findings', 'retries', 'round', 'goal', 'scope', 'steers', 'stop', 'text'], o = {};
      for (const k of keep) o[k] = t[k] === undefined ? null : t[k];
      return ok({ task: o, calls: [], notes: '', findings: v.order.filter(i => v.f.get(i).task === t.n) });
    }
    if (r.length === 1 && (r[0] === 'report' || r[0] === 'report.md' || r[0] === 'board.json' || r[0] in DOWNLOADS)) {
      if (!v.done) return none(404, 'no report yet');
      const name = r[0] === 'report' ? 'report.json' : r[0], text = D.files[name];
      if (text === undefined) return none(404, 'no report yet');
      return [200, text, r[0] in DOWNLOADS ? DOWNLOADS[r[0]] : name.endsWith('.md') ? 'text/markdown; charset=utf-8' : 'application/json'];
    }
    return none(404, 'unknown action');
  }

  const realFetch = window.fetch.bind(window);
  window.fetch = async function (input, init) {
    const url = new URL(typeof input === 'string' ? input : input.url, location.href);
    const i = url.pathname.indexOf('/api/');
    if (i < 0 || url.origin !== location.origin) return realFetch(input, init);
    const method = ((init && init.method) || 'GET').toUpperCase();
    let body = null;
    if (method === 'POST' && init && typeof init.body === 'string') { try { body = JSON.parse(init.body); } catch (e) { body = null; } }
    const parts = url.pathname.slice(i + 5).split('/').filter(Boolean);
    const [code, payload, ctype] = await route(method, parts, url.searchParams, body);
    const text = typeof payload === 'string' ? payload : JSON.stringify(payload);
    return new Response(text, { status: code, headers: { 'Content-Type': ctype || 'application/json' } });
  };
  window.__demo = { route, state, control, view: V, tick };     // for the tests that compare this fold with player.py
})();
