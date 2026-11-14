/* Node harness for tests/test_shim.py: loads tools/shim.js against a data file, then for each cursor given on the command line answers every route and prints the lot as JSON.
 *   node shim_probe.js DATA.json SHIM.js CURSOR [CURSOR ...] */
'use strict';
const fs = require('fs');
const [dataPath, shimPath, ...cursors] = process.argv.slice(2);
const raw = fs.readFileSync(dataPath, 'utf8');
global.document = { getElementById: id => (id === 'demo-data' ? { textContent: raw } : null) };
global.performance = { now: () => 0 };                 // a frozen clock: nothing plays by itself
global.setInterval = () => 0;
global.location = { href: 'http://localhost/', origin: 'http://localhost' };
global.window = { fetch: async () => { throw new Error('no network'); } };
eval(fs.readFileSync(shimPath, 'utf8'));
const demo = window.__demo, D = JSON.parse(raw), rid = D.run;
const q = o => new URLSearchParams(o);
const get = (path, query) => { const r = demo.route('GET', path.split('/').filter(Boolean), q(query || {}), null); return r; };
const out = {};
const offs = [0, 1, 16, 64, 100, 300, D.final.sample.size - 1, D.final.sample.size + 5];
for (const c of cursors) {
  const n = parseInt(c, 10);
  demo.view.advance(n);
  const v = demo.view, row = {};
  const put = (k, r) => { row[k] = [r[0], r[1]]; };
  put('run', get('swarm/' + rid));
  put('board', get('swarm/' + rid + '/board'));
  put('events0', get('swarm/' + rid + '/events', { since: '0' }));
  put('events_mid', get('swarm/' + rid + '/events', { since: String(v.cursor > 5 ? v.cursor - 5 : 0) }));
  put('events_future', get('swarm/' + rid + '/events', { since: String(v.cursor + 3) }));
  put('coverage', get('swarm/' + rid + '/coverage'));
  put('layout', get('swarm/' + rid + '/layout'));
  put('thoughts', get('swarm/' + rid + '/thoughts'));
  put('list', get('swarm'));
  for (const id of v.order.slice(0, 3).concat(['f9999'])) put('finding ' + id, get('swarm/' + rid + '/finding/' + id));
  for (const t of v.tasks.slice(0, 3).concat([{ n: 9999 }])) put('task ' + t.n, get('swarm/' + rid + '/task/' + t.n));
  for (const o of offs) put('bytes ' + o, get('swarm/' + rid + '/bytes', { off: String(o), len: '64' }));
  for (const name of ['report', 'report.md', 'board.json', 'report.html', 'iocs.csv', 'iocs.stix.json', 'iocs.misp.json', 'detection.yar']) put('file ' + name, get('swarm/' + rid + '/' + name));
  put('nope', get('swarm/' + rid + '/model'));
  out[n] = row;
}
process.stdout.write(JSON.stringify(out));
