// Run with: node --test Tests/Prototype/terminal.test.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function prototype() {
  const html = fs.readFileSync(path.join(__dirname, '../../docs/prototype/skerry-gui.html'), 'utf8');
  const open = html.indexOf('<script>');
  assert.notEqual(open, -1, 'the prototype has no opening <script> tag');
  const start = open + '<script>'.length;
  const end = html.indexOf('</script>', start);
  assert.notEqual(end, -1, 'the prototype has no closing </script> tag');
  const script = html.slice(start, end);
  const elements = new Map();
  const listeners = {};
  const document = {
    getElementById(id) {
      if (id === 'statusbar') return null;
      if (!elements.has(id)) elements.set(id, { id, dataset: {}, style: {}, focus() {} });
      return elements.get(id);
    },
    addEventListener(type, listener) { listeners[type] = listener; }
  };
  vm.runInNewContext(script, { document, setTimeout });
  function act(act, id) {
    listeners.click({ target: { closest: () => ({ dataset: { act, id } }) } });
  }
  function view(id) { act('view', id); }
  function command(value) {
    const target = { id: 'terminput', value };
    listeners.keydown({ target, key: 'Enter' });
  }
  return { act, view, command, pane: () => elements.get('pane').innerHTML };
}

test('restart displays an argument as text across terminal renders', () => {
  const app = prototype();
  app.view('terminal');
  app.command('docker restart <img/src="x"/onerror="window.test=1">');
  const escaped = '&lt;img/src=&quot;x&quot;/onerror=&quot;window.test=1&quot;&gt;';
  assert.ok(app.pane().includes(`<div class="term-line">${escaped}</div>`));
  assert.ok(!app.pane().includes('<img/src='));
  app.view('overview');
  app.view('terminal');
  assert.ok(app.pane().includes(`<div class="term-line">${escaped}</div>`));
  assert.ok(app.pane().includes('<span class="d">container restarted in 1.8 s</span>'));
});

test('restart preserves ordinary names and HTML entities as literal text', () => {
  const app = prototype();
  app.view('terminal');
  app.command('docker restart web');
  app.command('docker restart &lt;web&gt;');
  assert.ok(app.pane().includes('<div class="term-line">web</div>'));
  assert.ok(app.pane().includes('<div class="term-line">&amp;lt;web&amp;gt;</div>'));
});

test('Docker panel actions display a container name as text', () => {
  const app = prototype();
  const name = '<img/src="x"/onerror="window.test=1">';
  const escaped = '&lt;img/src=&quot;x&quot;/onerror=&quot;window.test=1&quot;&gt;';
  app.act('restart', name);
  app.act('logs', name);
  app.view('terminal');
  assert.ok(app.pane().includes(`docker restart ${escaped}</div>`));
  assert.ok(app.pane().includes(`<div class="term-line">${escaped}</div>`));
  assert.ok(app.pane().includes(`docker logs --tail 6 ${escaped}</div>`));
  assert.ok(!app.pane().includes('<img/src='));
});
