// Run the packaged script in a real V8 global script scope, not eval's local
// declaration scope. A browser Window has an unforgeable location accessor.
const fs = require('fs'), path = require('path'), vm = require('vm'), assert = require('assert');
const { spawnSync } = require('child_process');
const scenarios = ['normal', 'denied-storage', 'bad-preferences', 'bridge-error', 'no-bridge', 'timeout', 'script-error', 'missing-editor'];
if (!process.argv[2]) {
  for (const scenario of scenarios) {
    const result = spawnSync(process.execPath, [__filename, scenario], { encoding: 'utf8', env: process.env });
    process.stdout.write(result.stdout); process.stderr.write(result.stderr);
    if (result.status !== 0) process.exit(result.status || 1);
  }
  console.log('ALL 8 STARTUP CHECKS PASSED (V8/DOM; Android WebView is not emulated)');
} else (async () => {
  const scenario = process.argv[2];
  const { Window } = await import(process.env.HAPPY_DOM_PATH || path.resolve(__dirname, '../../toolchain/test-node/node_modules/happy-dom/lib/index.js'));
  const w = new Window({ url: 'https://appassets.androidplatform.net/assets/app.html', settings: { disableJavaScriptFileLoading: true, disableCSSFileLoading: true } });
  const assets = path.resolve(__dirname, '../app/src/main/assets');
  w.document.write(fs.readFileSync(path.join(assets, 'app.html'), 'utf8').replace(/<script[^>]*>[\s\S]*?<\/script>/g, '').replace(/<link[^>]*>/g, ''));
  assert(w.document.querySelector('#toolbar').textContent.includes('DB Manager'));
  assert(w.document.querySelector('#content').textContent.includes('Opening your workspace'));
  for (const key of ['document', 'Element', 'Node']) globalThis[key] = w[key];
  globalThis.window = w;
  Object.defineProperty(globalThis, 'navigator', { value: w.navigator, configurable: true });
  const browserLocation = w.location;
  Object.defineProperty(globalThis, 'location', { get: () => browserLocation, set: () => { throw Error('Unexpected navigation'); }, configurable: false, enumerable: true });
  assert.throws(() => vm.runInThisContext('function location(p) { return p; }'), /Identifier 'location' has already been declared/);
  const originalSetTimeout = globalThis.setTimeout;
  // Keep RPC and boot-watchdog timeout tests fast, without changing app code.
  if (scenario === 'timeout') globalThis.setTimeout = (fn, delay, ...args) => originalSetTimeout(fn, delay >= 15000 ? 60 : delay, ...args);
  const errors = [];
  w.addEventListener('error', e => errors.push(e.message));
  delete w.Element.prototype.replaceChildren;
  vm.runInThisContext(fs.readFileSync(path.join(assets, 'boot.js'), 'utf8'), { filename: 'boot.js' });
  if (scenario === 'denied-storage') Object.defineProperty(w, 'localStorage', { get: () => { throw Error('Access denied'); } });
  if (scenario === 'bad-preferences') w.localStorage.setItem('cyber-preferences', '{bad json');
  if (scenario !== 'no-bridge') w.CyberNative = {
    request(id, action) {
      if (scenario === 'bridge-error') throw Error('Native bridge test failure');
      if (scenario === 'timeout') return;
      const data = action === 'init'
        ? { permission: false, home: '/storage/emulated/0', workspace: '/data/Workspace', ownApk: '/data/base.apk' }
        : [{ name: 'Welcome.txt', path: '/data/Workspace/Welcome.txt', size: 20, time: 1, dir: false }];
      originalSetTimeout(() => w.receive({ id, ok: true, data }), 1);
    }
  };
  for (const file of ['vendor/codemirror.js', 'vendor/clike.js', 'vendor/xml.js', 'vendor/searchcursor.js']) w.eval(fs.readFileSync(path.join(assets, file), 'utf8'));
  if (scenario !== 'missing-editor') globalThis.CodeMirror = w.CodeMirror;
  const source = fs.readFileSync(path.join(assets, 'app.js'), 'utf8');
  try {
    vm.runInThisContext(scenario === 'script-error' ? 'function broken( {' : source, { filename: 'app.js' });
  } catch (error) {
    // DOM engines dispatch script compilation/execution failures as ErrorEvents.
    w.dispatchEvent(new w.ErrorEvent('error', { message: error.message, error, lineno: 1 }));
  }
  await new Promise(resolve => originalSetTimeout(resolve, 180));
  if (['normal', 'denied-storage', 'bad-preferences'].includes(scenario)) {
    assert.equal(w.document.querySelectorAll('.pane').length, 2);
    assert(w.document.querySelector('#grant'));
    assert(w.document.querySelector('#content').textContent.includes('Welcome.txt'));
    assert.equal(w.document.querySelectorAll('#bottom button').length, 5);
    w.document.querySelector('[aria-label="Open navigation"]').click();
    await new Promise(resolve => originalSetTimeout(resolve, 20));
    assert(w.document.querySelector('.drawer'));
    assert.deepEqual(errors, []);
  } else {
    assert(w.document.querySelector('#content').textContent.includes('Unable to start'));
    assert(w.document.querySelector('.bootDetails').textContent.length > 30);
    assert(w.document.querySelector('.bootStatus button'));
    assert(!w.document.body.classList.contains('busy'));
  }
  assert.strictEqual(globalThis.location, browserLocation);
  assert.equal(globalThis.paneLocation, undefined, 'App helpers must stay private');
  w.CyberBoot.ready();
  await w.happyDOM.close();
  console.log('PASS ' + scenario + ': visible startup state; protected Window.location unchanged');
})().catch(e => { console.error(e); process.exit(1); });
