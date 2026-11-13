import { fileURLToPath } from 'node:url';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import zlib from 'node:zlib';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { readPackage, checkManifest, parseStrictJson } from '../src/cmd-npm.js';

const dir = fs.mkdtempSync(join(tmpdir(), 'npm-area-'));
after(() => fs.rmSync(dir, { recursive: true, force: true }));
const cli = fileURLToPath(new URL('../bin/lmconn.js', import.meta.url));
const TOKEN = 'npm_CANARY_TOKEN_0123456789';
const sri = (b) => 'sha512-' + createHash('sha512').update(b).digest('base64');

// ---- minimal tar writer for hostile fixtures ----
function header(name, size, type = '0') {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100); h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  h.write(size.toString(8).padStart(11, '0') + '\0', 124); h.write('00000000000\0', 136); h.write('        ', 148);
  h.write(type, 156); h.write('ustar\0', 257); h.write('00', 263);
  let sum = 0; for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return h;
}
const entry = (name, body = '', type = '0') => { const b = Buffer.from(body); return Buffer.concat([header(name, b.length, type), b, Buffer.alloc((512 - (b.length % 512)) % 512)]); };
const tgz = (...entries) => zlib.gzipSync(Buffer.concat([...entries, Buffer.alloc(1024)]));
const manifest = (extra = {}) => JSON.stringify({ name: '@lmctl-ai/demo', version: '1.0.0', ...extra });
const good = (extra) => tgz(entry('package/package.json', manifest(extra)), entry('package/index.js', 'x'));

test('tar reader accepts a normal package and rejects hostile layouts', () => {
  assert.equal(readPackage(good()).manifest.name, '@lmctl-ai/demo');
  const m = entry('package/package.json', manifest());
  const bad = {
    'entry outside package/': tgz(m, entry('other/package.json', '{}')),
    'dotdot': tgz(m, entry('package/../x', 'x')),
    'absolute': tgz(m, entry('/etc/x', 'x')),
    'duplicate after normalization': tgz(m, entry('package//package.json', manifest())),
    'symlink': tgz(m, entry('package/l', '', '2')),
    'hardlink': tgz(m, entry('package/l', '', '1')),
    'device': tgz(m, entry('package/d', '', '3')),
    'pax path': tgz(m, entry('PaxHeader', '30 path=other/package.json\n'.replace('30', '28'), 'x'), entry('package/y', 'x')),
    'hidden entry after a single zero block': zlib.gzipSync(Buffer.concat([m, Buffer.alloc(512), entry('package/package.json', manifest({ publishConfig: { registry: 'http://evil' } })), Buffer.alloc(1024)])),
    'bytes after the end marker': zlib.gzipSync(Buffer.concat([m, Buffer.alloc(1024), entry('package/x', 'x')])),
    'no end marker': zlib.gzipSync(m),
    'prefix without ustar magic': (() => { const h = entry('package.json', manifest()); h.write('package', 345); h.fill(0, 257, 265); return tgz(h); })(),
    'file name ending in slash': tgz(m, entry('package/a/', 'x')),
    'file and directory share a path': tgz(m, entry('package/a', 'x'), entry('package/a/b', 'y')),
    'pax record with a short length': tgz(m, entry('PaxHeader', '2 path=x\n', 'x'), entry('package/y', 'x')),
    'no manifest': tgz(entry('package/index.js', 'x')),
    'duplicate manifest member': tgz(entry('package/package.json', '{"name":"a","version":"1.0.0","name":"b"}')),
    'not gzip': Buffer.from('hello'),
  };
  for (const [what, buf] of Object.entries(bad)) assert.throws(() => readPackage(buf), /./, what);
});

test('strict JSON refuses duplicate members at any depth', () => {
  assert.deepEqual(parseStrictJson('{"a":[1,{"b":2}]}'), { a: [1, { b: 2 }] });
  assert.throws(() => parseStrictJson('{"a":{"b":1,"b":2}}'), /duplicate/);
  assert.throws(() => parseStrictJson('{"a":1} x'));
});

test('manifest policy: publishConfig, top-level tag, prerelease needs --tag', () => {
  assert.deepEqual(checkManifest({ name: 'a', version: '1.0.0' }), { name: 'a', version: '1.0.0' });
  for (const bad of [
    { name: 'a', version: '1.0.0', tag: 'latest' },
    { name: 'a', version: '1.0.0', publishConfig: { registry: 'https://evil' } },
    { name: 'a', version: '1.0.0', publishConfig: { '@a:registry': 'https://evil' } },
    { name: 'a', version: '1.0.0', publishConfig: { tag: 'latest' } },
    { name: 'a', version: '2.0.0-rc.1' },
    { name: 'A B', version: '1.0.0' }, { name: 'a', version: 'x' }, [],
  ]) assert.throws(() => checkManifest(bad, undefined), /./, JSON.stringify(bad));
  assert.throws(() => checkManifest({ name: 'a', version: '2.0.0-rc.1' }, 'latest'), /tag/);
  assert.ok(checkManifest({ name: 'a', version: '2.0.0-rc.1', publishConfig: { access: 'public', tag: 'next' } }, 'next'));
});

// ---- real npm against a loopback mock registry ----
function mockRegistry(mode) {
  const seen = { auth: [], puts: 0, stored: null };
  const server = http.createServer((req, res) => {
    const chunks = []; req.on('data', c => chunks.push(c));
    req.on('end', () => {
      if (req.headers.authorization) seen.auth.push(req.headers.authorization);
      res.setHeader('content-type', 'application/json');
      if (req.method === 'PUT') {
        seen.puts++;
        if (mode === 'fail500') { res.statusCode = 500; return res.end('{"error":"boom"}'); }
        const body = JSON.parse(Buffer.concat(chunks)); const name = Object.keys(body.versions)[0];
        const v = body.versions[name]; const att = Object.values(body._attachments)[0];
        seen.stored = { name: body.name, version: v.version, tag: Object.keys(body['dist-tags']), integrity: sri(Buffer.from(att.data, 'base64')) };
        return res.end('{}');
      }
      if (req.url.endsWith('/-/whoami')) return res.end('{"username":"ci-bot"}');
      const stored = mode === 'conflict' ? { name: '@lmctl-ai/demo', version: '1.0.0', integrity: 'sha512-' + 'A'.repeat(86) + '==' } : seen.stored;
      if (!stored) { res.statusCode = 404; return res.end('{"error":"Not found"}'); }
      res.end(JSON.stringify({ name: stored.name, 'dist-tags': { latest: stored.version }, versions: { [stored.version]: { name: stored.name, version: stored.version, dist: { integrity: stored.integrity, tarball: 'http://x/y.tgz' } } } }));
    });
  });
  return new Promise(r => server.listen(0, '127.0.0.1', () => r({ server, seen, url: `http://127.0.0.1:${server.address().port}` })));
}

function lmconn(args, { input, env = {} } = {}) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [cli, ...args], { env: { ...process.env, LMCONN_DB: join(dir, 'main.db'), LMCONN_RUN_DIR: join(dir, 'run'), LMCONN_NPM_RECONCILE_MS: '300', LMCONN_NPM_TEST: '1', ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = ''; let err = '';
    c.stdout.on('data', d => { out += d; }); c.stderr.on('data', d => { err += d; });
    c.on('close', code => { let json = null; try { json = JSON.parse(out); } catch { /* */ } resolve({ code, out, err, json }); });
    c.stdin.end(input === undefined ? '' : JSON.stringify(input));
  });
}
const store = (handle, origin) => lmconn(['cred', 'store', handle, '--stdin'], { env: { LMCONN_STORE_MODE: 'broker' }, input: { kind: 'bearer', accessToken: TOKEN, scopes: ['publish'], owner: 'test', source: 'lmauth', issuer: 'https://registry.npmjs.org', allowedOrigins: [origin] } });

async function packDemo(version = '1.0.0', extra = {}) {
  const src = join(dir, 'src-' + version); fs.mkdirSync(join(src, 'node_modules/leak'), { recursive: true });
  fs.writeFileSync(join(src, 'package.json'), JSON.stringify({ name: '@lmctl-ai/demo', version, files: ['index.js'], scripts: { prepack: 'touch ../PWNED', prepublishOnly: 'touch ../PWNED' }, ...extra }));
  fs.writeFileSync(join(src, 'index.js'), 'module.exports=1\n'); fs.writeFileSync(join(src, 'node_modules/leak/x.js'), 'x');
  const out = join(dir, `demo-${version}.tgz`);
  const r = await lmconn(['npm', 'pack', src, '--out', out]);
  return { r, out, src };
}

test('pack uses real npm with scripts off and returns the file hash', async () => {
  const { r, out } = await packDemo();
  assert.equal(r.code, 0, r.out + r.err);
  assert.equal(r.json.result.integrity, sri(fs.readFileSync(out)));
  assert.equal(r.json.result.name, '@lmctl-ai/demo');
  assert.ok(!fs.existsSync(join(dir, 'PWNED')) && !fs.existsSync(join(dir, 'run', 'PWNED')), 'lifecycle script did not run');
  assert.deepEqual(fs.readdirSync(join(dir, 'run')), [], 'scratch directory removed');
});

test('publish: token only through env, receipt only, hostile caller env ignored, scratch removed', async () => {
  const reg = await mockRegistry('ok');
  try {
    assert.equal((await store('npmcred', reg.url)).code, 0);
    const { out } = await packDemo('1.0.1');
    const integrity = sri(fs.readFileSync(out));
    const r = await lmconn(['npm', 'publish', out, '--credential', 'npmcred', '--expect-integrity', integrity],
      { env: { LMCONN_STORE_MODE: 'broker', LMCONN_NPM_TEST_REGISTRY: reg.url, NPM_CONFIG_REGISTRY: 'http://127.0.0.1:1', npm_config_userconfig: '/nonexistent', NPM_TOKEN: 'x' } });
    assert.equal(r.code, 0, r.out + r.err);
    assert.equal(r.json.result.outcome, 'published_confirmed');
    assert.equal(r.json.result.registryIntegrity, integrity);
    assert.equal(reg.seen.puts, 1);
    assert.ok(reg.seen.auth.includes('Bearer ' + TOKEN));
    assert.ok(!r.out.includes(TOKEN) && !r.err.includes(TOKEN));
    assert.deepEqual(fs.readdirSync(join(dir, 'run')), []);
    const again = await lmconn(['npm', 'publish', out, '--credential', 'npmcred', '--expect-integrity', integrity], { env: { LMCONN_STORE_MODE: 'broker', LMCONN_NPM_TEST_REGISTRY: reg.url } });
    assert.equal(again.json.result.outcome, 'published_confirmed', 'already published with the same bytes is confirmed, not an error');
  } finally { reg.server.close(); }
});

test('publish: conflict, pending, refusals before the credential is touched', async () => {
  const conflict = await mockRegistry('conflict');
  const pending = await mockRegistry('fail500');
  try {
    assert.equal((await store('c1', conflict.url)).code, 0);
    assert.equal((await store('c2', pending.url)).code, 0);
    const { out } = await packDemo('1.0.0');
    const integrity = sri(fs.readFileSync(out));
    const base = { LMCONN_STORE_MODE: 'broker' };
    let r = await lmconn(['npm', 'publish', out, '--credential', 'c1', '--expect-integrity', integrity], { env: { ...base, LMCONN_NPM_TEST_REGISTRY: conflict.url } });
    assert.equal(r.json.result.outcome, 'conflict');
    r = await lmconn(['npm', 'publish', out, '--credential', 'c2', '--expect-integrity', integrity], { env: { ...base, LMCONN_NPM_TEST_REGISTRY: pending.url } });
    assert.equal(r.json.result.outcome, 'pending_verification');
    assert.equal(pending.seen.puts, 1, 'never retried blindly');
    // wrong hash: refused with no credential lookup (the handle does not even exist)
    r = await lmconn(['npm', 'publish', out, '--credential', 'nosuch', '--expect-integrity', 'sha512-' + 'B'.repeat(86) + '=='], { env: { ...base, LMCONN_NPM_TEST_REGISTRY: pending.url } });
    assert.equal(r.json.error.code, 'NPM_REFUSED');
    // origin outside the credential binding
    r = await lmconn(['npm', 'publish', out, '--credential', 'c1', '--expect-integrity', integrity], { env: { ...base, LMCONN_NPM_TEST_REGISTRY: pending.url } });
    assert.equal(r.json.error.code, 'CREDENTIAL_POLICY');
    // prerelease without --tag
    const rc = await packDemo('2.0.0-rc.1');
    r = await lmconn(['npm', 'publish', rc.out, '--credential', 'c1', '--expect-integrity', sri(fs.readFileSync(rc.out))], { env: { ...base, LMCONN_NPM_TEST_REGISTRY: conflict.url } });
    assert.equal(r.json.error.code, 'NPM_REFUSED');
    assert.match(r.json.error.message, /--tag/);
    // publishConfig registry in the manifest
    const evil = await packDemo('1.0.2', { publishConfig: { registry: 'https://evil.invalid' } });
    r = await lmconn(['npm', 'publish', evil.out, '--credential', 'c1', '--expect-integrity', sri(fs.readFileSync(evil.out))], { env: { ...base, LMCONN_NPM_TEST_REGISTRY: conflict.url } });
    assert.equal(r.json.error.code, 'NPM_REFUSED');
  } finally { conflict.server.close(); pending.server.close(); }
});

test('whoami returns only the user name; unknown flags are refused', async () => {
  const reg = await mockRegistry('ok');
  try {
    assert.equal((await store('w1', reg.url)).code, 0);
    const r = await lmconn(['npm', 'whoami', '--credential', 'w1'], { env: { LMCONN_STORE_MODE: 'broker', LMCONN_NPM_TEST_REGISTRY: reg.url } });
    assert.equal(r.code, 0, r.out + r.err);
    assert.equal(r.json.result.username, 'ci-bot');
    for (const flag of ['--registry', '--userconfig', '--otp', '--globalconfig']) {
      const x = await lmconn(['npm', 'publish', 'f.tgz', '--credential', 'w1', '--expect-integrity', 'z', flag, 'v']);
      assert.equal(x.code, 2, flag);
    }
  } finally { reg.server.close(); }
});

test('an ancestor project config cannot steer npm; test overrides are ignored without LMCONN_NPM_TEST', async () => {
  const reg = await mockRegistry('ok');
  try {
    assert.equal((await store('anc', reg.url)).code, 0);
    fs.writeFileSync(join(dir, 'package.json'), '{"name":"ancestor"}'); fs.writeFileSync(join(dir, '.npmrc'), 'registry=http://127.0.0.1:1/\nstrict-ssl=false\nhttps-proxy=http://127.0.0.1:1\n');
    const { out } = await packDemo('1.0.3');
    const integrity = sri(fs.readFileSync(out));
    const r = await lmconn(['npm', 'publish', out, '--credential', 'anc', '--expect-integrity', integrity], { env: { LMCONN_STORE_MODE: 'broker', LMCONN_NPM_TEST_REGISTRY: reg.url } });
    assert.equal(r.json?.result?.outcome, 'published_confirmed', r.out + r.err);
    assert.equal(reg.seen.puts, 1);
    // an ancestor setting that only the config (not our command line) controls: retries must stay 0
    fs.writeFileSync(join(dir, '.npmrc'), 'fetch-retries=2\nfetch-retry-mintimeout=10\nfetch-retry-maxtimeout=20\n');
    const bad = await mockRegistry('fail500');
    try {
      assert.equal((await store('anc2', bad.url)).code, 0);
      const rc = await packDemo('1.0.4'); const ig = sri(fs.readFileSync(rc.out));
      await lmconn(['npm', 'publish', rc.out, '--credential', 'anc2', '--expect-integrity', ig], { env: { LMCONN_STORE_MODE: 'broker', LMCONN_NPM_TEST_REGISTRY: bad.url } });
      assert.equal(bad.seen.puts, 1, 'ancestor .npmrc must not be read');
    } finally { bad.server.close(); }
    // without the test switch the registry is the constant, which this credential is not bound to
    const x = await lmconn(['npm', 'whoami', '--credential', 'anc'], { env: { LMCONN_STORE_MODE: 'broker', LMCONN_NPM_TEST: '', LMCONN_NPM_TEST_REGISTRY: reg.url, LMCONN_NPM_BIN: '/bin/true' } });
    assert.equal(x.json.error.code, 'CREDENTIAL_POLICY');
  } finally { reg.server.close(); }
});
