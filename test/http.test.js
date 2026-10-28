import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run, parseArgs, envNameFor } from '../src/cmd-http.js';
import { setCred, closeDb } from '../src/creds.js';

const directory = mkdtempSync(join(tmpdir(), 'lmconn-http-test-'));
const originalDb = process.env.LMCONN_DB;
process.env.LMCONN_DB = join(directory, 'creds.db');

let server; let base; let last;
before(async () => {
  server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      last = { method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString('utf8') };
      if (req.url === '/json') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ hello: 'world', echo: last.headers['x-echo'] ?? null }));
      } else if (req.url === '/text') {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('plain body');
      } else if (req.url === '/slow') {
        setTimeout(() => { res.writeHead(200); res.end('late'); }, 500);
      } else if (req.url === '/missing') {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'nope' }));
      } else {
        res.writeHead(500); res.end('boom');
      }
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => {
  server.close();
  if (originalDb === undefined) delete process.env.LMCONN_DB; else process.env.LMCONN_DB = originalDb;
  closeDb(join(directory, 'creds.db')); // Windows: open handle blocks rm
  rmSync(directory, { recursive: true, force: true });
});

async function capture(args) {
  const stdoutWrite = process.stdout.write;
  const stderrWrite = process.stderr.write;
  let stdout = ''; let stderr = '';
  process.stdout.write = function (chunk, ...rest) {
    if (typeof chunk !== 'string') return stdoutWrite.call(this, chunk, ...rest);
    stdout += chunk; return true;
  };
  process.stderr.write = (chunk) => { stderr += chunk; return true; };
  try {
    const code = await run(args);
    return { code, stdout, stderr, envelope: JSON.parse(stdout) };
  } finally {
    process.stdout.write = stdoutWrite;
    process.stderr.write = stderrWrite;
  }
}

test('GET parses a JSON body and injects custom headers', async () => {
  const r = await capture(['request', `${base}/json`, '--header', 'X-Echo: ping', '--header', 'X-Other:  spaced  ']);
  assert.equal(r.code, 0);
  assert.equal(r.envelope.ok, true);
  const res = r.envelope.result;
  assert.equal(res.status, 200);
  assert.equal(res.ok, true);
  assert.match(res.contentType, /application\/json/);
  assert.deepEqual(res.bodyJson, { hello: 'world', echo: 'ping' });
  assert.equal(res.bodyText, undefined);
  assert.equal(typeof res.latencyMs, 'number');
  assert.equal(last.headers['x-other'], 'spaced');
  assert.equal(last.method, 'GET');
});

test('text body is returned as bodyText', async () => {
  const r = await capture(['request', `${base}/text`]);
  assert.equal(r.envelope.result.bodyText, 'plain body');
  assert.equal(r.envelope.result.bodyJson, undefined);
});

test('--data implies POST and application/json when the body is JSON', async () => {
  const r = await capture(['request', `${base}/json`, '--data', '{"a":1}']);
  assert.equal(r.code, 0);
  assert.equal(last.method, 'POST');
  assert.equal(last.body, '{"a":1}');
  assert.equal(last.headers['content-type'], 'application/json');
});

test('--data-file sends the file content with an explicit method', async () => {
  const file = join(directory, 'body.txt');
  writeFileSync(file, 'hello file');
  const r = await capture(['request', `${base}/json`, '--method', 'put', '--data-file', file]);
  assert.equal(r.code, 0);
  assert.equal(last.method, 'PUT');
  assert.equal(last.body, 'hello file');
  assert.match(last.headers['content-type'], /text\/plain/);
});

test('error status is a successful envelope with ok:false inside the result', async () => {
  const r = await capture(['request', `${base}/missing`]);
  assert.equal(r.code, 0);
  assert.equal(r.envelope.ok, true);
  assert.equal(r.envelope.result.status, 404);
  assert.equal(r.envelope.result.ok, false);
  assert.deepEqual(r.envelope.result.bodyJson, { error: 'nope' });
  const r2 = await capture(['request', `${base}/boom`]);
  assert.equal(r2.envelope.result.status, 500);
  assert.equal(r2.envelope.result.bodyText, 'boom');
});

test('--auth sends a Bearer token from the store and never prints it', async () => {
  setCred('acme', 'api_key', 'sk-secret-store');
  const r = await capture(['request', `${base}/json`, '--auth', 'acme']);
  assert.equal(r.code, 0);
  assert.equal(last.headers.authorization, 'Bearer sk-secret-store');
  assert.ok(!r.stdout.includes('sk-secret-store'));
  assert.ok(!r.stderr.includes('sk-secret-store'));
});

test('--auth falls back to <SERVICE>_API_KEY and fails cleanly when nothing is set', async () => {
  assert.equal(envNameFor('ollama-cloud'), 'OLLAMA_CLOUD_API_KEY');
  process.env.ZED_TEST_API_KEY = 'sk-from-env';
  try {
    const r = await capture(['request', `${base}/json`, '--auth', 'zed-test']);
    assert.equal(last.headers.authorization, 'Bearer sk-from-env');
    assert.ok(!r.stdout.includes('sk-from-env'));
  } finally { delete process.env.ZED_TEST_API_KEY; }
  const miss = await capture(['request', `${base}/json`, '--auth', 'nobody-here']);
  assert.equal(miss.code, 1);
  assert.equal(miss.envelope.ok, false);
  assert.equal(miss.envelope.error.code, 'MISSING_KEY');
  assert.match(miss.envelope.error.message, /NOBODY_HERE_API_KEY/);
});

test('timeout and connection errors are runtime failures (exit 1)', async () => {
  const slow = await capture(['request', `${base}/slow`, '--timeout', '50']);
  assert.equal(slow.code, 1);
  assert.equal(slow.envelope.error.code, 'TIMEOUT');
  const closed = createServer(); await new Promise((r) => closed.listen(0, '127.0.0.1', r));
  const port = closed.address().port; await new Promise((r) => closed.close(r));
  const dead = await capture(['request', `http://127.0.0.1:${port}/`, '--timeout', '2000']);
  assert.equal(dead.code, 1);
  assert.equal(dead.envelope.error.code, 'NETWORK');
});

test('usage errors exit 2', async () => {
  for (const args of [[], ['get'], ['request'], ['request', 'ftp://x'], ['request', 'not a url'],
    ['request', 'http://x', '--bogus'], ['request', 'http://x', '--data', 'a', '--data-file', 'b'],
    ['request', 'http://x', '--header', 'no-colon'], ['request', 'http://x', '--timeout', '-1']]) {
    const r = await capture(args);
    assert.equal(r.code, 2, JSON.stringify(args));
    assert.equal(r.envelope.error.code, 'USAGE');
  }
  assert.throws(() => parseArgs(['request', 'http://x', '--method']), /missing value/);
});

test('ops fragment names the http_request operation', async () => {
  const { ops } = await import('../src/cmd-http.js');
  assert.equal(ops[0].name, 'http_request');
  assert.ok(ops[0].params.some((p) => p.name === 'url' && p.positional === true));
});
