import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { startMock } from '../scripts/lmmock.js';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run, parseArgs, envNameFor } from '../src/cmd-http.js';
import { setCred, getCred, closeDb } from '../src/creds.js';

const directory = mkdtempSync(join(tmpdir(), 'lmconn-http-test-'));
const originalDb = process.env.LMCONN_DB;
process.env.LMCONN_DB = join(directory, 'creds.db');

let server; let base; let last;
let refreshCalls = 0; let tokenRequest; let tokenReply; let tokenStatus = 200;
let generation = 0;
before(async () => {
  server = await startMock('connector-http', {generation,tokenStatus:200,tokenReply:{}});
  base = server.origin;
});
after(async () => {
  await server.close();
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
    server.configure({generation,tokenStatus,tokenReply:tokenReply || {}});
    const code = await run(args);
    ({last,tokenRequest,refreshCalls} = await server.inspect());
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

function seedOAuth(service, { expired = true, refresh = true, style = 'header' } = {}) {
  const values = {
    oauth_access_token: 'oauth-old-private',
    oauth_expires_at: new Date(Date.now() + (expired ? -60000 : 3600000)).toISOString(),
    oauth_token_url: `${base}/token`, oauth_client_id: 'client-id',
    oauth_client_secret: 'client-private', oauth_auth_style: style,
  };
  if (refresh) values.oauth_refresh_token = 'refresh-private';
  for (const [field, value] of Object.entries(values)) setCred(service, field, value);
  refreshCalls = 0;
  generation++;
  tokenStatus = 200;
  tokenReply = { access_token: 'oauth-fresh-private', expires_in: 3600, token_type: 'Bearer' };
}
function assertNoSecrets(result) {
  for (const secret of ['oauth-old-private', 'oauth-fresh-private', 'refresh-private', 'rotated-private', 'client-private']) {
    assert.ok(!result.stdout.includes(secret));
    assert.ok(!result.stderr.includes(secret));
  }
}

test('valid OAuth token is used without refresh and echoed credentials are redacted', async () => {
  seedOAuth('oauth-valid', { expired: false });
  const r = await capture(['request', `${base}/echo-auth`, '--auth', 'oauth-valid']);
  assert.equal(r.code, 0);
  assert.equal(last.headers.authorization, 'Bearer oauth-old-private');
  assert.equal(refreshCalls, 0);
  assert.equal(r.envelope.result.bodyJson.authorization, 'Bearer [REDACTED]');
  assertNoSecrets(r);
});

test('expired OAuth token refreshes once with Basic auth and retains refresh token', async () => {
  seedOAuth('oauth-header');
  const before = Date.now();
  const r = await capture(['request', `${base}/json`, '--auth', 'oauth-header']);
  assert.equal(r.code, 0);
  assert.equal(refreshCalls, 1);
  assert.equal(tokenRequest.method, 'POST');
  assert.equal(tokenRequest.headers.authorization, `Basic ${Buffer.from('client-id:client-private').toString('base64')}`);
  assert.deepEqual(Object.fromEntries(new URLSearchParams(tokenRequest.body)), { grant_type: 'refresh_token', refresh_token: 'refresh-private' });
  assert.equal(last.headers.authorization, 'Bearer oauth-fresh-private');
  assert.equal(getCred('oauth-header', 'oauth_refresh_token'), 'refresh-private');
  assert.equal(getCred('oauth-header', 'oauth_access_token'), 'oauth-fresh-private');
  assert.equal(getCred('oauth-header', 'oauth_token_type'), 'Bearer');
  assert.ok(Date.parse(getCred('oauth-header', 'oauth_expires_at')) >= before + 3600000);
  assertNoSecrets(r);
  assert.equal((await capture(['request', `${base}/json`, '--auth', 'oauth-header'])).code, 0);
  assert.equal(refreshCalls, 1);
});

test('body client auth rotates refresh tokens and stores new scope', async () => {
  seedOAuth('oauth-body', { style: 'body' });
  tokenReply.refresh_token = 'rotated-private';
  tokenReply.scope = 'read';
  const r = await capture(['request', `${base}/json`, '--auth', 'oauth-body']);
  assert.equal(r.code, 0);
  assert.equal(tokenRequest.headers.authorization, undefined);
  assert.deepEqual(Object.fromEntries(new URLSearchParams(tokenRequest.body)), {
    grant_type: 'refresh_token', refresh_token: 'refresh-private', client_id: 'client-id', client_secret: 'client-private',
  });
  assert.equal(getCred('oauth-body', 'oauth_refresh_token'), 'rotated-private');
  assert.equal(getCred('oauth-body', 'oauth_scope'), 'read');
  assertNoSecrets(r);
});

test('invalid_grant or expired token without refresh requires reconnect', async () => {
  for (const refresh of [true, false]) {
    const service = `oauth-reconnect-${refresh}`;
    seedOAuth(service, { refresh });
    tokenStatus = 400;
    tokenReply = { error: 'invalid_grant', error_description: 'refresh-private client-private' };
    const r = await capture(['request', `${base}/json`, '--auth', service]);
    assert.equal(r.code, 1);
    assert.equal(r.envelope.error.code, 'RECONNECT');
    assert.ok(r.envelope.error.message.includes(`lmconn oauth authorize ${service}`));
    assert.equal(refreshCalls, refresh ? 1 : 0);
    assert.equal(getCred(service, 'oauth_access_token'), 'oauth-old-private');
    assertNoSecrets(r);
  }
});

test('API key precedence is store, environment, then OAuth without unnecessary refresh', async () => {
  seedOAuth('oauth-precedence');
  setCred('oauth-precedence', 'api_key', 'stored-api-private');
  const original = process.env.OAUTH_PRECEDENCE_API_KEY;
  process.env.OAUTH_PRECEDENCE_API_KEY = 'env-api-private';
  try {
    const stored = await capture(['request', `${base}/json`, '--auth', 'oauth-precedence']);
    assert.equal(stored.code, 0);
    assert.equal(last.headers.authorization, 'Bearer stored-api-private');
    setCred('oauth-precedence', 'api_key', '');
    const env = await capture(['request', `${base}/json`, '--auth', 'oauth-precedence']);
    assert.equal(env.code, 0);
    assert.equal(last.headers.authorization, 'Bearer env-api-private');
    assert.equal(refreshCalls, 0);
  } finally {
    if (original === undefined) delete process.env.OAUTH_PRECEDENCE_API_KEY;
    else process.env.OAUTH_PRECEDENCE_API_KEY = original;
  }
});

test('refresh failures do not leak token endpoint details or mutate stored tokens', async () => {
  seedOAuth('oauth-failure');
  tokenStatus = 500;
  tokenReply = { error: 'server_error', error_description: 'refresh-private client-private' };
  const r = await capture(['request', `${base}/json`, '--auth', 'oauth-failure']);
  assert.equal(r.code, 1);
  assert.equal(r.envelope.error.code, 'OAUTH_REFRESH');
  assert.equal(getCred('oauth-failure', 'oauth_access_token'), 'oauth-old-private');
  assertNoSecrets(r);
  const missing = await capture(['request', `${base}/json`, '--auth', 'oauth-absent']);
  assert.match(missing.envelope.error.message, /lmconn cred set oauth-absent api_key/);
  assert.match(missing.envelope.error.message, /lmconn oauth authorize oauth-absent/);
});


test('lmmock injects rate limits, malformed JSON and connection loss', async () => {
  const limited = await capture(['request', `${base}/rate-limit`]);
  assert.equal(limited.envelope.result.status, 429);
  assert.equal(limited.envelope.result.ok, false);
  const malformed = await capture(['request', `${base}/malformed`]);
  assert.equal(malformed.envelope.result.bodyText, '{broken');
  const dropped = await capture(['request', `${base}/disconnect`]);
  assert.equal(dropped.code, 1);
  assert.equal(dropped.envelope.error.code, 'NETWORK');
});
