// Internal run(args, { onListening(port, authorizeUrl), stdin }) hooks register
// exact ephemeral redirects with the shared IdP and feed manual redirect input.
// Transport wrappers inject faults absent from its pinned interface; they do not
// implement another IdP. All grants/authentication/PKCE checks use createMockIdP.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run, refresh } from '../src/cmd-oauth.js';
import { run as httpRun } from '../src/cmd-http.js';
import { getCred, setCred, closeDb } from '../src/creds.js';
import { schemaDocument, argvFromSchemaCall } from '../src/schema.js';
import { createMockIdP } from '../scripts/mock-idp.js';

const directory = mkdtempSync(join(tmpdir(), 'lmconn-oauth-'));
const previousDb = process.env.LMCONN_DB;
process.env.LMCONN_DB = join(directory, 'creds.db');
after(() => {
  closeDb();
  if (previousDb === undefined) delete process.env.LMCONN_DB;
  else process.env.LMCONN_DB = previousDb;
  rmSync(directory, { recursive: true, force: true });
});
const secrets = new Set(['mock-client-secret']);
function remember(value) { if (value) secrets.add(value); }
function assertRedacted(text) {
  for (const secret of secrets) assert.ok(!text.includes(secret), 'output/log must not contain a secret');
}
async function capture(args, hooks, runner = run) {
  const write = process.stdout.write;
  const errorWrite = process.stderr.write;
  let stdout = '', stderr = '';
  process.stdout.write = function (chunk, ...rest) {
    if (typeof chunk !== 'string') return write.call(this, chunk, ...rest);
    stdout += chunk;
    return true;
  };
  process.stderr.write = chunk => { stderr += chunk; return true; };
  let code;
  try { code = await runner(args, hooks); }
  finally { process.stdout.write = write; process.stderr.write = errorWrite; }
  assert.equal(stdout.trim().split('\n').length, 1);
  assertRedacted(stdout + stderr);
  return { code, envelope: JSON.parse(stdout), stdout, stderr };
}

async function fixture(t, options = {}, authStyle = 'header') {
  const idp = await createMockIdP({ port: 0, requirePkce: true, ...options });
  t.after(async () => { await idp.close(); assertRedacted(JSON.stringify(idp.log)); });
  const transport = globalThis.fetch;
  // Track actual random secrets so redaction checks don't merely test constants.
  t.mock.method(globalThis, 'fetch', async (url, init) => {
    if (String(url) === idp.tokenUrl) {
      const body = new URLSearchParams(init?.body);
      for (const key of ['code', 'code_verifier', 'refresh_token', 'client_secret']) remember(body.get(key));
    }
    const response = await transport(url, init);
    if (String(url) === idp.tokenUrl) {
      const text = await response.clone().text();
      let token;
      try { token = JSON.parse(text); } catch { token = Object.fromEntries(new URLSearchParams(text)); }
      remember(token.access_token);
      remember(token.refresh_token);
    }
    return response;
  });
  const register = port => idp.registerClient({ clientId: 'mock-client', clientSecret: 'mock-client-secret', redirectUris: [`http://127.0.0.1:${port}/callback`], authStyle });
  const follow = async (port, url) => {
    register(port);
    const response = await fetch(url);
    await response.text();
  };
  const flags = ['--client-id', 'mock-client', '--client-secret', 'mock-client-secret', '--auth-url', idp.authUrl, '--token-url', idp.tokenUrl, '--scope', 'read write', '--port', '0', '--timeout', '5000'];
  return { idp, register, follow, flags };
}
async function authorize(t, service, options = {}, extra = [], authStyle = 'header') {
  const mock = await fixture(t, options, authStyle);
  const result = await capture(['authorize', service, ...mock.flags, ...extra], { onListening: mock.follow });
  return { ...result, mock };
}
function interceptToken(t, idp, handler) {
  const transport = globalThis.fetch;
  t.mock.method(globalThis, 'fetch', (url, init) => String(url) === idp.tokenUrl ? handler(url, init, transport) : transport(url, init));
}

test('status before authorization and schema registration including auto-follow', async () => {
  const result = await capture(['status', 'absent', '--json']);
  assert.equal(result.code, 0);
  assert.deepEqual(result.envelope.result, { service: 'absent', authorized: false, expiresAt: null, expired: false, hasRefreshToken: false, scope: '', tokenUrl: null });
  const doc = await schemaDocument();
  for (const name of ['oauth_authorize', 'oauth_refresh', 'oauth_status']) assert.ok(doc.operations.some(op => op.name === name));
  assert.deepEqual(await argvFromSchemaCall(['oauth_status', '--input-json', '{"service":"absent"}']), ['oauth', 'status', 'absent']);
  assert.deepEqual(await argvFromSchemaCall(['oauth_authorize', '--input-json', '{"service":"demo","autoFollow":true}']), ['oauth', 'authorize', 'demo', '--auto-follow']);
});

test('complete authorization validates PKCE, stores tokens/config, and emits only metadata', async t => {
  const start = Date.now();
  const result = await authorize(t, 'happy', {}, ['--auth-query', 'access_type=offline&prompt=consent&state=ignored']);
  assert.equal(result.code, 0);
  const meta = result.envelope.result;
  assert.deepEqual(Object.keys(meta).sort(), ['expiresAt', 'hasRefreshToken', 'scope', 'service']);
  assert.equal(meta.service, 'happy');
  assert.equal(meta.hasRefreshToken, true);
  assert.equal(meta.scope, 'read write');
  assert.ok(Date.parse(meta.expiresAt) >= start + 3600000);
  assert.ok(getCred('happy', 'oauth_access_token'));
  assert.ok(getCred('happy', 'oauth_refresh_token'));
  assert.equal(getCred('happy', 'oauth_client_id'), 'mock-client');
  assert.equal(getCred('happy', 'oauth_token_type'), 'Bearer');
  assert.match(result.stderr, /access_type=offline/);
  const authRequest = result.mock.idp.log.find(entry => entry.path === '/authorize');
  assert.match(authRequest.params.code_challenge, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(authRequest.params.code_challenge_method, 'S256');
  assert.notEqual(authRequest.params.state, 'ignored');
  const status = await capture(['status', 'happy']);
  assert.equal(status.envelope.result.authorized, true);
  assert.equal(status.envelope.result.expired, false);
  setCred('happy', 'oauth_expires_at', new Date(0).toISOString());
  assert.equal((await capture(['status', 'happy'])).envelope.result.expired, true);
});

test('state mismatch fails without token exchange', async t => {
  const result = await authorize(t, 'bad-state', { misbehave: 'bad-state' });
  assert.equal(result.code, 1);
  assert.equal(result.envelope.error.code, 'OAUTH_ERROR');
  assert.equal(result.mock.idp.log.filter(entry => entry.path === '/token').length, 0);
  assert.equal(getCred('bad-state', 'oauth_access_token'), null);
});

test('mock rejects an incorrect PKCE verifier', async t => {
  const mock = await fixture(t);
  interceptToken(t, mock.idp, (url, init, transport) => {
    const body = new URLSearchParams(init.body);
    body.set('code_verifier', 'wrong-verifier-'.repeat(4));
    return transport(url, { ...init, body });
  });
  const result = await capture(['authorize', 'bad-verifier', ...mock.flags], { onListening: mock.follow });
  assert.equal(result.code, 1);
  assert.equal(result.envelope.error.code, 'RECONNECT');
  assert.equal(getCred('bad-verifier', 'oauth_access_token'), null);
});

test('refresh retains an omitted refresh token and reports invalid_grant as RECONNECT', async t => {
  const result = await authorize(t, 'refresh-test');
  assert.equal(result.code, 0);
  const old = getCred('refresh-test', 'oauth_refresh_token');
  interceptToken(t, result.mock.idp, async (url, init, transport) => {
    const response = await transport(url, init);
    const token = await response.json();
    delete token.refresh_token;
    return new Response(JSON.stringify(token), { status: response.status });
  });
  setCred('refresh-test', 'oauth_expires_at', new Date(0).toISOString());
  const refreshed = await capture(['refresh', 'refresh-test']);
  assert.equal(refreshed.code, 0);
  assert.equal(getCred('refresh-test', 'oauth_refresh_token'), old);
  assert.ok(Date.parse(getCred('refresh-test', 'oauth_expires_at')) > Date.now());
  assert.equal((await refresh('refresh-test')).hasRefreshToken, true);
  setCred('refresh-test', 'oauth_refresh_token', 'revoked-token');
  remember('revoked-token');
  const failed = await capture(['refresh', 'refresh-test']);
  assert.equal(failed.code, 1);
  assert.equal(failed.envelope.error.code, 'RECONNECT');
  assert.equal(getCred('refresh-test', 'oauth_refresh_token'), 'revoked-token');
});

test('manual redirect input, body client authentication, and form-encoded token response', async t => {
  const mock = await fixture(t, { formEncodedTokenResponse: true }, 'body');
  const stdin = new PassThrough();
  const result = await capture(['authorize', 'manual', ...mock.flags, '--manual', '--auth-style', 'body'], {
    stdin,
    async onListening(port, url) {
      mock.register(port);
      const response = await fetch(url, { redirect: 'manual' });
      stdin.end(response.headers.get('location') + '\n');
    },
  });
  assert.equal(result.code, 0);
  assert.ok(getCred('manual', 'oauth_access_token'));
  assert.equal(getCred('manual', 'oauth_auth_style'), 'body');
});

test('stored configuration and explicit overrides work with no-pkce', async t => {
  const mock = await fixture(t, { requirePkce: false });
  for (let i = 0; i < 10; i += 2) setCred('stored', 'oauth_' + mock.flags[i].slice(2).replaceAll('-', '_'), mock.flags[i + 1]);
  setCred('stored', 'oauth_client_id', 'stale-id');
  const result = await capture(['authorize', 'stored', '--client-id', 'mock-client', '--no-pkce', '--timeout', '5000'], { onListening: mock.follow });
  assert.equal(result.code, 0);
  assert.equal(getCred('stored', 'oauth_client_id'), 'mock-client');
  assert.equal(mock.idp.log.find(entry => entry.path === '/authorize').params.code_challenge, undefined);
});

test('timeouts close the callback listener and abort a stalled token exchange', async t => {
  const mock = await fixture(t);
  let port;
  const result = await capture(['authorize', 'timeout', ...mock.flags.slice(0, -2), '--timeout', '100'], { onListening(p) { port = p; } });
  assert.equal(result.code, 1);
  assert.equal(result.envelope.error.code, 'TIMEOUT');
  await assert.rejects(fetch(`http://127.0.0.1:${port}/callback`));
  let exchangeStarted = false;
  interceptToken(t, mock.idp, (url, init) => new Promise((resolve, reject) => {
    exchangeStarted = true;
    init.signal.addEventListener('abort', () => reject(init.signal.reason), { once: true });
  }));
  const failed = await capture(['authorize', 'stalled', ...mock.flags.slice(0, -2), '--timeout', '500', '--auto-follow'], { onListening: mock.register });
  assert.equal(exchangeStarted, true);
  assert.equal(failed.envelope.error.code, 'TIMEOUT');
});

test('one-time authorization code reuse is rejected by the shared IdP', async t => {
  const mock = await fixture(t);
  let exchange;
  interceptToken(t, mock.idp, (url, init, transport) => {
    exchange = { ...init, body: String(init.body), signal: undefined };
    return transport(url, init);
  });
  const result = await capture(['authorize', 'reuse', ...mock.flags], { onListening: mock.follow });
  assert.equal(result.code, 0);
  const response = await fetch(mock.idp.tokenUrl, exchange);
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, 'invalid_grant');
});

test('IdP rejects mismatched redirect_uri at authorization and token exchange', async t => {
  const mock = await fixture(t);
  const result = await capture(['authorize', 'redirect-auth', ...mock.flags, '--auto-follow'], {
    onListening(port) { mock.register(port === 65535 ? port - 1 : port + 1); },
  });
  assert.equal(result.envelope.error.code, 'OAUTH_ERROR');
  assert.equal(mock.idp.log.filter(entry => entry.path === '/token').length, 0);
  interceptToken(t, mock.idp, (url, init, transport) => {
    const body = new URLSearchParams(init.body);
    body.set('redirect_uri', 'http://127.0.0.1:1/callback');
    return transport(url, { ...init, body });
  });
  const tokenResult = await capture(['authorize', 'redirect-token', ...mock.flags], { onListening: mock.follow });
  assert.equal(tokenResult.envelope.error.code, 'RECONNECT');
});

for (const style of ['header', 'body']) {
  test(`${style}-only client rejects the other authentication style`, async t => {
    const result = await authorize(t, 'wrong-style-' + style, {}, ['--auth-style', style === 'header' ? 'body' : 'header'], style);
    assert.equal(result.code, 1);
    assert.equal(result.envelope.error.code, 'OAUTH_ERROR');
    assert.equal(getCred('wrong-style-' + style, 'oauth_access_token'), null);
  });
}

test('auto-follow completes PKCE, rotates refresh tokens, and accesses userinfo via http --auth', async t => {
  const mock = await fixture(t, { rotateRefreshTokens: true });
  const result = await capture(['authorize', 'auto-demo', ...mock.flags, '--auto-follow'], { onListening: mock.register });
  assert.equal(result.code, 0);
  assert.match(result.stderr, /Authorize URL:/);
  const old = getCred('auto-demo', 'oauth_refresh_token');
  assert.equal((await capture(['refresh', 'auto-demo'])).code, 0);
  const rotated = getCred('auto-demo', 'oauth_refresh_token');
  assert.ok(rotated && rotated !== old);
  setCred('auto-demo', 'oauth_expires_at', new Date(0).toISOString());
  const resource = await capture(['request', mock.idp.userinfoUrl, '--auth', 'auto-demo'], undefined, httpRun);
  assert.equal(resource.code, 0);
  assert.equal(resource.envelope.result.status, 200);
  assert.deepEqual(resource.envelope.result.bodyJson, { sub: 'mock-user-1', client_id: 'mock-client', scope: 'read write' });
  assert.notEqual(getCred('auto-demo', 'oauth_refresh_token'), rotated);
  const denied = await fetch(mock.idp.userinfoUrl);
  assert.equal(denied.status, 401);
  assert.ok(denied.headers.has('www-authenticate'));
  await denied.text();
});

test('usage and configuration errors are actionable without secret disclosure', async () => {
  for (const args of [[], ['bogus', 's'], ['status'], ['status', 's', '--manual'], ['authorize', 's', '--wat'], ['authorize', 's', '--timeout', '0'], ['authorize', 's', '--port', '65536'], ['authorize', 's', '--manual', '--auto-follow']]) {
    const result = await capture(args);
    assert.equal(result.code, 2);
    assert.equal(result.envelope.error.code, 'USAGE');
  }
  const missing = await capture(['authorize', 'unconfigured']);
  assert.equal(missing.code, 1);
  assert.equal(missing.envelope.error.code, 'MISSING_CONFIG');
  assert.match(missing.envelope.error.message, /cred set unconfigured oauth_client_id --value/);
});
