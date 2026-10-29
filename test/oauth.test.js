// run(args, { onListening(port, authorizeUrl), stdin }) is an internal test hook.
// The mock IdP follows the real loopback redirect; manual tests supply a stream.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { PassThrough } from 'node:stream';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run, refresh } from '../src/cmd-oauth.js';
import { getCred, setCred, closeDb } from '../src/creds.js';
import { schemaDocument, argvFromSchemaCall } from '../src/schema.js';

const directory = mkdtempSync(join(tmpdir(), 'lmconn-oauth-'));
const previousDb = process.env.LMCONN_DB;
process.env.LMCONN_DB = join(directory, 'creds.db');
after(() => {
  closeDb();
  if (previousDb === undefined) delete process.env.LMCONN_DB;
  else process.env.LMCONN_DB = previousDb;
  rmSync(directory, { recursive: true, force: true });
});

async function capture(args, hooks) {
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
  try { code = await run(args, hooks); }
  finally { process.stdout.write = write; process.stderr.write = errorWrite; }
  assert.equal(stdout.trim().split('\n').length, 1);
  for (const secret of ['mock-access-secret', 'mock-refresh-secret', 'mock-client-secret', 'mock-code-secret']) {
    assert.ok(!stdout.includes(secret), 'stdout must not contain secrets');
    assert.ok(!stderr.includes(secret), 'stderr must not contain secrets');
  }
  return { code, envelope: JSON.parse(stdout), stdout, stderr };
}

async function idp(t, mode = {}) {
  const requests = [];
  const grants = new Map();
  const failures = [];
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname === '/authorize') {
        assert.equal(url.searchParams.get('client_id'), 'mock-client');
        assert.equal(url.searchParams.get('response_type'), 'code');
        assert.ok(url.searchParams.get('state'));
        const redirect = new URL(url.searchParams.get('redirect_uri'));
        assert.equal(redirect.hostname, '127.0.0.1');
        assert.equal(redirect.pathname, '/callback');
        const challenge = url.searchParams.get('code_challenge');
        if (mode.noPkce) assert.equal(challenge, null);
        else {
          assert.match(challenge, /^[A-Za-z0-9_-]{43}$/);
          assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
        }
        grants.set('mock-code-secret', { challenge: mode.badVerifier ? 'wrong-challenge' : challenge, redirect: redirect.href });
        redirect.searchParams.set('code', 'mock-code-secret');
        redirect.searchParams.set('state', mode.badState ? 'wrong-state' : url.searchParams.get('state'));
        res.writeHead(302, { Location: redirect.href }).end();
      } else if (url.pathname === '/token') {
        assert.equal(req.method, 'POST');
        assert.equal(req.headers.accept, 'application/json');
        let text = '';
        for await (const chunk of req) text += chunk;
        const params = new URLSearchParams(text);
        requests.push(params);
        if (mode.body) {
          assert.equal(req.headers.authorization, undefined);
          assert.equal(params.get('client_id'), 'mock-client');
          assert.equal(params.get('client_secret'), 'mock-client-secret');
        } else {
          assert.equal(req.headers.authorization, 'Basic ' + Buffer.from('mock-client:mock-client-secret').toString('base64'));
          assert.equal(params.get('client_secret'), null);
        }
        if (mode.stall) return;
        let rejected = mode.invalidGrant;
        if (params.get('grant_type') === 'authorization_code') {
          const grant = grants.get(params.get('code'));
          assert.ok(grant);
          assert.equal(params.get('redirect_uri'), grant.redirect);
          if (mode.noPkce) assert.equal(params.get('code_verifier'), null);
          else {
            const verifier = params.get('code_verifier');
            assert.match(verifier, /^[A-Za-z0-9_-]{43}$/);
            rejected ||= createHash('sha256').update(verifier).digest('base64url') !== grant.challenge;
          }
        } else {
          assert.equal(params.get('grant_type'), 'refresh_token');
          assert.equal(params.get('refresh_token'), 'mock-refresh-secret');
        }
        if (rejected) {
          res.writeHead(400, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'invalid_grant', error_description: 'mock-code-secret mock-access-secret' }));
          return;
        }
        const token = { access_token: 'mock-access-secret', token_type: 'Bearer', expires_in: 3600, scope: 'read write' };
        if (!(mode.omitRefresh && params.get('grant_type') === 'refresh_token')) token.refresh_token = 'mock-refresh-secret';
        if (mode.form) res.end(new URLSearchParams(token).toString());
        else res.end(JSON.stringify(token));
      } else res.writeHead(404).end();
    } catch (err) {
      failures.push(err);
      res.writeHead(500).end('Mock validation failed');
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); });
    assert.deepEqual(failures, []);
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  return { requests, flags: ['--client-id', 'mock-client', '--client-secret', 'mock-client-secret', '--auth-url', base + '/authorize', '--token-url', base + '/token', '--scope', 'read write', '--port', '0', '--timeout', '3000'],
    async follow(port, authorizeUrl) {
      const response = await fetch(authorizeUrl);
      // Failure cases can close the socket once the error envelope is ready.
      await response.text();
    } };
}

async function authorize(t, service, mode = {}, extra = []) {
  const mock = await idp(t, mode);
  const result = await capture(['authorize', service, ...mock.flags, ...extra], { onListening: mock.follow });
  return { ...result, mock };
}

test('status before authorization and schema registration', async () => {
  const result = await capture(['status', 'absent', '--json']);
  assert.equal(result.code, 0);
  assert.deepEqual(result.envelope.result, { service: 'absent', authorized: false, expiresAt: null, expired: false, hasRefreshToken: false, scope: '', tokenUrl: null });
  const doc = await schemaDocument();
  for (const name of ['oauth_authorize', 'oauth_refresh', 'oauth_status']) assert.ok(doc.operations.some(op => op.name === name));
  assert.deepEqual(await argvFromSchemaCall(['oauth_status', '--input-json', '{"service":"absent"}']), ['oauth', 'status', 'absent']);
});

test('complete authorization validates PKCE, stores tokens/config, and emits only metadata', async t => {
  const start = Date.now();
  const result = await authorize(t, 'happy', {}, ['--auth-query', 'access_type=offline&prompt=consent&state=ignored']);
  assert.equal(result.code, 0);
  assert.equal(result.envelope.ok, true);
  const meta = result.envelope.result;
  assert.deepEqual(Object.keys(meta).sort(), ['expiresAt', 'hasRefreshToken', 'scope', 'service']);
  assert.equal(meta.service, 'happy');
  assert.equal(meta.hasRefreshToken, true);
  assert.equal(meta.scope, 'read write');
  assert.ok(Date.parse(meta.expiresAt) >= start + 3600000);
  assert.equal(getCred('happy', 'oauth_access_token'), 'mock-access-secret');
  assert.equal(getCred('happy', 'oauth_refresh_token'), 'mock-refresh-secret');
  assert.equal(getCred('happy', 'oauth_client_id'), 'mock-client');
  assert.equal(getCred('happy', 'oauth_token_type'), 'Bearer');
  assert.match(result.stderr, /access_type=offline/);
  const status = await capture(['status', 'happy']);
  assert.equal(status.envelope.result.authorized, true);
  assert.equal(status.envelope.result.expired, false);
  setCred('happy', 'oauth_expires_at', new Date(0).toISOString());
  assert.equal((await capture(['status', 'happy'])).envelope.result.expired, true);
});

test('state mismatch fails without token exchange', async t => {
  const result = await authorize(t, 'bad-state', { badState: true });
  assert.equal(result.code, 1);
  assert.equal(result.envelope.error.code, 'OAUTH_ERROR');
  assert.equal(result.mock.requests.length, 0);
  assert.equal(getCred('bad-state', 'oauth_access_token'), null);
});

test('mock rejects an incorrect PKCE verifier', async t => {
  const result = await authorize(t, 'bad-verifier', { badVerifier: true });
  assert.equal(result.code, 1);
  assert.equal(result.envelope.error.code, 'RECONNECT');
  assert.equal(getCred('bad-verifier', 'oauth_access_token'), null);
});

test('refresh retains an omitted refresh token and reports invalid_grant as RECONNECT', async t => {
  const mode = { omitRefresh: true };
  const result = await authorize(t, 'refresh-test', mode);
  assert.equal(result.code, 0);
  setCred('refresh-test', 'oauth_expires_at', new Date(0).toISOString());
  const refreshed = await capture(['refresh', 'refresh-test']);
  assert.equal(refreshed.code, 0);
  assert.equal(getCred('refresh-test', 'oauth_refresh_token'), 'mock-refresh-secret');
  assert.ok(Date.parse(getCred('refresh-test', 'oauth_expires_at')) > Date.now());
  assert.equal((await refresh('refresh-test')).hasRefreshToken, true);
  mode.invalidGrant = true;
  const failed = await capture(['refresh', 'refresh-test']);
  assert.equal(failed.code, 1);
  assert.equal(failed.envelope.error.code, 'RECONNECT');
  assert.equal(getCred('refresh-test', 'oauth_refresh_token'), 'mock-refresh-secret');
});

test('manual redirect input, body client authentication, and form-encoded token response', async t => {
  const mock = await idp(t, { body: true, form: true });
  const stdin = new PassThrough();
  const result = await capture(['authorize', 'manual', ...mock.flags, '--manual', '--auth-style', 'body'], {
    stdin,
    async onListening(port, url) {
      const response = await fetch(url, { redirect: 'manual' });
      stdin.end(response.headers.get('location') + '\n');
    },
  });
  assert.equal(result.code, 0);
  assert.equal(getCred('manual', 'oauth_access_token'), 'mock-access-secret');
  assert.equal(getCred('manual', 'oauth_auth_style'), 'body');
});

test('stored configuration and explicit overrides work with no-pkce', async t => {
  const mock = await idp(t, { noPkce: true });
  for (let i = 0; i < 10; i += 2) setCred('stored', 'oauth_' + mock.flags[i].slice(2).replaceAll('-', '_'), mock.flags[i + 1]);
  setCred('stored', 'oauth_client_id', 'stale-id');
  const result = await capture(['authorize', 'stored', '--client-id', 'mock-client', '--no-pkce', '--timeout', '3000'], { onListening: mock.follow });
  assert.equal(result.code, 0);
  assert.equal(getCred('stored', 'oauth_client_id'), 'mock-client');
});

test('timeouts close the callback listener and abort a stalled token exchange', async t => {
  const mock = await idp(t);
  let port;
  const result = await capture(['authorize', 'timeout', ...mock.flags.filter((x, i, a) => x !== '--timeout' && a[i - 1] !== '--timeout'), '--timeout', '30'], { onListening(p) { port = p; } });
  assert.equal(result.code, 1);
  assert.equal(result.envelope.error.code, 'TIMEOUT');
  await assert.rejects(fetch(`http://127.0.0.1:${port}/callback`));
  const stalled = await idp(t, { stall: true });
  const flags = stalled.flags.slice(0, -2);
  const failed = await capture(['authorize', 'stalled', ...flags, '--timeout', '150'], { onListening: stalled.follow });
  assert.equal(failed.envelope.error.code, 'TIMEOUT');
});

test('usage and configuration errors are actionable without secret disclosure', async () => {
  for (const args of [[], ['bogus', 's'], ['status'], ['status', 's', '--manual'], ['authorize', 's', '--wat'], ['authorize', 's', '--timeout', '0'], ['authorize', 's', '--port', '65536']]) {
    const result = await capture(args);
    assert.equal(result.code, 2);
    assert.equal(result.envelope.error.code, 'USAGE');
  }
  const missing = await capture(['authorize', 'unconfigured']);
  assert.equal(missing.code, 1);
  assert.equal(missing.envelope.error.code, 'MISSING_CONFIG');
  assert.match(missing.envelope.error.message, /cred set unconfigured oauth_client_id --value/);
});
