import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createMockIdP } from '../scripts/mock-idp.js';
import { run } from '../src/cmd-oauth.js';
import { closeDb, getCred, setCred } from '../src/creds.js';

const directory = mkdtempSync(join(tmpdir(), 'lmconn-adversarial-'));
const previousDb = process.env.LMCONN_DB;
process.env.LMCONN_DB = join(directory, 'creds.db');
after(() => {
  closeDb();
  if (previousDb === undefined) delete process.env.LMCONN_DB;
  else process.env.LMCONN_DB = previousDb;
  rmSync(directory, { recursive: true, force: true });
});

const clientSecret = 'adversarial-client-secret';
async function capture(args, hooks, secrets) {
  const originalOut = process.stdout.write;
  const originalErr = process.stderr.write;
  let stdout = '', stderr = '', code;
  process.stdout.write = function (chunk, ...rest) {
    if (typeof chunk !== 'string') return originalOut.call(this, chunk, ...rest);
    stdout += chunk;
    return true;
  };
  process.stderr.write = chunk => { stderr += chunk; return true; };
  try { code = await run(args, hooks); }
  finally { process.stdout.write = originalOut; process.stderr.write = originalErr; }
  assert.equal(stdout.trim().split('\n').length, 1, 'exactly one envelope');
  for (const secret of secrets) {
    assert.ok(!stdout.includes(secret), 'stdout must not disclose credentials');
    assert.ok(!stderr.includes(secret), 'stderr must not disclose credentials');
  }
  return { code, envelope: JSON.parse(stdout) };
}

async function scenario(t, service, { misbehave, failToken = false, scope = 'read' } = {}) {
  const idp = await createMockIdP({ port: 0, requirePkce: true, misbehave: failToken ? 'server-error' : misbehave });
  t.after(() => idp.close());
  const secrets = [clientSecret, Buffer.from(`adversarial-client:${clientSecret}`).toString('base64')];
  const args = ['authorize', service, '--client-id', 'adversarial-client', '--client-secret', clientSecret,
    '--auth-url', idp.authUrl, '--token-url', idp.tokenUrl,
    '--scope', scope, '--port', '0', '--timeout', '5000'];
  const result = await capture(args, {
    async onListening(port, url) {
      idp.registerClient({ clientId: 'adversarial-client', clientSecret,
        redirectUris: [`http://127.0.0.1:${port}/callback`], authStyle: 'header' });
      const response = await fetch(url, { redirect: 'manual' });
      const redirect = response.headers.get('location');
      assert.equal(response.status, 302);
      secrets.push(new URL(redirect).searchParams.get('code'));
      await (await fetch(redirect)).text();
    },
  }, secrets);
  const status = await capture(['status', service], undefined, secrets);
  const log = JSON.stringify(idp.log);
  for (const secret of secrets) assert.ok(!log.includes(secret), 'IdP logs must redact secrets');
  return { ...result, status: status.envelope.result, idp };
}

for (const misbehave of ['bad-state', 'bad-json']) {
  test(`${misbehave} returns OAUTH_ERROR without storing tokens or leaking secrets`, async t => {
    const result = await scenario(t, misbehave, { misbehave });
    assert.equal(result.code, 1);
    assert.equal(result.envelope.ok, false);
    assert.equal(result.envelope.error.code, 'OAUTH_ERROR');
    assert.equal(result.status.authorized, false);
    assert.equal(getCred(misbehave, 'oauth_access_token'), null);
    if (misbehave === 'bad-state') assert.equal(result.idp.log.filter(r => r.path === '/token').length, 0);
  });
}

test('numeric string expires_in is accepted and gives a finite future expiry', async t => {
  const start = Date.now();
  const result = await scenario(t, 'string-expires', { misbehave: 'string-expires' });
  assert.equal(result.code, 0);
  assert.equal(result.envelope.ok, true);
  assert.ok(Date.parse(result.status.expiresAt) >= start + 3600000);
  assert.ok(Date.parse(result.status.expiresAt) <= Date.now() + 3600000);
  assert.equal(result.status.expired, false);
});

test('omitted expires_in clears stale expiry and status reports null', async t => {
  setCred('missing-expiry', 'oauth_expires_at', new Date(0).toISOString());
  const result = await scenario(t, 'missing-expiry', { misbehave:'missing-expiry' });
  assert.equal(result.code, 0);
  assert.equal(result.envelope.result.expiresAt, null);
  assert.equal(result.status.expiresAt, null);
  assert.equal(result.status.expired, false);
  assert.equal(result.status.authorized, true);
});

test('unknown token response fields are tolerated without appearing in metadata', async t => {
  const result = await scenario(t, 'extra-fields', { misbehave:'extra-fields' });
  assert.equal(result.code, 0);
  assert.equal(result.status.authorized, true);
  assert.deepEqual(Object.keys(result.envelope.result).sort(), ['expiresAt', 'hasRefreshToken', 'scope', 'service']);
});

test('HTTP 500 from token endpoint becomes sanitized OAUTH_ERROR', async t => {
  const result = await scenario(t, 'server-error', { failToken: true });
  assert.equal(result.code, 1);
  assert.equal(result.envelope.ok, false);
  assert.equal(result.envelope.error.code, 'OAUTH_ERROR');
  assert.equal(result.status.authorized, false);
});

test('empty scope is accepted and preserved in authorization and status', async t => {
  const result = await scenario(t, 'empty-scope', { scope: '' });
  assert.equal(result.code, 0);
  assert.equal(result.envelope.result.scope, '');
  assert.equal(result.status.scope, '');
  assert.equal(result.status.authorized, true);
});
