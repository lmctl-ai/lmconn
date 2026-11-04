import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { closeDb, getCred, setCred } from '../src/creds.js';

const directory = mkdtempSync(join(tmpdir(), 'lmconn-oauth-store-'));
const previousDb = process.env.LMCONN_DB;
process.env.LMCONN_DB = join(directory, 'creds.db');
const cli = fileURLToPath(new URL('../bin/lmconn.js', import.meta.url));
const access = 'synthetic-store-access';
const refresh = 'synthetic-store-refresh';
after(() => {
  closeDb();
  if (previousDb === undefined) delete process.env.LMCONN_DB;
  else process.env.LMCONN_DB = previousDb;
  rmSync(directory, { recursive: true, force: true });
});
function invoke(args, input) {
  const result = spawnSync(process.execPath, [cli, ...args], { env: process.env, input, encoding: 'utf8' });
  return { code: result.status, stdout: result.stdout, stderr: result.stderr, envelope: JSON.parse(result.stdout) };
}
async function invokeAsync(args) {
  const child = spawn(process.execPath, [cli, ...args], { env: process.env, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', chunk => { stdout += chunk; });
  child.stderr.setEncoding('utf8').on('data', chunk => { stderr += chunk; });
  const code = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', resolve);
  });
  return { code, stdout, stderr, envelope: JSON.parse(stdout) };
}

test('oauth-store atomically accepts stdin credentials, returns a handle, and lists metadata only', () => {
  const stored = invoke(['cred', 'oauth-store', 'mock-owner/github', '--stdin'], JSON.stringify({
    kind: 'oauth2', accessToken: access, refreshToken: refresh, scopes: ['repo', 'read:user'],
    expiresAt: '2030-01-01T00:00:00.000Z', owner: 'mock-owner', source: 'lmauth',
  }));
  assert.equal(stored.code, 0);
  assert.deepEqual(stored.envelope.result, { provider: 'mock-owner/github', handle: 'mock-owner/github', kind: 'oauth2', stored: true });
  assert.ok(!stored.stdout.includes(access));
  assert.ok(!stored.stdout.includes(refresh));
  assert.equal(getCred('mock-owner/github', 'oauth_access_token'), access);
  assert.equal(getCred('mock-owner/github', 'oauth_refresh_token'), refresh);
  assert.equal(getCred('mock-owner/github', 'oauth_scope'), 'repo read:user');
  assert.equal(getCred('mock-owner/github', 'oauth_owner'), 'mock-owner');
  assert.equal(getCred('mock-owner/github', 'oauth_source'), 'lmauth');
  const listing = invoke(['oauth', 'list']);
  assert.equal(listing.code, 0);
  assert.deepEqual(listing.envelope.result, [{
    service: 'mock-owner/github', provider: 'mock-owner/github', handle: 'mock-owner/github', kind: 'oauth2', owner: 'mock-owner',
    source: 'lmauth', scopes: 'repo read:user', expiresAt: '2030-01-01T00:00:00.000Z', hasRefreshToken: true,
  }]);
  assert.ok(!listing.stdout.includes(access));
  assert.ok(!listing.stdout.includes(refresh));
});

test('the service handle supplies a token only to lmconn HTTP auth and never in its result', async t => {
  const saved = invoke(['cred', 'oauth-store', 'handle-test', '--stdin'], JSON.stringify({
    kind: 'oauth2', accessToken: 'synthetic-handle-access', scopes: ['read'],
    owner: 'mock-owner', source: 'lmauth',
  }));
  assert.equal(saved.code, 0);
  let authorization;
  const server = createServer((request, response) => {
    authorization = request.headers.authorization;
    response.setHeader('Content-Type', 'application/json');
    response.end('{"ok":true}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const result = await invokeAsync(['http', 'request', `http://127.0.0.1:${server.address().port}/resource`, '--auth', 'handle-test']);
  assert.equal(result.code, 0);
  assert.equal(result.envelope.result.bodyJson.ok, true);
  assert.equal(authorization, 'Bearer synthetic-handle-access');
  assert.ok(!result.stdout.includes('synthetic-handle-access'));
});

test('oauth-store rejects invalid input without replacing an existing token or echoing submitted secrets', () => {
  setCred('atomic', 'oauth_access_token', 'synthetic-existing-access');
  const invalid = invoke(['cred', 'oauth-store', 'atomic', '--stdin'], JSON.stringify({
    kind: 'oauth2', accessToken: 'synthetic-invalid-access', scopes: ['read'], expiresAt: 'not-a-date', owner: 'owner', source: 'test',
  }));
  assert.equal(invalid.code, 1);
  assert.equal(invalid.envelope.error.code, 'CREDENTIAL_INPUT');
  assert.ok(!invalid.stdout.includes('synthetic-invalid-access'));
  assert.equal(getCred('atomic', 'oauth_access_token'), 'synthetic-existing-access');
});
