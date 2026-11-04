import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createMockDeviceIdP } from '../scripts/mock-device-idp.js';
import { closeDb, getCred } from '../src/creds.js';

const directory = mkdtempSync(join(tmpdir(), 'lmconn-oauth-device-'));
const previousDb = process.env.LMCONN_DB;
process.env.LMCONN_DB = join(directory, 'creds.db');
after(() => {
  closeDb();
  if (previousDb === undefined) delete process.env.LMCONN_DB;
  else process.env.LMCONN_DB = previousDb;
  rmSync(directory, { recursive: true, force: true });
});

async function capture(args) {
  const entry = fileURLToPath(new URL('../bin/lmconn.js', import.meta.url));
  const child = spawn(process.execPath, [entry, ...args], { env: process.env, stdio: ['ignore', 'pipe', 'pipe'] });
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

test('device authorization polls RFC 8628 status, stores tokens, and returns only safe metadata', async t => {
  const mock = await createMockDeviceIdP();
  t.after(() => mock.close());
  const result = await capture(['oauth', 'device', 'mock-device', '--client-id', 'mock-client', '--device-url', mock.deviceUrl,
    '--token-url', mock.tokenUrl, '--scope', 'repo read:user', '--owner', 'mock-owner', '--source', 'lmmock']);
  assert.equal(result.code, 0);
  assert.deepEqual(result.envelope.result, {
    service: 'mock-device', expiresAt: result.envelope.result.expiresAt, hasRefreshToken: true,
    scope: 'repo read:user',
  });
  assert.ok(Date.parse(result.envelope.result.expiresAt) > Date.now());
  assert.equal(getCred('mock-device', 'oauth_access_token'), 'synthetic-access-secret');
  assert.equal(getCred('mock-device', 'oauth_refresh_token'), 'synthetic-refresh-secret');
  assert.equal(getCred('mock-device', 'oauth_owner'), 'mock-owner');
  assert.equal(getCred('mock-device', 'oauth_source'), 'lmmock');
  assert.deepEqual(mock.state.deviceRequests, [{ client_id: 'mock-client', scope: 'repo read:user' }]);
  assert.equal(mock.state.polls.length, 2);
  assert.deepEqual(mock.state.polls[0], {
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: 'synthetic-device-code', client_id: 'mock-client',
  });
  assert.ok(result.stderr.includes('MOCK-CODE'));
  assert.ok(!result.stdout.includes('synthetic-access-secret'));
  assert.ok(!result.stderr.includes('synthetic-access-secret'));
  assert.ok(!result.stdout.includes('synthetic-refresh-secret'));
  assert.ok(!result.stderr.includes('synthetic-refresh-secret'));
});

test('device authorization denies missing provider user instructions without storing a credential', async t => {
  const mock = await createMockDeviceIdP({ missingInstructions: true });
  t.after(() => mock.close());
  const result = await capture(['oauth', 'device', 'missing-instructions', '--client-id', 'mock-client', '--device-url', mock.deviceUrl, '--token-url', mock.tokenUrl]);
  assert.equal(result.code, 1);
  assert.equal(result.envelope.error.code, 'OAUTH_ERROR');
  assert.equal(getCred('missing-instructions', 'oauth_access_token'), null);
});
