import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

async function runExample(name) {
  const path = fileURLToPath(new URL(`../examples/${name}`, import.meta.url));
  const child = spawn(process.execPath, [path], { env: process.env, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', chunk => { stdout += chunk; });
  child.stderr.setEncoding('utf8').on('data', chunk => { stderr += chunk; });
  const code = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(code, 0, `${name} exited unsuccessfully`);
  assert.ok(!stdout.includes('synthetic-access-secret'));
  assert.ok(!stdout.includes('synthetic-refresh-secret'));
  assert.ok(!stdout.includes('synthetic-client-secret'));
  assert.ok(!stderr.includes('synthetic-access-secret'));
  assert.ok(!stderr.includes('synthetic-refresh-secret'));
  assert.ok(!stderr.includes('synthetic-client-secret'));
}

test('device-code, PKCE and refresh-rotation examples run against local mock providers', async () => {
  await runExample('oauth-device.mjs');
  await runExample('oauth-pkce.mjs');
  await runExample('oauth-refresh-rotation.mjs');
});
