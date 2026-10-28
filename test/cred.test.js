import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { run } from '../src/cmd-cred.js';

const directory = mkdtempSync(join(tmpdir(), 'lmconn-cred-test-'));
const originalDb = process.env.LMCONN_DB;
process.env.LMCONN_DB = join(directory, 'creds.db');
after(() => {
  if (originalDb === undefined) delete process.env.LMCONN_DB;
  else process.env.LMCONN_DB = originalDb;
  rmSync(directory, { recursive: true, force: true });
});

async function capture(args, stdin) {
  const stdoutWrite = process.stdout.write;
  const stderrWrite = process.stderr.write;
  const stdinDescriptor = Object.getOwnPropertyDescriptor(process, 'stdin');
  let stdout = '';
  let stderr = '';
  process.stdout.write = function (chunk, ...args) {
    // Node's test runner also writes binary IPC frames to stdout.
    if (typeof chunk !== 'string') return stdoutWrite.call(this, chunk, ...args);
    stdout += chunk;
    return true;
  };
  process.stderr.write = (chunk) => { stderr += chunk; return true; };
  if (stdin !== undefined) Object.defineProperty(process, 'stdin', { configurable: true, value: stdin });
  let code;
  try {
    code = await run(args);
  } finally {
    process.stdout.write = stdoutWrite;
    process.stderr.write = stderrWrite;
    if (stdin !== undefined) Object.defineProperty(process, 'stdin', stdinDescriptor);
  }
  assert.equal(stdout.trim().split('\n').length, 1, 'exactly one envelope');
  return { code, envelope: JSON.parse(stdout), stdout, stderr };
}

test('set/list/get/delete round trip redacts values unless revealed', async () => {
  const secret = 'synthetic-credential-roundtrip';
  const set = await capture(['set', 'test-service', 'key', '--value', secret]);
  assert.equal(set.code, 0);
  assert.deepEqual(set.envelope, { ok: true, result: { service: 'test-service', field: 'key', stored: true } });
  assert.match(set.stderr, /argv.*visible/);
  assert.ok(!(set.stdout + set.stderr).includes(secret));
  const list = await capture(['list']);
  assert.equal(list.code, 0);
  assert.ok(!list.stdout.includes(secret));
  const row = list.envelope.result.find(row => row.service === 'test-service');
  assert.deepEqual(Object.keys(row).sort(), ['field', 'service', 'updated_at']);
  assert.ok(Number.isFinite(Date.parse(row.updated_at)));
  const get = await capture(['get', 'test-service', 'key']);
  assert.equal(get.code, 0);
  assert.deepEqual(get.envelope.result, { service: 'test-service', field: 'key', set: true });
  assert.ok(!get.stdout.includes(secret));
  const reveal = await capture(['get', 'test-service', 'key', '--reveal']);
  assert.equal(reveal.code, 0);
  assert.equal(reveal.envelope.result.value, secret);
  for (const deleted of [true, false]) {
    const result = await capture(['delete', 'test-service', 'key']);
    assert.equal(result.code, 0);
    assert.deepEqual(result.envelope.result, { deleted });
  }
  assert.equal((await capture(['get', 'test-service', 'key'])).envelope.result.set, false);
  const missing = await capture(['get', 'test-service', 'key', '--reveal']);
  assert.equal(missing.code, 1);
  assert.equal(missing.envelope.error.code, 'NOT_FOUND');
});

test('--env preserves values, including empty values', async () => {
  const name = 'LMCONN_TEST_CRED_SOURCE';
  const previous = process.env[name];
  try {
    for (const value of ['synthetic-env-value\n', '']) {
      process.env[name] = value;
      const set = await capture(['set', 'env-service', 'key', '--env', name]);
      assert.equal(set.code, 0);
      assert.ok(!set.stdout.includes('synthetic-env-value'));
      assert.equal(set.stderr, '');
      assert.equal((await capture(['get', 'env-service', 'key', '--reveal'])).envelope.result.value, value);
    }
    delete process.env[name];
    const missing = await capture(['set', 'env-service', 'key', '--env', name]);
    assert.equal(missing.code, 2);
    assert.equal(missing.envelope.error.code, 'USAGE');
  } finally {
    if (previous === undefined) delete process.env[name];
    else process.env[name] = previous;
  }
});

test('--stdin reads all bytes without trimming or corrupting split UTF-8', async () => {
  const value = '  synthetic-stdin-🔑\nsecond line\n';
  const bytes = Buffer.from(value);
  const stdin = Readable.from([...bytes].map(byte => Buffer.from([byte])));
  const set = await capture(['set', 'stdin-service', 'key', '--stdin'], stdin);
  assert.equal(set.code, 0);
  assert.ok(!set.stdout.includes('synthetic-stdin'));
  assert.equal(set.stderr, '');
  assert.equal((await capture(['get', 'stdin-service', 'key', '--reveal'])).envelope.result.value, value);
});

test('path returns the configured database path', async () => {
  const result = await capture(['path']);
  assert.equal(result.code, 0);
  assert.deepEqual(result.envelope.result, { path: process.env.LMCONN_DB });
});

test('invalid commands, operands, and sources return USAGE without echoing input', async () => {
  for (const args of [
    [], ['unknown'], ['list', 'extra'], ['path', 'extra'], ['get', 'service'],
    ['get', 'service', 'field', '--unknown'], ['get', 'service', 'field', '--reveal', '--reveal'],
    ['delete', 'service'], ['delete', 'service', 'field', 'extra'],
    ['set', 'service', 'field'], ['set', 'service', 'field', '--unknown'],
    ['set', 'service', 'field', '--value'], ['set', 'service', 'field', '--env'],
    ['set', 'service', 'field', '--value', '--stdin'],
    ['set', 'service', 'field', '--stdin', '--stdin'],
    ['set', 'service', 'field', '--value', 'synthetic-invalid-secret', '--stdin'],
    ['set', 'service', 'field', '--env', 'VAR', '--stdin'],
    ['set', 'service', 'field', '--value', 'synthetic-invalid-secret', '--env', 'VAR'],
  ]) {
    const result = await capture(args);
    assert.equal(result.code, 2);
    assert.equal(result.envelope.ok, false);
    assert.equal(result.envelope.error.code, 'USAGE');
    assert.ok(!(result.stdout + result.stderr).includes('synthetic-invalid-secret'));
  }
});

test('runtime errors return a sanitized failure envelope', async () => {
  const stdin = Readable.from((async function* () { throw new Error('synthetic-secret-in-error'); })());
  const result = await capture(['set', 'failed-service', 'key', '--stdin'], stdin);
  assert.equal(result.code, 1);
  assert.equal(result.envelope.ok, false);
  assert.ok(!(result.stdout + result.stderr).includes('synthetic-secret-in-error'));
});
