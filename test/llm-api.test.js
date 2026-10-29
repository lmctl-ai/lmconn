import test from 'node:test';
import assert from 'node:assert/strict';
import { startMock } from '../scripts/lmmock.js';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { providers } from '../src/providers/index.js';
import { chatApi } from '../src/providers/api.js';
import { run } from '../src/cmd-llm.js';
import { closeDb } from '../src/creds.js';

 test('local OpenAI-compatible adapter and llm envelopes', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'lmconn-api-'));
  const oldDb = process.env.LMCONN_DB;
  const oldKey = process.env.LMCONN_TEST_API_KEY;
  process.env.LMCONN_DB = join(dir, 'creds.db');
  process.env.LMCONN_TEST_API_KEY = 'test-private-key-12345';
  const key = process.env.LMCONN_TEST_API_KEY;
  let mode = 'ok';
  let received;
  const server = await startMock('llm', {mode:'ok'});
  const callApi = async (...args) => {
    server.configure({mode});
    try {return await chatApi(...args);} finally {
      const raw = await server.inspect();
      received = {url:raw.url, authorization:raw.headers?.authorization, body:JSON.parse(raw.body || '{}')};
    }
  };
  providers.localtest = { kind: 'api', baseUrl: `${server.origin}/v1/`, keyEnv: 'LMCONN_TEST_API_KEY', defaultModel: 'test-model' };
  t.after(async () => {
    await server.close();
    delete providers.localtest;
    if (oldDb === undefined) delete process.env.LMCONN_DB; else process.env.LMCONN_DB = oldDb;
    if (oldKey === undefined) delete process.env.LMCONN_TEST_API_KEY; else process.env.LMCONN_TEST_API_KEY = oldKey;
    closeDb(join(dir, 'creds.db')); // Windows: open handle blocks rm
    await rm(dir, { recursive: true, force: true });
  });
  async function capture(args) {
    let output = '';
    const original = process.stdout.write;
    process.stdout.write = chunk => { output += chunk; return true; };
    try { server.configure({mode}); const exit = await run(args); const raw = await server.inspect(); received = {url:raw.url,authorization:raw.headers?.authorization,body:JSON.parse(raw.body || '{}')}; return {exit,envelope:JSON.parse(output)}; }
    finally { process.stdout.write = original; }
  }
  await t.test('request and response contract', async () => {
    const result = await callApi('localtest', { prompt: 'ping', system: 'be brief', model: 'override', maxTokens: 12 });
    assert.equal(received.url, '/v1/chat/completions');
    assert.equal(received.authorization, `Bearer ${key}`);
    assert.deepEqual(received.body, { model: 'override', max_tokens: 12, messages: [{ role: 'system', content: 'be brief' }, { role: 'user', content: 'ping' }] });
    assert.equal(result.text, 'pong');
    assert.equal(result.model, 'served-model');
    assert.deepEqual(result.usage, { prompt_tokens: 2, completion_tokens: 2, total_tokens: 4 });
    assert.equal(result.keySource, 'env:LMCONN_TEST_API_KEY');
    assert.ok(result.latencyMs >= 0);
  });
  await t.test('HTTP 401 mapping and redaction', async () => {
    mode = 'unauthorized';
    await assert.rejects(callApi('localtest', { prompt: 'ping' }), err => {
      assert.equal(err.code, 'HTTP_ERROR');
      assert.equal(err.status, 401);
      assert.match(err.message, /HTTP 401/);
      assert.ok(!err.message.includes(key));
      assert.ok(!err.message.includes('different-secret-token'));
      return true;
    });
    const result = await capture(['chat', 'localtest', '--prompt', 'ping']);
    assert.equal(result.exit, 1);
    assert.equal(result.envelope.error.code, 'HTTP_ERROR');
  });
  await t.test('deadline aborts a stalled response', async () => {
    mode = 'timeout';
    await assert.rejects(callApi('localtest', { prompt: 'ping', timeoutMs: 30 }), { code: 'TIMEOUT' });
  });
  await t.test('echoed key is never returned', async () => {
    mode = 'echo';
    assert.equal((await callApi('localtest', { prompt: 'ping' })).text, '[REDACTED]');
  });
  for (const [fault, code, status] of [['rate-limit','HTTP_ERROR',429],['server-error','HTTP_ERROR',503],['bad-json','API_ERROR'],['disconnect','API_ERROR']]) {
    await t.test(`scripted ${fault} is a sanitized failure`, async () => {
      mode = fault;
      await assert.rejects(callApi('localtest', {prompt:'ping'}), err => {
        assert.equal(err.code,code); if(status) assert.equal(err.status,status);
        assert.ok(!err.message.includes(key)); return true;
      });
    });
  }
  await t.test('command file input, provider sources, and usage', async () => {
    mode = 'ok';
    const file = join(dir, 'prompt.txt');
    await writeFile(file, 'file prompt');
    const result = await capture(['chat', 'localtest', '--prompt-file', file]);
    assert.equal(result.exit, 0);
    assert.equal(result.envelope.result.provider, 'localtest');
    assert.equal(result.envelope.result.model, 'served-model');
    assert.equal(received.body.messages[0].content, 'file prompt');
    const listed = await capture(['providers']);
    assert.equal(listed.envelope.result.find(p => p.name === 'localtest').key, 'env:LMCONN_TEST_API_KEY');
    assert.ok(!JSON.stringify(listed).includes(key));
    for (const args of [['chat', 'no-such-provider'], ['chat', 'toString'], ['chat', 'localtest', '--max-tokens', '0'], ['chat', 'localtest', '--prompt', 'x', '--stdin']]) {
      const failure = await capture(args);
      assert.equal(failure.exit, 2);
      assert.equal(failure.envelope.error.code, 'USAGE');
    }
  });
});
