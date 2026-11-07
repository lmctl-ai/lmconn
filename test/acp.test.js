import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { AcpClient, converse } from '../src/acp.js';

const agent = mode => ({ command: process.execPath, args: [fileURLToPath(new URL('./mocks/acp-fake-agent.mjs', import.meta.url)), mode], timeoutMs: 5000 });

test('multi-turn conversation keeps one session and streams chunks in order', async () => {
  const res = await converse({ ...agent('echo'), prompts: ['one', 'two', 'three'] });
  assert.equal(res.sessionId, 'fake-session');
  assert.deepEqual(res.turns.map(t => t.text), ['echo:1:one', 'echo:2:two', 'echo:3:three']);
  assert.deepEqual(res.turns[1].chunks, ['echo:2:', 'two']);
  assert.ok(res.turns.every(t => t.stopReason === 'end_turn'));
});

test('permission requests are cancelled by default and approved with autoApprove', async () => {
  let res = await converse({ ...agent('permission'), prompts: ['go'] });
  assert.equal(res.turns[0].text, 'outcome:{"outcome":"cancelled"}');
  res = await converse({ ...agent('permission'), prompts: ['go'], autoApprove: true });
  assert.equal(res.turns[0].text, 'outcome:{"outcome":"selected","optionId":"yes"}');
});

test('agent->client fs requests are refused with method-not-found', async () => {
  const res = await converse({ ...agent('fs'), prompts: ['go'] });
  assert.equal(res.turns[0].text, 'fs:-32601');
});

test('agent exit, garbage output, spawn failure and timeout map to typed errors', async () => {
  await assert.rejects(converse({ ...agent('exit'), prompts: ['x'] }), e => e.code === 'AGENT_EXIT');
  await assert.rejects(converse({ ...agent('garbage'), prompts: ['x'] }), e => e.code === 'PROTOCOL');
  await assert.rejects(converse({ command: '/nonexistent/acp-agent', prompts: ['x'] }), e => e.code === 'SPAWN');
  await assert.rejects(converse({ command: process.execPath, args: ['-e', 'setTimeout(()=>{},60000)'], prompts: ['x'], timeoutMs: 100 }), e => e.code === 'TIMEOUT');
});

test('prompt() requires a session and a string', async () => {
  const c = new AcpClient(agent('echo'));
  await c.start();
  try {
    await assert.rejects(c.prompt('x'), e => e.code === 'USAGE');
    await c.newSession();
    await assert.rejects(c.prompt(5), e => e.code === 'USAGE');
  } finally { await c.close(); }
});

test('cli: usage errors exit 2 with a single JSON envelope; success exits 0', () => {
  const cli = (...a) => spawnSync(process.execPath, [fileURLToPath(new URL('../bin/lmconn.js', import.meta.url)), 'acp', ...a], { encoding: 'utf8' });
  let r = cli('chat');
  assert.equal(r.status, 2);
  assert.equal(JSON.parse(r.stdout).error.code, 'USAGE');
  r = cli('chat', '--command', process.execPath, '--arg', agent('echo').args[0], '--arg', 'echo', '--prompt', 'a', '--prompt', 'b');
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const env = JSON.parse(r.stdout);
  assert.deepEqual(env.result.turns.map(t => t.text), ['echo:1:a', 'echo:2:b']);
});
