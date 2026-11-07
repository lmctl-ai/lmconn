// Integration: lmconn's ACP client against the real lmmock ACP server mock
// (`lmmock stdio acp`), over a scripted multi-turn conversation.
// Needs an lmmock with `stdio acp`; set LMMOCK_BIN, or have it on PATH.
// Skipped (not failed) when the binary is absent or predates `stdio acp`.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { converse } from '../src/acp.js';

const bin = process.env.LMMOCK_BIN || 'lmmock';
const scenario = fileURLToPath(new URL('./mocks/acp-conversation.json', import.meta.url));
const probe = spawnSync(bin, ['stdio', '--schema'], { encoding: 'utf8' });
const skip = probe.error || probe.status !== 0 ? `lmmock with "stdio acp" not available (${bin})` : false;
const mock = alias => ({ command: bin, args: ['stdio', 'acp', '--scenario', scenario, '--alias', alias], timeoutMs: 10000 });

test('three-turn conversation against lmmock stdio acp', { skip }, async () => {
  const res = await converse({ ...mock('Chat'), prompts: ['Hello agent', 'What is the weather?', 'ok, bye'] });
  assert.equal(res.sessionId, 'acp-conversation-1');
  assert.deepEqual(res.turns.map(t => t.text), [
    'Hi there! I am the mock ACP agent.',
    'It is sunny in the fixture world.',
    'Goodbye!',
  ]);
  assert.deepEqual(res.turns[0].chunks, ['Hi there! ', 'I am the mock ACP agent.']);
  assert.deepEqual(res.turns[2].chunks, ['Goodbye', '!']);
  assert.ok(res.turns.every(t => t.stopReason === 'end_turn'));
});

test('scripted stopReason is surfaced', { skip }, async () => {
  const res = await converse({ ...mock('Truncated'), prompts: ['anything'] });
  assert.equal(res.turns[0].text, 'partial answer');
  assert.equal(res.turns[0].stopReason, 'max_tokens');
});

test('a prompt that breaks the script, a scripted error and an exhausted script all fail', { skip }, async () => {
  await assert.rejects(converse({ ...mock('Chat'), prompts: ['not what the script expects'] }), e => ['AGENT_EXIT', 'AGENT_ERROR'].includes(e.code));
  await assert.rejects(converse({ ...mock('Failing'), prompts: ['one', 'two'] }), e => e.code === 'AGENT_ERROR' && /scripted agent failure/.test(e.message));
  await assert.rejects(converse({ ...mock('Chat'), prompts: ['Hello', 'weather', 'bye', 'one too many'] }), e => ['AGENT_EXIT', 'AGENT_ERROR'].includes(e.code));
});

test('lmconn acp chat CLI drives lmmock end to end', { skip }, () => {
  const r = spawnSync(process.execPath, [fileURLToPath(new URL('../bin/lmconn.js', import.meta.url)), 'acp', 'chat',
    '--command', bin, ...['stdio', 'acp', '--scenario', scenario, '--alias', 'Chat'].flatMap(a => ['--arg', a]),
    '--prompt', 'Hello', '--prompt', 'weather', '--prompt', 'bye'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const env = JSON.parse(r.stdout);
  assert.equal(env.ok, true);
  assert.equal(env.result.turns.length, 3);
  assert.equal(env.result.turns[1].text, 'It is sunny in the fixture world.');
});
