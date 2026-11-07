// Integration: lmconn's MCP client against the real lmmock MCP server mock
// (`lmmock stdio mcp`) over stdio, no network. Needs an lmmock with `stdio mcp`;
// set LMMOCK_BIN or put it on PATH. Skipped when the binary is absent.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { withMcp } from '../src/mcp.js';

const bin = process.env.LMMOCK_BIN || 'lmmock';
const scenario = fileURLToPath(new URL('./mocks/mcp-conversation.json', import.meta.url));
const probe = spawnSync(bin, ['stdio', '--schema'], { encoding: 'utf8' });
const skip = probe.error || probe.status !== 0 ? `lmmock with "stdio mcp" not available (${bin})` : false;
const mockArgs = alias => ['stdio', 'mcp', '--scenario', scenario, '--alias', alias];
const mock = alias => ({ command: bin, args: mockArgs(alias), timeoutMs: 10000 });

test('discovery: tools, resources and prompts of the mock server', { skip }, () => withMcp(mock('Tools'), async c => {
  assert.equal(c.serverInfo.name, 'lmmock');
  assert.deepEqual((await c.listTools()).map(t => t.name), ['fixture']);
  assert.equal((await c.readResource('fixture:///note'))[0].text, 'fixture note');
  assert.deepEqual((await c.listPrompts()).map(p => p.name), ['fixture']);
  assert.equal((await c.getPrompt('fixture')).messages[0].content.text, 'fixture prompt');
  await c.ping();
}));

test('multi-call session follows the script and surfaces a scripted tool error', { skip }, () => withMcp(mock('Tools'), async c => {
  const berlin = await c.callTool('fixture', { city: 'berlin' });
  assert.equal(berlin.text, 'Berlin: 12C, cloudy');
  assert.equal(berlin.isError, false);
  assert.deepEqual(berlin.logs.map(l => l.data), ['fixture called']);
  assert.equal((await c.callTool('fixture', { city: 'tokyo' })).text, 'Tokyo: 21C, clear');
  assert.equal((await c.callTool('fixture', { city: 'paris' })).text, 'Paris: 16C, rain');
  await assert.rejects(c.callTool('fixture', { city: 'oslo' }), e => e.code === 'SERVER_ERROR' && /no data for oslo/.test(e.message));
}));

test('unknown tool (unscripted, -32099) and out-of-script calls are rejected', { skip }, async () => {
  await withMcp(mock('Tools'), async c => {
    await assert.rejects(c.callTool('does-not-exist'), e => e.code === 'SERVER_ERROR' && e.rpcCode === -32099);
  });
  await withMcp(mock('Tools'), async c => {
    await assert.rejects(c.callTool('fixture', { city: 'madrid' }), e => ['SERVER_ERROR', 'SERVER_EXIT'].includes(e.code));
  });
  await withMcp(mock('Short'), async c => {
    assert.equal((await c.callTool('fixture')).text, 'only one');
    await assert.rejects(c.callTool('fixture'), e => ['SERVER_ERROR', 'SERVER_EXIT'].includes(e.code));
  });
});

test('lmconn mcp session CLI drives lmmock end to end', { skip }, () => {
  const r = spawnSync(process.execPath, [fileURLToPath(new URL('../bin/lmconn.js', import.meta.url)), 'mcp', 'session', '--command', bin,
    ...mockArgs('Tools').flatMap(a => ['--arg', a]),
    '--call', '{"name":"fixture","arguments":{"city":"berlin"}}', '--call', '{"name":"fixture","arguments":{"city":"tokyo"}}'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const env = JSON.parse(r.stdout);
  assert.deepEqual(env.result.results.map(x => x.text), ['Berlin: 12C, cloudy', 'Tokyo: 21C, clear']);
});
