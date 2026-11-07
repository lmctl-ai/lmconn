import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { McpClient, withMcp } from '../src/mcp.js';

const script = fileURLToPath(new URL('./mocks/mcp-fake-server.mjs', import.meta.url));
const server = mode => ({ command: process.execPath, args: [script, mode], timeoutMs: 5000 });

test('lists tools/resources/prompts and runs several tool calls in one session', () => withMcp(server('basic'), async c => {
  assert.equal(c.serverInfo.name, 'fake');
  assert.deepEqual((await c.listTools()).map(t => t.name), ['echo', 'add']);
  assert.deepEqual((await c.listResources()).map(r => r.uri), ['fake:///r']);
  assert.equal((await c.readResource('fake:///r'))[0].text, 'resource body');
  assert.deepEqual((await c.listPrompts()).map(p => p.name), ['greet']);
  assert.equal((await c.getPrompt('greet', { who: 'mcp' })).messages[0].content.text, 'hello mcp');
  const first = await c.callTool('echo', { text: 'hi' });
  assert.equal(first.text, 'hi');
  assert.deepEqual(first.logs, [{ level: 'info', data: 'called echo' }]);
  assert.equal((await c.callTool('add', { a: 2, b: 3 })).text, '5');
  assert.deepEqual((await c.callTool('add', { a: 1, b: 1 })).logs, [{ level: 'info', data: 'called add' }], 'logs are per call');
  assert.equal((await c.callTool('nope')).isError, true);
  await c.ping();
}));

test('server requests: ping is answered, sampling is refused with -32601', () => withMcp(server('probing'), async c => {
  assert.equal((await c.callTool('echo', { text: 'x' })).text, 'x|ping:{}|sampling:-32601');
}));

test('server errors, exits, bad protocol versions and timeouts map to typed errors', async () => {
  await withMcp(server('basic'), async c => {
    await assert.rejects(c.readResource('fake:///missing'), e => e.code === 'SERVER_ERROR' && e.rpcCode === -32602);
    await assert.rejects(c.callTool(''), e => e.code === 'USAGE');
  });
  await assert.rejects(withMcp(server('exit'), c => c.listTools()), e => e.code === 'SERVER_EXIT');
  await assert.rejects(withMcp(server('oldproto'), c => c.listTools()), e => e.code === 'PROTOCOL');
  await assert.rejects(withMcp({ command: '/nonexistent/mcp-server' }, c => c.listTools()), e => e.code === 'SPAWN');
  await assert.rejects(withMcp({ command: process.execPath, args: ['-e', 'setTimeout(()=>{},60000)'], timeoutMs: 100 }, c => c.listTools()), e => e.code === 'TIMEOUT');
  assert.ok(new McpClient({ command: 'x' }));
});

const cli = (...a) => spawnSync(process.execPath, [fileURLToPath(new URL('../bin/lmconn.js', import.meta.url)), 'mcp', ...a], { encoding: 'utf8' });
const target = ['--command', process.execPath, '--arg', script, '--arg', 'basic'];

test('cli: tools, call and session emit one JSON envelope', () => {
  let r = cli('tools', ...target);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout).result.tools.map(t => t.name), ['echo', 'add']);
  r = cli('call', ...target, '--tool', 'add', '--arguments', '{"a":4,"b":5}');
  assert.equal(JSON.parse(r.stdout).result.results[0].text, '9');
  r = cli('session', ...target, '--call', '{"name":"echo","arguments":{"text":"a"}}', '--call', '{"name":"add","arguments":{"a":1,"b":2}}');
  assert.deepEqual(JSON.parse(r.stdout).result.results.map(x => x.text), ['a', '3']);
  r = cli('read', ...target, '--uri', 'fake:///r');
  assert.equal(JSON.parse(r.stdout).result.contents[0].text, 'resource body');
});

test('cli: usage errors exit 2, runtime errors exit 1', () => {
  for (const args of [[], ['bogus'], ['tools'], ['call', ...target], ['call', ...target, '--tool', 't', '--arguments', '[1]'], ['session', ...target], ['tools', ...target, '--timeout-ms', '0']]) {
    const r = cli(...args);
    assert.equal(r.status, 2, JSON.stringify(args));
    assert.equal(JSON.parse(r.stdout).error.code, 'USAGE');
  }
  const r = cli('tools', '--command', '/nonexistent/mcp-server');
  assert.equal(r.status, 1);
  assert.equal(JSON.parse(r.stdout).error.code, 'SPAWN');
});
