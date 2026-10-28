import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { providers } from '../src/providers/index.js';
import { chatCli } from '../src/providers/cli.js';
import { probe } from '../src/llm-probe.js';

async function fixture(t, mode = 'echo') {
  const dir = await mkdtemp(join(tmpdir(), 'lmconn-cli-'));
  const script = join(dir, 'fixture.cjs');
  await writeFile(script, `#!${process.execPath}\n
const mode = process.argv[2];
if (mode === 'fail') { process.stderr.write('fixture failure ' + 'x'.repeat(600)); process.exitCode = 7; }
else if (mode === 'sleep') { setTimeout(() => {}, 60000); }
else { if (process.cwd() !== '/tmp') process.exit(9); console.log(process.argv.at(-1)); }
`, { mode: 0o755 });
  const name = `fixture-${mode}`;
  providers[name] = { kind: 'cli', cmd: [script, mode], timeoutMs: 2000 };
  t.after(async () => { delete providers[name]; await rm(dir, { recursive: true, force: true }); });
  return name;
}

test('chatCli preserves prompt as one argument, prepends system, and trims stdout', async t => {
  const name = await fixture(t);
  const prompt = 'hello "quoted"; $(exit 42)\nsecond line';
  const result = await chatCli(name, { prompt, system: 'system text' });
  assert.equal(result.text, `system text\n\n${prompt}`);
  assert.ok(Number.isFinite(result.latencyMs) && result.latencyMs >= 0);
  assert.equal((await chatCli(name, { prompt: '  plain  ' })).text, 'plain');
});

test('chatCli maps nonzero exit and caps stderr excerpt', async t => {
  const name = await fixture(t, 'fail');
  await assert.rejects(chatCli(name, { prompt: 'hello' }), error => {
    assert.match(error.message, /exited with code 7: fixture failure/);
    assert.equal(error.message.split(': ').at(-1).length, 500);
    return true;
  });
});

test('chatCli terminates on timeout, including registry default', async t => {
  const name = await fixture(t, 'sleep');
  providers[name].timeoutMs = 50;
  await assert.rejects(chatCli(name, { prompt: 'hello' }), /timed out after 50ms/);
  await assert.rejects(chatCli(name, { prompt: 'hello', timeoutMs: 75 }), /timed out after 75ms/);
});

test('chatCli reports spawn errors', async t => {
  const name = await fixture(t);
  providers[name].cmd = ['/nonexistent/lmconn-fixture'];
  await assert.rejects(chatCli(name, { prompt: 'hello' }), /ENOENT/);
});

test('probe continues after failures and returns complete entries', async t => {
  const failure = await fixture(t, 'fail');
  const success = await fixture(t);
  const results = await probe(['missing-fixture', failure, success]);
  assert.deepEqual(results.map(entry => entry.ok), [false, false, true]);
  assert.match(results[0].error, /unknown provider/);
  assert.equal(results[0].kind, null);
  assert.match(results[1].error, /code 7/);
  assert.equal(results[2].reply, 'Reply with exactly: pong');
  assert.equal(results[2].error, null);
  assert.equal(results[2].kind, 'cli');
  for (const entry of results) assert.ok(entry.latencyMs >= 0);
});
