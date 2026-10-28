import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { schemaDocument, argvFromSchemaCall, normalizeOp, opName, camelCase, kebabCase, GLOBALS } from '../src/schema.js';

const OP_NAME = /^[a-z][a-z0-9_]*$/;
const PARAM_NAME = /^[A-Za-z_]\w*$/;
const PARAM_KEYS = new Set(['name', 'type', 'occurs', 'default', 'enum', 'positional', 'items', 'description', 'aliases', 'cliOnly', 'docOnly', 'derived']);

function assertStructure(doc) {
  assert.equal(doc.schema, 'cli.schema.v1');
  assert.equal(doc.tool, 'lmconn');
  assert.match(doc.version, /^\d+\.\d+\.\d+/);
  assert.deepEqual(doc.policy, { dryrun: false, readonly: false });
  assert.deepEqual(doc.inputs, ['flags', 'json']);
  assert.ok(Array.isArray(doc.operations));
  const names = doc.operations.map((o) => o.name);
  assert.equal(new Set(names).size, names.length, 'operation names are unique');
  for (const op of doc.operations) {
    assert.match(op.name, OP_NAME, op.name);
    assert.ok(['read', 'write', 'dynamic'].includes(op.access), `${op.name} access`);
    assert.equal(typeof op.description, 'string');
    assert.ok(Array.isArray(op.params), `${op.name} params`);
    const pnames = op.params.map((p) => p.name);
    assert.equal(new Set(pnames).size, pnames.length, `${op.name} param names unique`);
    for (const p of op.params) {
      assert.match(p.name, PARAM_NAME, `${op.name}.${p.name}`);
      assert.ok(['string', 'number', 'boolean', 'object', 'array', 'json'].includes(p.type), `${op.name}.${p.name} type ${p.type}`);
      if (p.occurs !== undefined) assert.ok(['1', '?', '+', '*'].includes(p.occurs));
      for (const key of Object.keys(p)) assert.ok(PARAM_KEYS.has(key), `${op.name}.${p.name} has unknown key ${key}`);
      assert.notEqual(p.name, 'dryrun');
      assert.ok(!['readonly', 'confirm'].includes(p.name), 'runner globals are not params');
    }
  }
  assert.ok(Array.isArray(doc.globals));
  assert.ok(!doc.globals.some((g) => g.name === 'input-graphql'));
  assert.deepEqual(doc.globals.map((g) => g.name), ['readonly', 'json', 'help', 'input-json', 'input-file']);
}

test('the real document validates structurally and contains this wave\'s operations', async () => {
  const doc = await schemaDocument();
  assertStructure(doc);
  const names = doc.operations.map((o) => o.name);
  for (const n of ['http_request', 'github_user', 'github_repos']) assert.ok(names.includes(n), n);
  assert.ok(doc.globals === GLOBALS);
});

test('missing or broken modules are skipped without breaking the document', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'lmconn-schema-test-'));
  try {
    writeFileSync(join(dir, 'cmd-good.js'), 'export const ops = [{ name: "good.thing", access: "read", description: "x", params: [{ name: "some-flag", type: "string", occurs: "?" }] }];\n');
    writeFileSync(join(dir, 'cmd-broken.js'), 'this is not javascript (\n');
    writeFileSync(join(dir, 'cmd-noops.js'), 'export async function run() { return 0; }\n');
    const warnings = [];
    const options = { areas: ['missing', 'broken', 'noops', 'good'], resolve: (a) => `file://${join(dir, `cmd-${a}.js`)}`, warn: (m) => warnings.push(m) };
    const doc = await schemaDocument(options);
    assertStructure(doc);
    assert.deepEqual(doc.operations.map((o) => o.name), ['good_thing']);
    assert.deepEqual(doc.operations[0].params, [{ name: 'someFlag', type: 'string', occurs: '?' }]);
    assert.equal(warnings.length, 1, 'only the broken module warns');
    assert.match(warnings[0], /broken/);
    const argv = await argvFromSchemaCall(['good_thing', '--input-json', '{"op":"good_thing","params":{"someFlag":"v"}}'], options);
    assert.deepEqual(argv, ['good', 'thing', '--some-flag', 'v']);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('an empty module list still yields a valid document', async () => {
  const doc = await schemaDocument({ areas: [] });
  assertStructure(doc);
  assert.deepEqual(doc.operations, []);
});

test('name normalisation follows the lmts rules', () => {
  assert.equal(opName('cred', 'cred.set'), 'cred_set');
  assert.equal(opName('llm', 'llm chat'), 'llm_chat');
  assert.equal(opName('http', 'http_request'), 'http_request');
  assert.equal(opName('github', 'Repos'), 'github_repos');
  assert.equal(camelCase('prompt-file'), 'promptFile');
  assert.equal(kebabCase('dataFile'), '--data-file'.slice(2));
  const { op, cli } = normalizeOp('llm', { name: 'llm chat', access: 'write', params: [
    { name: 'provider', type: 'string', positional: true }, { name: 'max-tokens', type: 'number', occurs: '?', default: 256, extraneous: 1 }] });
  assert.deepEqual(op.params, [{ name: 'provider', type: 'string', positional: true }, { name: 'maxTokens', type: 'number', occurs: '?', default: 256 }]);
  assert.equal(cli.sub, 'chat');
  assert.deepEqual(cli.params.map((p) => p.flag), ['--provider', '--max-tokens']);
});

test('argvFromSchemaCall maps params to CLI argv', async () => {
  const doc = JSON.stringify({ op: 'http_request', params: { url: 'http://h/p', method: 'POST', header: ['A: 1', 'B: 2'], data: '{"x":1}', timeout: 5 } });
  assert.deepEqual(await argvFromSchemaCall(['http_request', '--input-json', doc]),
    ['http', 'request', 'http://h/p', '--method', 'POST', '--header', 'A: 1', '--header', 'B: 2', '--data', '{"x":1}', '--timeout', '5']);
  assert.deepEqual(await argvFromSchemaCall(['github_repos', '--input-json', '{"org":"lmctl-ai","limit":5}']), ['github', 'repos', 'lmctl-ai', '--limit', '5']);
  assert.deepEqual(await argvFromSchemaCall(['github_user', '--input-json', '{}', '--readonly']), ['github', 'user']);
  const dir = mkdtempSync(join(tmpdir(), 'lmconn-schema-file-'));
  try {
    writeFileSync(join(dir, 'in.json'), '{"op":"github_repos","params":{"org":"x"}}');
    assert.deepEqual(await argvFromSchemaCall(['github_repos', '--input-file', join(dir, 'in.json')]), ['github', 'repos', 'x']);
  } finally { rmSync(dir, { recursive: true, force: true }); }
  for (const argv of [['nope_op', '--input-json', '{}'], ['http_request', '--input-json', '{}'], ['http_request', '--input-json', 'not json'],
    ['http_request', '--input-json', '{"op":"github_user","params":{}}'], ['github_repos', '--input-json', '{"org":"x","bogus":1}'], ['github_user']]) {
    await assert.rejects(argvFromSchemaCall(argv), (e) => e.code === 'USAGE', JSON.stringify(argv));
  }
  await assert.rejects(argvFromSchemaCall(['http_request', '--input-json', '{"url":"http://x"}', '--readonly']), (e) => e.code === 'READONLY');
});
