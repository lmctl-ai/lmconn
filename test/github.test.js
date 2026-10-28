import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run, resolveToken, ops } from '../src/cmd-github.js';
import { setCred, deleteCred, closeDb } from '../src/creds.js';

const directory = mkdtempSync(join(tmpdir(), 'lmconn-github-test-'));
const originalDb = process.env.LMCONN_DB;
const originalEnv = { GITHUB_TOKEN: process.env.GITHUB_TOKEN, GH_TOKEN: process.env.GH_TOKEN };
process.env.LMCONN_DB = join(directory, 'creds.db');
delete process.env.GITHUB_TOKEN; delete process.env.GH_TOKEN;
after(() => {
  if (originalDb === undefined) delete process.env.LMCONN_DB; else process.env.LMCONN_DB = originalDb;
  for (const [k, v] of Object.entries(originalEnv)) if (v !== undefined) process.env[k] = v;
  closeDb(join(directory, 'creds.db')); // Windows: open handle blocks rm
  rmSync(directory, { recursive: true, force: true });
});

// A fetch stub: routes is { 'GET /path?query': { status, body, headers } }. Records requests.
function fakeFetch(routes) {
  const calls = [];
  const fetch = async (url, init = {}) => {
    const u = new URL(url);
    calls.push({ path: u.pathname + u.search, headers: init.headers || {} });
    const route = routes[u.pathname + u.search] || routes[u.pathname] || { status: 404, body: { message: 'Not Found' } };
    return new Response(JSON.stringify(route.body), { status: route.status ?? 200,
      headers: { 'content-type': 'application/json', ...(route.headers || {}) } });
  };
  return { fetch, calls };
}
const noGh = () => { throw new Error('gh not available in tests'); };
const fakeGh = (cmd, args) => { assert.deepEqual([cmd, ...args], ['gh', 'auth', 'token']); return 'gho_from_gh\n'; };

async function capture(args, deps) {
  const stdoutWrite = process.stdout.write;
  const stderrWrite = process.stderr.write;
  let stdout = ''; let stderr = '';
  process.stdout.write = function (chunk, ...rest) {
    if (typeof chunk !== 'string') return stdoutWrite.call(this, chunk, ...rest);
    stdout += chunk; return true;
  };
  process.stderr.write = (chunk) => { stderr += chunk; return true; };
  try {
    const code = await run(args, deps);
    return { code, stdout, stderr, envelope: JSON.parse(stdout) };
  } finally {
    process.stdout.write = stdoutWrite;
    process.stderr.write = stderrWrite;
  }
}

test('repos returns count and names, anonymous when no token exists', async () => {
  const { fetch, calls } = fakeFetch({ '/orgs/acme/repos?per_page=30&sort=full_name': { status: 200, body: [{ name: 'a' }, { name: 'b' }] } });
  const r = await capture(['repos', 'acme'], { fetch, exec: noGh });
  assert.equal(r.code, 0);
  assert.deepEqual(r.envelope, { ok: true, result: { org: 'acme', count: 2, names: ['a', 'b'], auth: 'anonymous' } });
  assert.equal(calls[0].headers.authorization, undefined);
});

test('repos follows Link pagination up to --limit and falls back to the user endpoint on 404', async () => {
  const page1 = { status: 200, body: [{ name: 'r1' }, { name: 'r2' }], headers: { link: '<https://api.github.com/users/mike/repos?per_page=2&sort=full_name&page=2>; rel="next"' } };
  const page2 = { status: 200, body: [{ name: 'r3' }, { name: 'r4' }] };
  const { fetch, calls } = fakeFetch({
    '/users/mike/repos?per_page=3&sort=full_name': { ...page1, body: page1.body },
    '/users/mike/repos?per_page=2&sort=full_name&page=2': page2,
  });
  const r = await capture(['repos', 'mike', '--limit', '3'], { fetch, exec: noGh });
  assert.equal(r.code, 0, r.stdout);
  assert.deepEqual(r.envelope.result.names, ['r1', 'r2', 'r3']);
  assert.equal(r.envelope.result.count, 3);
  assert.equal(calls[0].path, '/orgs/mike/repos?per_page=3&sort=full_name');
  assert.equal(calls.length, 3);
});

test('token resolution: store, then env, then gh, then anonymous; token is sent but never printed', async () => {
  assert.equal(resolveToken(noGh).source, 'anonymous');
  assert.equal(resolveToken(fakeGh).source, 'gh');
  process.env.GH_TOKEN = 'ghp_env';
  assert.deepEqual(resolveToken(fakeGh), { token: 'ghp_env', source: 'env:GH_TOKEN' });
  setCred('github', 'api_key', 'ghp_store');
  assert.deepEqual(resolveToken(fakeGh), { token: 'ghp_store', source: 'store' });
  const { fetch, calls } = fakeFetch({ '/user': { status: 200, body: { login: 'octo', name: 'Octo', id: 7, public_repos: 3 } } });
  const r = await capture(['user'], { fetch, exec: noGh });
  assert.equal(r.code, 0);
  assert.deepEqual(r.envelope.result, { login: 'octo', name: 'Octo', id: 7, publicRepos: 3, auth: 'store' });
  assert.equal(calls[0].headers.authorization, 'Bearer ghp_store');
  assert.ok(!r.stdout.includes('ghp_store') && !r.stderr.includes('ghp_store'));
  delete process.env.GH_TOKEN;
  deleteCred('github', 'api_key');
});

test('user without any token is MISSING_KEY (exit 1) and HTTP errors are GITHUB_HTTP', async () => {
  const miss = await capture(['user'], { fetch: fakeFetch({}).fetch, exec: noGh });
  assert.equal(miss.code, 1);
  assert.equal(miss.envelope.error.code, 'MISSING_KEY');
  const { fetch } = fakeFetch({ '/user': { status: 401, body: { message: 'Bad credentials' } } });
  const bad = await capture(['user'], { fetch, exec: fakeGh });
  assert.equal(bad.code, 1);
  assert.equal(bad.envelope.error.code, 'GITHUB_HTTP');
  assert.match(bad.envelope.error.message, /HTTP 401.*Bad credentials/);
  assert.ok(!bad.stdout.includes('gho_from_gh'));
  const gone = await capture(['repos', 'nobody'], { fetch: fakeFetch({}).fetch, exec: noGh });
  assert.equal(gone.code, 1);
  assert.equal(gone.envelope.error.code, 'GITHUB_HTTP');
});

test('network failure is NETWORK (exit 1)', async () => {
  const fetch = async () => { throw Object.assign(new TypeError('fetch failed'), { cause: new Error('ECONNREFUSED') }); };
  const r = await capture(['repos', 'acme'], { fetch, exec: noGh });
  assert.equal(r.code, 1);
  assert.equal(r.envelope.error.code, 'NETWORK');
  assert.match(r.envelope.error.message, /ECONNREFUSED/);
});

test('usage errors exit 2', async () => {
  const fetch = async () => { throw new Error('must not be called'); };
  for (const args of [[], ['orgs'], ['user', 'extra'], ['repos'], ['repos', 'a', '--limit'], ['repos', 'a', '--limit', '0'],
    ['repos', 'a', '--limit', '5000'], ['repos', 'a', 'b'], ['repos', 'a', '--bogus']]) {
    const r = await capture(args, { fetch, exec: noGh });
    assert.equal(r.code, 2, JSON.stringify(args));
    assert.equal(r.envelope.error.code, 'USAGE');
  }
});

test('ops fragments are read-only and named github_*', () => {
  assert.deepEqual(ops.map((o) => [o.name, o.access]), [['github_user', 'read'], ['github_repos', 'read']]);
});
