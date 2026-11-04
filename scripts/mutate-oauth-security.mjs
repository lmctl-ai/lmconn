// Each valid production-copy mutation must fail a semantic security assertion, never hang a transport.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
const root = path.resolve(import.meta.dirname, '..'), dir = fs.mkdtempSync(path.join(tmpdir(), 'lmconn-security-mut-'));
const copy = path.join(dir, 'copy');
fs.cpSync(root, copy, { recursive: true, filter: file => !file.split(path.sep).includes('.git') });
const cases = [
  ['Windows protected DB allowed', 'src/creds.js', [["if (process.platform !== 'win32') return;", 'return;']]],
  ['secret scopes accepted', 'src/oauth-security.js', [["export function scopeText(value, requested = '', secrets = []) {", "export function scopeText(value, requested = '', secrets = []) { return value;"]]],
  ['old metadata unredacted', 'src/cmd-oauth.js', [["function safeMeta(service, value) { return safeMetadata", "function safeMeta(service, value) { return value; return safeMetadata"]]],
  ['stale issuer configuration retained', 'src/cmd-cred.js', [["for (const field of configFields) deleteCred(service, field, db);", 'void 0;']]],
  ['issuer mismatch accepted', 'src/cmd-cred.js', [["if (old?.noReveal) {", 'if (false) {']]],
  ['foreign origin accepted', 'src/credential-policy.js', [["if (!p.origins.includes(origin))", 'if (false)']]],
  ['protected legacy write allowed', 'src/credential-policy.js', [["if (brokerMode() || policy(service, db)?.noReveal) throw securityError('Protected credentials require cred store; legacy writes cannot change them');", "if (false) throw securityError('Protected credentials require cred store; legacy writes cannot change them');"]]],
  ['reveal policy ignored', 'src/credential-policy.js', [["if (brokerMode() || policy(service, db)?.noReveal) throw securityError('This credential cannot be revealed');", "if (false) throw securityError('This credential cannot be revealed');"]]],
  ['protected body exposed', 'src/cmd-http.js', [["if (binding?.noReveal) {", 'if (false) {']]],
  ['authorization forwarded across origins', 'src/cmd-http.js', [["headers.delete(name);", 'void name;']]],
  ['public HTTP OAuth accepted', 'src/oauth-security.js', [["url.protocol !== 'https:' && !(url.protocol === 'http:' && literalLoopback)", 'false']]],
  ['terminal controls accepted', 'src/cmd-oauth.js', [["|| unsafeText(userCode)", '|| false']]],
  ['pending mapped to denial', 'src/cmd-oauth.js', [["if (token?.error === 'authorization_pending') continue;", "if (token?.error === 'authorization_pending') throw error('DENIED', 'mutation');"]]],
  ['slow_down increment omitted', 'src/cmd-oauth.js', [['intervalMs += 5000', 'intervalMs += 0']]],
  ['access_denied branch omitted', 'src/cmd-oauth.js', [["if (token?.error === 'access_denied')", 'if (false)']]],
  ['expired_token branch omitted', 'src/cmd-oauth.js', [["if (token?.error === 'expired_token')", 'if (false)']]],
  ['provider signal omitted', 'src/cmd-oauth.js', [['signal: lifetime.signal', 'signal: undefined']]],
  ['body cancellation race omitted', 'src/cmd-oauth.js', [['token = await lifetime.race(response.json());', 'token = await response.json();']]],
  ['fetch cancellation race omitted', 'src/cmd-oauth.js', [['response = await lifetime.race(fetch(tokenUrl, {', 'response = await (fetch(tokenUrl, {']]],
  ['precommit expiry guard omitted', 'src/cmd-oauth.js', [['    guard();', '    void 0;']]],
  ['oversized timer chunks allowed', 'src/oauth-deadline.js', [['Math.min(remaining, MAX_TIMER)', 'remaining']]],
  ['invalid callback claims session', 'src/cmd-oauth.js', [['    let parsed;', '    received = true; let parsed;']]],
  ['PKCE S256 replaced with verifier', 'src/cmd-oauth.js', [["createHash('sha256').update(verifier).digest('base64url')", 'verifier']]],
  ['callback state equality omitted', 'src/oauth-security.js', [["params.get('state') !== state", 'false']]],
  ['duplicate callback params accepted', 'src/oauth-security.js', [['|| params.has(key)', '|| false']]],
  ['callback fragments accepted', 'src/oauth-security.js', [["raw.includes('#') ||", 'false ||']]],
  ['callback decoding permissive', 'src/oauth-security.js', [["value = decodeURIComponent(pair.slice(at + 1).replaceAll('+', ' '));", "value = pair.slice(at + 1).replaceAll('+', ' ');"]]],
  ['store transaction omitted', 'src/cmd-cred.js', [["db.exec('BEGIN IMMEDIATE');", 'void 0;'], ["db.exec('COMMIT');", 'void 0;'], ["db.exec('ROLLBACK');", 'void 0;']]],
  ['unsafe directory accepted', 'src/store-path.js', [["fs.chmodSync(directory, 0o700); if ((fs.statSync(directory).mode & 0o777) !== 0o700) fail();", 'void 0;']]],
  ['sidecar symlinks unchecked', 'src/store-path.js', [["for (const suffix of ['-journal', '-wal', '-shm']) regular(file + suffix);", 'void 0;']]],
  ['protected LLM adapter bypass', 'src/main.js', [["if (area === 'llm' && argv[1] === 'chat' && protectedHandle(argv[2]))", 'if (false)']]],
];
const names = [...new Set(cases.map(c => c[1]))], original = Object.fromEntries(names.map(file => [file, fs.readFileSync(path.join(copy, file), 'utf8')]));
const evidence = process.env.LMCONN_MUTATION_EVIDENCE;
if (evidence) fs.mkdirSync(evidence, { recursive: true });
function run(label) {
  const r = spawnSync(process.execPath, ['--test', 'test/oauth-security.test.js', 'test/credential-security.test.js'], { cwd: copy, env: process.env, encoding: 'utf8', maxBuffer: Infinity });
  assert.ifError(r.error);
  if (evidence) fs.writeFileSync(path.join(evidence, label + '.log'), r.stdout + r.stderr);
  return r;
}
try {
  let r = run('baseline'); assert.equal(r.status, 0, r.stdout + r.stderr); console.log('healthy baseline PASS');
  const results = [];
  for (let i = 0; i < cases.length; i++) {
    const [name, file, edits] = cases[i]; let text = original[file];
    for (const [from, to] of edits) { assert.equal(text.split(from).length, 2, 'unique mutation anchor: ' + name); text = text.replace(from, to); }
    fs.writeFileSync(path.join(copy, file), text);
    try {
      r = run(String(i + 1)); assert.notEqual(r.status, 0, 'SURVIVED: ' + name);
      assert.match(r.stdout + r.stderr, /AssertionError/); assert.doesNotMatch(r.stdout + r.stderr, /SyntaxError|ERR_MODULE_NOT_FOUND/);
      console.log('CAUGHT ' + name); results.push({ name, caught: true });
    } finally { fs.writeFileSync(path.join(copy, file), original[file]); }
  }
  if (evidence) fs.writeFileSync(path.join(evidence, 'results.json'), JSON.stringify(results, null, 2));
  console.log(results.length + ' valid mutants caught; zero survivors');
} finally { fs.rmSync(dir, { recursive: true, force: true }); }
