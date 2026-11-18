// Encryption at rest: real SQLite files, real AES-GCM, real child processes, real modes and symlinks.
// Every secret is synthetic; every store lives in a temp directory with its own key directory.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { run as runCred } from '../src/cmd-cred.js';
import { run as runKey } from '../src/cmd-key.js';
import { openDb, closeDb, setCred, getCred, listCreds } from '../src/creds.js';
import { policy, putPolicy } from '../src/credential-policy.js';
import { resetKeyCache } from '../src/keystore.js';
import { rotateKey, rotateData, encryptExisting } from '../src/crypto-store.js';
import { request, parseArgs } from '../src/cmd-http.js';

const cli = fileURLToPath(new URL('../bin/lmconn.js', import.meta.url));
const root = fs.mkdtempSync(join(tmpdir(), 'lmconn-enc-'));
const posix = process.platform !== 'win32';
const isRoot = posix && process.geteuid() === 0;
const ENV = ['LMCONN_DB', 'XDG_CONFIG_HOME', 'LMCONN_KEY', 'LMCONN_KEY_FILE', 'LMCONN_ALLOW_PLAINTEXT', 'LMCONN_STORE_MODE'];
const saved = Object.fromEntries(ENV.map(name => [name, process.env[name]]));
let current = null;
let counter = 0;

after(() => {
  if (current) closeDb(current);
  for (const name of ENV) { if (saved[name] === undefined) delete process.env[name]; else process.env[name] = saved[name]; }
  resetKeyCache();
  fs.rmSync(root, { recursive: true, force: true });
});

function world() {
  const dir = join(root, `w${++counter}`);
  fs.mkdirSync(dir, { mode: 0o700 });
  return { dir, db: join(dir, 'db', 'creds.db'), cfg: join(dir, 'cfg'), key: join(dir, 'cfg', 'lmconn', 'instance.key') };
}
// Point this process at a world with no key source configured except its own XDG directory.
function use(w, extra = {}) {
  if (current) closeDb(current);
  resetKeyCache();
  for (const name of ENV) delete process.env[name];
  Object.assign(process.env, { LMCONN_DB: w.db, XDG_CONFIG_HOME: w.cfg }, extra);
  current = w.db;
  return w;
}
const childEnv = (w, extra = {}) => {
  const env = { ...process.env, LMCONN_DB: w.db, XDG_CONFIG_HOME: w.cfg, ...extra };
  for (const name of ['LMCONN_KEY', 'LMCONN_KEY_FILE', 'LMCONN_ALLOW_PLAINTEXT', 'LMCONN_STORE_MODE']) if (!(name in extra)) delete env[name];
  return env;
};
function lmconn(w, args, input, extra) {
  const r = spawnSync(process.execPath, [cli, ...args], { env: childEnv(w, extra), input: typeof input === 'object' ? JSON.stringify(input) : input, encoding: 'utf8', maxBuffer: 1 << 24 });
  assert.ifError(r.error);
  let envelope = null;
  try { envelope = JSON.parse(r.stdout); } catch { /* checked by callers */ }
  return { code: r.status, out: r.stdout, err: r.stderr, envelope };
}
async function capture(run, args, stdin) {
  const outWrite = process.stdout.write, errWrite = process.stderr.write;
  const stdinDescriptor = Object.getOwnPropertyDescriptor(process, 'stdin');
  let out = '', err = '';
  process.stdout.write = function (chunk, ...rest) { if (typeof chunk !== 'string') return outWrite.call(this, chunk, ...rest); out += chunk; return true; };
  process.stderr.write = chunk => { err += chunk; return true; };
  if (stdin !== undefined) Object.defineProperty(process, 'stdin', { configurable: true, value: stdin });
  let code;
  try { code = await run(args); } finally {
    process.stdout.write = outWrite; process.stderr.write = errWrite;
    if (stdin !== undefined) Object.defineProperty(process, 'stdin', stdinDescriptor);
  }
  assert.equal(out.trim().split('\n').length, 1, 'exactly one envelope');
  return { code, envelope: JSON.parse(out), out, err };
}
const codeOf = fn => { try { fn(); } catch (err) { return err.code ?? `uncoded:${err.message}`; } return null; };

// A store as an older lmconn left it: plain table, plaintext values, no gen column.
function legacyDb(w, rows, policies = []) {
  fs.mkdirSync(dirname(w.db), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(w.db);
  db.exec(`CREATE TABLE creds (service TEXT NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (service, field));
    CREATE TABLE credential_policy (service TEXT PRIMARY KEY, document TEXT NOT NULL);`);
  for (const [service, field, value] of rows) db.prepare('INSERT INTO creds VALUES (?, ?, ?, ?)').run(service, field, value, '2026-01-01T00:00:00.000Z');
  for (const [service, document] of policies) db.prepare('INSERT INTO credential_policy VALUES (?, ?)').run(service, document);
  db.close();
  if (posix) fs.chmodSync(w.db, 0o600);
}
function raw(w, fn) {
  closeDb(w.db); // no cached connection while the test edits the file; the next call reopens
  const db = new DatabaseSync(w.db);
  try { return fn(db); } finally { db.close(); }
}
const rows = w => raw(w, db => db.prepare('SELECT service, field, value, gen FROM creds ORDER BY service, field').all());
const bytes = w => [w.db, `${w.db}-journal`].filter(f => fs.existsSync(f)).map(f => fs.readFileSync(f));
const holds = (w, text) => bytes(w).some(b => b.includes(Buffer.from(text)));
const keyText = w => fs.readFileSync(w.key, 'utf8').trim();
const flip = text => text.slice(0, -3) + (text.slice(-3, -2) === 'A' ? 'B' : 'A') + text.slice(-2);

// ---- 1, 5: round trip, legacy, mixed, read never creates a key ----------------------------------

test('round trip for every field kind; legacy plaintext readable; mixed table; a read never creates a key', async () => {
  const w = use(world());
  legacyDb(w, [['legacy', 'api_key', 'synthetic-legacy-api'], ['legacy', 'oauth_access_token', 'synthetic-legacy-access']]);
  assert.equal(getCred('legacy', 'api_key'), 'synthetic-legacy-api');
  assert.equal(listCreds().length, 2);
  const read = await capture(runCred, ['get', 'legacy', 'api_key', '--reveal']);
  assert.equal(read.envelope.result.value, 'synthetic-legacy-api');
  assert.equal(fs.existsSync(w.key), false, 'reading legacy rows must not create a key');
  const kinds = { api_key: 'synthetic-api', oauth_access_token: 'synthetic-access', oauth_refresh_token: 'synthetic-refresh', oauth_client_secret: 'synthetic-client', oauth_expires_at: '2030-01-01T00:00:00.000Z', empty: '', unicode: 'synthetic-\u{1F511}-é\n tail ' };
  for (const [field, value] of Object.entries(kinds)) setCred('mixed', field, value);
  for (const [field, value] of Object.entries(kinds)) assert.equal(getCred('mixed', field), value, field);
  assert.equal(getCred('legacy', 'api_key'), 'synthetic-legacy-api', 'legacy row still readable next to ciphertext');
  const stored = rows(w);
  assert.ok(stored.filter(r => r.service === 'mixed').every(r => r.value.startsWith('lmc1:')));
  assert.ok(stored.filter(r => r.service === 'legacy').every(r => !r.value.startsWith('lmc1:')));
  assert.ok(!holds(w, 'synthetic-api') && !holds(w, 'synthetic-refresh'));
  assert.equal(raw(w, db => db.prepare("SELECT v FROM meta WHERE k = 'encrypted_required'").get()), undefined, 'a mixed store is not sealed yet');
  assert.equal(fs.existsSync(w.key), true);
  closeDb(w.db);
  const imported = lmconn(w, ['cred', 'oauth-store', 'oauthsvc', '--stdin'], { kind: 'oauth2', accessToken: 'synthetic-os-access', refreshToken: 'synthetic-os-refresh', scopes: ['read'], owner: 'tester', source: 'lmauth' });
  assert.equal(imported.code, 0, imported.out + imported.err);
  assert.ok(rows(w).filter(r => r.service === 'oauthsvc').every(r => r.value.startsWith('lmc1:')));
  assert.ok(!holds(w, 'synthetic-os-access'));
  assert.equal(lmconn(w, ['cred', 'get', 'oauthsvc', 'oauth_refresh_token', '--reveal']).envelope.result.value, 'synthetic-os-refresh');
});

// ---- 2, truncation: tamper ----------------------------------------------------------------------

test('flipped or truncated ciphertext, nonce, tag and wrapped data key are DECRYPT_FAILED', () => {
  const w = use(world());
  setCred('svc', 'api_key', 'synthetic-tamper');
  const [row] = rows(w);
  const [prefix, keyId, nonce, data] = row.value.split(':');
  const original = `${prefix}:${keyId}:${nonce}:${data}`;
  const forms = {
    ciphertext: `${prefix}:${keyId}:${nonce}:${flip(data)}`,
    nonce: `${prefix}:${keyId}:${flip(nonce)}:${data}`,
    'short nonce': `${prefix}:${keyId}:${Buffer.from(nonce, 'base64').subarray(0, 8).toString('base64')}:${data}`,
    'truncated tag': `${prefix}:${keyId}:${nonce}:${Buffer.from(data, 'base64').subarray(0, -1).toString('base64')}`,
    'no tag': `${prefix}:${keyId}:${nonce}:${Buffer.alloc(8).toString('base64')}`,
    'unpadded base64': `${prefix}:${keyId}:${nonce}:${data.replace(/=+$/, '')}x`,
    'unknown key id': `${prefix}:${'0'.repeat(16)}:${nonce}:${data}`,
    'extra field': `${original}:x`,
  };
  for (const [name, value] of Object.entries(forms)) {
    raw(w, db => db.prepare('UPDATE creds SET value = ?').run(value));
    const attempt = codeOf(() => getCred('svc', 'api_key'));
    assert.equal(attempt, 'DECRYPT_FAILED', name);
  }
  raw(w, db => db.prepare('UPDATE creds SET value = ?').run(original));
  assert.equal(getCred('svc', 'api_key'), 'synthetic-tamper');
  const wrapped = raw(w, db => db.prepare('SELECT id, wrapped FROM data_keys').get());
  const [tag, wn, wd] = wrapped.wrapped.split(':');
  for (const bad of [`${tag}:${flip(wn)}:${wd}`, `${tag}:${wn}:${flip(wd)}`, `${tag}:${wn}:${Buffer.from(wd, 'base64').subarray(0, -2).toString('base64')}`]) {
    raw(w, db => db.prepare('UPDATE data_keys SET wrapped = ?').run(bad));
    assert.equal(codeOf(() => getCred('svc', 'api_key')), 'DECRYPT_FAILED');
    assert.equal(codeOf(() => setCred('svc', 'other', 'x')), 'DECRYPT_FAILED', 'canary refuses writes on a tampered data key');
  }
});

// ---- 3: row swap ---------------------------------------------------------------------------------

test('a ciphertext moved to another service or field fails authentication', () => {
  const w = use(world());
  setCred('one', 'api_key', 'synthetic-one');
  setCred('two', 'api_key', 'synthetic-two');
  setCred('one', 'other', 'synthetic-three');
  const value = rows(w).find(r => r.service === 'one' && r.field === 'api_key').value;
  for (const [service, field] of [['two', 'api_key'], ['one', 'other']]) {
    raw(w, db => db.prepare('UPDATE creds SET value = ? WHERE service = ? AND field = ?').run(value, service, field));
    assert.equal(codeOf(() => getCred(service, field)), 'DECRYPT_FAILED', `${service}/${field}`);
  }
  assert.equal(getCred('one', 'api_key'), 'synthetic-one');
});

test('NUL in names is fine and length-prefixed AAD keeps ("a\\0b","c") apart from ("a","b\\0c")', () => {
  const w = use(world());
  setCred('a\0b', 'c', 'synthetic-nul-1');
  setCred('a', 'b\0c', 'synthetic-nul-2');
  assert.equal(getCred('a\0b', 'c'), 'synthetic-nul-1');
  assert.equal(getCred('a', 'b\0c'), 'synthetic-nul-2');
  const first = rows(w).find(r => r.service === 'a\0b').value;
  raw(w, db => db.prepare('UPDATE creds SET value = ? WHERE service = ?').run(first, 'a'));
  assert.equal(codeOf(() => getCred('a', 'b\0c')), 'DECRYPT_FAILED');
});

// ---- 4: wrong and missing key --------------------------------------------------------------------

test('missing or wrong key with ciphertext present fails closed and never creates a key', () => {
  const w = use(world());
  setCred('svc', 'api_key', 'synthetic-closed');
  const good = fs.readFileSync(w.key);
  fs.unlinkSync(w.key);
  assert.equal(codeOf(() => getCred('svc', 'api_key')), 'KEY_MISSING');
  assert.equal(codeOf(() => setCred('svc', 'new', 'synthetic-new')), 'KEY_MISSING');
  assert.equal(fs.existsSync(w.key), false, 'no new key may be generated over existing ciphertext');
  fs.writeFileSync(w.key, `${randomBytes(32).toString('base64')}\n`, { mode: 0o600 });
  assert.equal(codeOf(() => getCred('svc', 'api_key')), 'KEY_MISMATCH');
  assert.equal(codeOf(() => setCred('svc', 'new', 'synthetic-new')), 'KEY_MISMATCH', 'canary: a wrong key cannot create a mixed store');
  assert.equal(rows(w).length, 1);
  fs.writeFileSync(w.key, good, { mode: 0o600 });
  assert.equal(getCred('svc', 'api_key'), 'synthetic-closed');
});

test('strict keys: wrong length, bad base64, truncated file are KEY_INVALID and a partial file is never overwritten', () => {
  const w = use(world());
  const good = randomBytes(32).toString('base64');
  for (const bad of [randomBytes(31).toString('base64'), randomBytes(33).toString('base64'), good.slice(0, -1), `${good} `, 'not base64!', good.replace(/=+$/, '')]) {
    use(w, { LMCONN_KEY: bad });
    assert.equal(codeOf(() => setCred('svc', 'api_key', 'synthetic-x')), 'KEY_INVALID', bad.length + ' chars');
  }
  use(w, { LMCONN_KEY: good });
  setCred('svc', 'api_key', 'synthetic-env-key');
  assert.equal(fs.existsSync(w.key), false, 'LMCONN_KEY means no key file');
  use(w, { LMCONN_KEY: good });
  assert.equal(getCred('svc', 'api_key'), 'synthetic-env-key');
  if (!posix) return;
  const partial = world(); use(partial);
  fs.mkdirSync(dirname(partial.key), { recursive: true, mode: 0o700 });
  fs.writeFileSync(partial.key, good.slice(0, 20), { mode: 0o600 });
  fs.writeFileSync(join(dirname(partial.key), '.instance.key.1.tmp'), 'partial', { mode: 0o600 });
  assert.equal(codeOf(() => setCred('svc', 'api_key', 'synthetic-x')), 'KEY_INVALID');
  assert.equal(fs.readFileSync(partial.key, 'utf8'), good.slice(0, 20), 'a damaged key file is not replaced');
  assert.equal(rows(partial).length, 0);
});

// ---- 6, 9, idempotence, VACUUM -------------------------------------------------------------------

test('encrypt-existing: every row ciphertext, no secret in the new file, warnings on stderr, idempotent', async () => {
  const w = use(world());
  const secrets = ['synthetic-legacy-aaa', 'synthetic-legacy-bbb', 'synthetic-legacy-ccc'];
  legacyDb(w, [['s1', 'api_key', secrets[0]], ['s1', 'oauth_refresh_token', secrets[1]], ['s2', 'api_key', secrets[2]]], [['s1', '{"origins":[],"noReveal":false}']]);
  raw(w, db => { db.exec("INSERT INTO creds VALUES ('big','x','" + 'synthetic-freed-page-'.repeat(300) + "','t')"); db.exec("DELETE FROM creds WHERE service = 'big'"); });
  assert.ok(holds(w, 'synthetic-legacy-aaa'));
  const r = await capture(runCred, ['encrypt-existing']);
  assert.equal(r.code, 0, r.out);
  assert.deepEqual(r.envelope.result, { total: 3, encrypted: 3, reencrypted: 0, alreadyEncrypted: 0, rewritten: true });
  assert.match(r.err, /plaintext may remain in earlier backups/);
  assert.match(r.err, /encryption key at/);
  assert.ok(rows(w).every(x => x.value.startsWith('lmc1:')));
  for (const secret of [...secrets, 'synthetic-freed-page-']) assert.ok(!holds(w, secret), secret);
  assert.equal(getCred('s1', 'oauth_refresh_token'), secrets[1]);
  assert.equal(policy('s1').noReveal, false);
  assert.equal(fs.statSync(w.db).mode & 0o777, posix ? 0o600 : fs.statSync(w.db).mode & 0o777);
  const again = await capture(runCred, ['encrypt-existing']);
  assert.deepEqual(again.envelope.result, { total: 3, encrypted: 0, reencrypted: 0, alreadyEncrypted: 3, rewritten: false });
  const before = fs.readFileSync(w.db);
  await capture(runCred, ['encrypt-existing']);
  assert.ok(before.equals(fs.readFileSync(w.db)), 're-run changes nothing');
  assert.equal(codeOf(() => raw(w, db => db.prepare("INSERT INTO creds VALUES ('x','y','plain','t',1)").run())), 'ERR_SQLITE_ERROR', 'sealed store refuses plaintext inserts');
  assert.equal((await capture(runCred, ['encrypt-existing', '--bogus'])).code, 2);
});

test('encrypt-existing falls back to one transaction plus VACUUM when the file cannot be replaced', () => {
  const w = use(world());
  legacyDb(w, [['v', 'api_key', 'synthetic-vacuum-secret'], ['v', 'other', 'synthetic-vacuum-two']]);
  const db = openDb();
  const result = encryptExisting(db, { inPlace: true });
  assert.equal(result.encrypted, 2);
  closeDb(w.db);
  assert.ok(!holds(w, 'synthetic-vacuum'));
  assert.equal(getCred('v', 'api_key'), 'synthetic-vacuum-secret');
});

// ---- 1 (hardening): no downgrade, authenticated policy, old binary --------------------------------

test('a sealed store refuses plaintext rows; stripping the trigger does not make them readable', () => {
  const w = use(world());
  setCred('svc', 'api_key', 'synthetic-sealed');
  assert.equal(raw(w, db => db.prepare("SELECT v FROM meta WHERE k = 'encrypted_required'").get().v), '1');
  assert.equal(raw(w, db => db.prepare('PRAGMA user_version').get().user_version), 2);
  // What an older lmconn would do: INSERT with its four columns and plaintext.
  assert.throws(() => raw(w, db => db.prepare('INSERT INTO creds (service, field, value, updated_at) VALUES (?, ?, ?, ?)').run('svc', 'api_key', 'plain', 'now')), /plaintext refused/);
  raw(w, db => { db.exec('DROP TRIGGER lmconn_sealed_insert; DROP TRIGGER lmconn_sealed_update'); db.prepare("UPDATE creds SET value = 'synthetic-planted'").run(); });
  assert.equal(codeOf(() => getCred('svc', 'api_key')), 'STORE_TAMPERED');
  raw(w, db => db.exec('DELETE FROM meta'));
  assert.equal(codeOf(() => getCred('svc', 'api_key')), 'STORE_TAMPERED', 'user_version still marks the store required');
  raw(w, db => db.exec('PRAGMA user_version = 99'));
  assert.equal(codeOf(() => openDb()), 'STORE_VERSION', 'a newer format is refused');
});

test('policy rows: edit, deletion, planted rows and a stripped MAC are STORE_TAMPERED', () => {
  const w = use(world());
  const doc = { noReveal: true, kind: 'bearer', issuer: null, owner: 'o', origins: ['https://api.invalid'], refresh: null };
  setCred('h', 'api_key', 'synthetic-policy');
  putPolicy('h', doc);
  assert.deepEqual(policy('h'), doc);
  const snapshot = raw(w, db => db.prepare('SELECT * FROM credential_policy').all());
  raw(w, db => db.prepare('UPDATE credential_policy SET document = ?').run(JSON.stringify({ ...doc, noReveal: false })));
  assert.equal(codeOf(() => policy('h')), 'STORE_TAMPERED');
  raw(w, db => db.prepare('UPDATE credential_policy SET document = ?, mac = NULL').run(snapshot[0].document));
  assert.equal(codeOf(() => policy('h')), 'STORE_TAMPERED', 'valid document, no MAC');
  raw(w, db => db.prepare('UPDATE credential_policy SET mac = ?').run(snapshot[0].mac));
  assert.deepEqual(policy('h'), doc);
  raw(w, db => db.exec('DELETE FROM credential_policy'));
  assert.equal(codeOf(() => policy('h')), 'STORE_TAMPERED', 'a deleted row would unprotect the handle');
  assert.equal(codeOf(() => getCred('h', 'api_key')), 'STORE_TAMPERED');
  raw(w, db => { db.prepare('INSERT INTO credential_policy VALUES (?, ?, ?)').run(snapshot[0].service, snapshot[0].document, snapshot[0].mac); db.prepare('INSERT INTO credential_policy VALUES (?, ?, NULL)').run('planted', '{}'); });
  assert.equal(codeOf(() => policy('h')), 'STORE_TAMPERED');
  raw(w, db => db.exec("DELETE FROM credential_policy WHERE service = 'planted'"));
  assert.deepEqual(policy('h'), doc);
});

test('broker mode requires encryption: no plaintext fallback, a fresh broker store creates a key, legacy rows are tampered', () => {
  const w = use(world(), { LMCONN_STORE_MODE: 'broker', LMCONN_ALLOW_PLAINTEXT: '1' });
  fs.mkdirSync(w.cfg, { mode: 0o500 });
  if (posix && !isRoot) {
    assert.equal(codeOf(() => setCred('b', 'api_key', 'synthetic-broker')), 'KEY_UNAVAILABLE', 'ALLOW_PLAINTEXT does not apply in broker mode');
    assert.equal(rows(w).length, 0);
  }
  fs.chmodSync(w.cfg, 0o700);
  setCred('b', 'api_key', 'synthetic-broker');
  assert.ok(rows(w)[0].value.startsWith('lmc1:'));
  const legacy = use(world(), { LMCONN_STORE_MODE: 'broker' });
  legacyDb(legacy, [['old', 'api_key', 'synthetic-old-plaintext']]);
  assert.equal(codeOf(() => getCred('old', 'api_key')), 'STORE_TAMPERED');
});

// ---- 6 (hardening): rollback ----------------------------------------------------------------------

test('a restored older value fails authentication (generation in the AAD); a whole older row is the documented limit', () => {
  const w = use(world());
  setCred('svc', 'api_key', 'synthetic-first');
  const first = rows(w)[0];
  setCred('svc', 'api_key', 'synthetic-second');
  assert.ok(rows(w)[0].gen > first.gen);
  raw(w, db => db.prepare('UPDATE creds SET value = ?').run(first.value));
  assert.equal(codeOf(() => getCred('svc', 'api_key')), 'DECRYPT_FAILED');
  raw(w, db => db.prepare('UPDATE creds SET value = ?, gen = ?').run(first.value, first.gen));
  assert.equal(getCred('svc', 'api_key'), 'synthetic-first', 'restoring value and gen together is undetectable, like whole-file rollback (docs)');
  setCred('svc', 'api_key', 'synthetic-third');
  setCred('gone', 'f', 'x');
  const old = rows(w).find(r => r.service === 'gone');
  raw(w, db => db.prepare("DELETE FROM creds WHERE service = 'gone'").run());
  setCred('gone', 'f', 'y');
  raw(w, db => db.prepare("UPDATE creds SET value = ? WHERE service = 'gone'").run(old.value));
  assert.equal(codeOf(() => getCred('gone', 'f')), 'DECRYPT_FAILED', 'delete and re-create does not reset the generation');
});

// ---- 7: rotation -------------------------------------------------------------------------------------

test('key rotate rewraps data keys; old key alone no longer opens the store; --data and --all retire old keys', async () => {
  const w = use(world());
  setCred('svc', 'api_key', 'synthetic-rot-1');
  putPolicy('svc', { noReveal: false, kind: 'legacy', issuer: null, owner: null, origins: [], refresh: null });
  const oldKey = fs.readFileSync(w.key);
  const oldRows = rows(w);
  const r = await capture(runKey, ['rotate']);
  assert.equal(r.code, 0, r.out);
  assert.deepEqual(r.envelope.result, { rotated: 'instance' });
  assert.deepEqual(rows(w), oldRows, 'rows are not rewritten');
  assert.notDeepEqual(fs.readFileSync(w.key), oldKey);
  assert.deepEqual(fs.readFileSync(`${w.key}.prev`), oldKey);
  assert.equal(getCred('svc', 'api_key'), 'synthetic-rot-1');
  assert.equal(policy('svc').kind, 'legacy');
  setCred('svc', 'two', 'synthetic-rot-2');
  const newKey = fs.readFileSync(w.key);
  fs.unlinkSync(`${w.key}.prev`);
  fs.writeFileSync(w.key, oldKey, { mode: 0o600 });
  assert.equal(codeOf(() => getCred('svc', 'api_key')), 'KEY_MISMATCH', 'old key alone is rejected after the switch');
  fs.writeFileSync(w.key, newKey, { mode: 0o600 });
  fs.writeFileSync(`${w.key}.prev`, oldKey, { mode: 0o600 });
  fs.chmodSync(`${w.key}.prev`, 0o600);
  const firstDek = raw(w, db => db.prepare('SELECT id FROM data_keys WHERE active = 1').get().id);
  assert.deepEqual((await capture(runKey, ['rotate', '--data'])).envelope.result, { rotated: 'data' });
  const secondDek = raw(w, db => db.prepare('SELECT id FROM data_keys WHERE active = 1').get().id);
  assert.notEqual(firstDek, secondDek);
  assert.equal(raw(w, db => db.prepare('SELECT count(*) AS n FROM data_keys').get().n), 2, 'old data keys stay while rows name them');
  assert.equal(getCred('svc', 'api_key'), 'synthetic-rot-1');
  setCred('svc', 'three', 'synthetic-rot-3');
  assert.ok(rows(w).find(x => x.field === 'three').value.startsWith(`lmc1:${secondDek}:`));
  const all = await capture(runCred, ['encrypt-existing', '--all']);
  assert.equal(all.envelope.result.reencrypted, 2);
  assert.ok(rows(w).every(x => x.value.startsWith(`lmc1:${secondDek}:`)));
  assert.equal(raw(w, db => db.prepare('SELECT count(*) AS n FROM data_keys').get().n), 1, 'unused data keys are deleted');
  assert.equal(fs.existsSync(`${w.key}.prev`), false, '.prev is removed after a successful --all');
  assert.equal(getCred('svc', 'api_key'), 'synthetic-rot-1');
  assert.equal(policy('svc').kind, 'legacy');
});

test('crash at every rotation step leaves the store readable and a re-run finishes the rotation', () => {
  for (const step of ['new-key-written', 'prev-written', 'key-switched', 'db-committed']) {
    const w = use(world());
    setCred('svc', 'api_key', `synthetic-crash-${step}`);
    putPolicy('svc', { noReveal: true, kind: 'bearer', issuer: null, owner: 'o', origins: ['https://a.invalid'], refresh: null });
    const db = openDb();
    assert.throws(() => rotateKey(db, name => { if (name === step) throw Object.assign(new Error('crash'), { code: 'CRASH' }); }), e => e.code === 'CRASH');
    assert.equal(getCred('svc', 'api_key'), `synthetic-crash-${step}`, step);
    assert.equal(policy('svc').noReveal, true, step);
    if (step === 'key-switched') assert.equal(codeOf(() => setCred('svc', 'x', 'y')), 'KEY_MISMATCH', 'writes wait for the rewrap');
    // After db-committed the rotation is complete; a second one must wait until .prev is retired.
    if (step === 'db-committed') assert.equal(codeOf(() => rotateKey(db)), 'KEY_UNAVAILABLE');
    else rotateKey(db);
    assert.equal(getCred('svc', 'api_key'), `synthetic-crash-${step}`, step);
    setCred('svc', 'after', 'synthetic-after');
    assert.equal(getCred('svc', 'after'), 'synthetic-after');
    assert.equal(policy('svc').noReveal, true);
    assert.equal(codeOf(() => rotateData(db)), null);
  }
});

// ---- 8: concurrent first write ------------------------------------------------------------------------

test('eight processes writing first at once create exactly one key and one active data key, and agree on it', async () => {
  const w = use(world());
  const children = Array.from({ length: 8 }, (_, i) => new Promise(resolve => {
    const child = spawn(process.execPath, [cli, 'cred', 'set', 'race', `f${i}`, '--stdin'], { env: childEnv(w), stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '', err = '';
    child.stdout.on('data', d => { out += d; }); child.stderr.on('data', d => { err += d; });
    child.on('close', code => resolve({ code, out, err }));
    child.stdin.end(`synthetic-race-${i}`);
  }));
  const results = await Promise.all(children);
  for (const r of results) assert.equal(r.code, 0, r.out + r.err);
  assert.deepEqual(fs.readdirSync(dirname(w.key)), ['instance.key'], 'no stray temp files');
  assert.equal(results.filter(r => /created a new encryption key/.test(r.err)).length, 1, 'exactly one process created the key');
  assert.equal(raw(w, db => db.prepare('SELECT count(*) AS n FROM data_keys WHERE active = 1').get().n), 1);
  assert.equal(raw(w, db => db.prepare('SELECT count(*) AS n FROM data_keys').get().n), 1);
  for (let i = 0; i < 8; i++) assert.equal(getCred('race', `f${i}`), `synthetic-race-${i}`);
});

// ---- 9: nothing sensitive in any output ------------------------------------------------------------------

test('no key, secret or ciphertext in stdout, stderr or error text across commands and failures', async () => {
  const w = use(world());
  const secret = 'synthetic-leakcheck-secret';
  const seen = [];
  const note = r => { seen.push(r.out + r.err); return r; };
  note(lmconn(w, ['cred', 'set', 'leak', 'api_key', '--stdin'], secret));
  note(lmconn(w, ['cred', 'get', 'leak', 'api_key']));
  note(lmconn(w, ['cred', 'list', '--json']));
  note(lmconn(w, ['cred', 'encrypt-existing', '--all']));
  note(lmconn(w, ['key', 'rotate']));
  note(lmconn(w, ['key', 'rotate', '--data']));
  const target = join(w.dir, 'backups', 'key.copy');
  fs.mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  const backup = note(lmconn(w, ['key', 'backup', '--to', target]));
  assert.equal(backup.code, 0, backup.out + backup.err);
  const keys = [keyText(w), fs.readFileSync(`${w.key}.prev`, 'utf8').trim()];
  const ciphertext = rows(w)[0].value;
  const wrapped = raw(w, db => db.prepare('SELECT wrapped FROM data_keys').all()).map(r => r.wrapped);
  // Failure paths: tamper, wrong key, missing key, bad key.
  raw(w, db => db.prepare('UPDATE creds SET value = ?').run(flip(ciphertext)));
  note(lmconn(w, ['cred', 'get', 'leak', 'api_key', '--reveal']));
  raw(w, db => db.prepare('UPDATE creds SET value = ?').run(ciphertext));
  note(lmconn(w, ['cred', 'get', 'leak', 'api_key', '--reveal'], undefined, { LMCONN_KEY: randomBytes(32).toString('base64') }));
  note(lmconn(w, ['cred', 'get', 'leak', 'api_key', '--reveal'], undefined, { LMCONN_KEY: 'AAAA' }));
  note(lmconn(w, ['cred', 'get', 'leak', 'api_key', '--reveal'], undefined, { XDG_CONFIG_HOME: join(w.dir, 'elsewhere') }));
  note(lmconn(w, ['--input-json', '{}', 'key_backup']));
  const everything = seen.join('\n');
  for (const needle of [...keys, ciphertext, ...wrapped, ciphertext.split(':')[2], ...keys.map(k => Buffer.from(k, 'base64').toString('hex'))]) assert.ok(!everything.includes(needle), 'output leaked sensitive material');
  const reveal = lmconn(w, ['cred', 'get', 'leak', 'api_key', '--reveal']);
  assert.equal(reveal.envelope.result.value, secret, 'only an explicit reveal prints the value');
  for (const out of seen.slice(0, 2)) assert.ok(!out.includes(secret));
});

// ---- 10: files, modes, symlinks, separation, backup -----------------------------------------------------------

test('key file 0600 in a 0700 directory separate from the database; loose mode and symlinks refused', { skip: !posix && 'POSIX modes and symlinks' }, () => {
  const w = use(world());
  setCred('svc', 'api_key', 'synthetic-modes');
  assert.equal(fs.statSync(w.key).mode & 0o777, 0o600);
  assert.equal(fs.statSync(dirname(w.key)).mode & 0o777, 0o700);
  assert.notEqual(dirname(w.key), dirname(w.db));
  fs.chmodSync(w.key, 0o644);
  assert.equal(codeOf(() => getCred('svc', 'api_key')), 'STORE_SECURITY');
  assert.equal(codeOf(() => setCred('svc', 'api_key', 'x')), 'STORE_SECURITY');
  assert.equal(fs.statSync(w.key).mode & 0o777, 0o644, 'a loose key file is not repaired');
  fs.chmodSync(w.key, 0o600);
  assert.equal(getCred('svc', 'api_key'), 'synthetic-modes');
  const real = `${w.key}.real`;
  fs.renameSync(w.key, real);
  fs.symlinkSync(real, w.key);
  assert.equal(codeOf(() => getCred('svc', 'api_key')), 'STORE_SECURITY', 'symlinked key file');
  fs.unlinkSync(w.key); fs.renameSync(real, w.key);
  fs.linkSync(w.key, `${w.key}.hard`);
  assert.equal(codeOf(() => getCred('svc', 'api_key')), 'STORE_SECURITY', 'hard-linked key file');
  fs.unlinkSync(`${w.key}.hard`);
  assert.equal(getCred('svc', 'api_key'), 'synthetic-modes');
  // A symlinked key directory (XDG pointing through a link) is refused for a fresh key too.
  const link = world(); use(link);
  fs.mkdirSync(join(link.dir, 'target'), { mode: 0o700 });
  fs.symlinkSync(join(link.dir, 'target'), link.cfg);
  assert.equal(codeOf(() => setCred('svc', 'api_key', 'x')), 'STORE_SECURITY');
  assert.equal(rows(link).length, 0);
  // Key file next to the database is refused.
  const same = world(); use(same, { LMCONN_KEY_FILE: join(dirname(same.db), 'instance.key') });
  assert.equal(codeOf(() => setCred('svc', 'api_key', 'x')), 'STORE_SECURITY');
  // LMCONN_KEY_FILE is honoured and checked like the default.
  const custom = world(); use(custom, { LMCONN_KEY_FILE: join(custom.dir, 'keys', 'my.key') });
  setCred('svc', 'api_key', 'synthetic-custom');
  assert.equal(fs.statSync(join(custom.dir, 'keys', 'my.key')).mode & 0o777, 0o600);
  assert.equal(fs.existsSync(custom.key), false);
  fs.chmodSync(join(custom.dir, 'keys', 'my.key'), 0o640);
  assert.equal(codeOf(() => getCred('svc', 'api_key')), 'STORE_SECURITY');
});

test('key backup: new 0600 file, never printed; refuses the database directory, sync folders and existing targets', { skip: !posix && 'POSIX modes' }, async () => {
  const w = use(world());
  setCred('svc', 'api_key', 'synthetic-backup');
  const outside = join(w.dir, 'safe');
  fs.mkdirSync(outside, { mode: 0o700 });
  const target = join(outside, 'k.bak');
  const ok = await capture(runKey, ['backup', '--to', target]);
  assert.equal(ok.code, 0);
  assert.deepEqual(ok.envelope.result, { backedUp: true, path: target });
  assert.equal(fs.readFileSync(target, 'utf8'), fs.readFileSync(w.key, 'utf8'));
  assert.equal(fs.statSync(target).mode & 0o777, 0o600);
  assert.ok(!(ok.out + ok.err).includes(keyText(w)));
  assert.equal((await capture(runKey, ['backup', '--to', target])).envelope.error.code, 'USAGE', 'O_EXCL: no overwrite');
  assert.equal((await capture(runKey, ['backup', '--to', join(dirname(w.db), 'k.bak')])).envelope.error.code, 'STORE_SECURITY');
  const dropbox = join(w.dir, 'Dropbox', 'sub');
  fs.mkdirSync(dropbox, { recursive: true });
  assert.equal((await capture(runKey, ['backup', '--to', join(dropbox, 'k.bak')])).envelope.error.code, 'STORE_SECURITY');
  assert.equal(fs.existsSync(join(dropbox, 'k.bak')), false);
  fs.symlinkSync(join(outside, 'elsewhere'), join(outside, 'link.bak'));
  assert.notEqual((await capture(runKey, ['backup', '--to', join(outside, 'link.bak')])).code, 0, 'no-follow');
  assert.equal(fs.existsSync(join(outside, 'elsewhere')), false);
  for (const args of [['backup'], ['backup', '--to'], ['rotate', 'x'], ['unknown']]) assert.equal((await capture(runKey, args)).code, 2);
});

// ---- 3 (hardening): no silent plaintext ----------------------------------------------------------------------------

test('when no key can be created a write fails with KEY_UNAVAILABLE unless LMCONN_ALLOW_PLAINTEXT=1', { skip: (!posix || isRoot) && 'needs an unprivileged POSIX user (read-only directory)' }, () => {
  const w = use(world());
  legacyDb(w, [['old', 'api_key', 'synthetic-old']]);
  fs.mkdirSync(w.cfg, { mode: 0o500 }); // read-only key location, like a read-only filesystem
  assert.equal(codeOf(() => setCred('svc', 'api_key', 'synthetic-denied')), 'KEY_UNAVAILABLE');
  assert.equal(codeOf(() => putPolicy('svc', { noReveal: false, kind: 'legacy', issuer: null, owner: null, origins: [], refresh: null })), 'KEY_UNAVAILABLE');
  assert.equal(rows(w).length, 1, 'nothing was written');
  assert.equal(getCred('old', 'api_key'), 'synthetic-old', 'reads of legacy rows still work');
  use(w, { LMCONN_ALLOW_PLAINTEXT: '1' });
  setCred('svc', 'api_key', 'synthetic-optin');
  assert.equal(rows(w).find(r => r.service === 'svc').value, 'synthetic-optin');
  assert.equal(codeOf(() => setCred('svc', 'api_key', 'lmc1:looks-like-ciphertext')), 'KEY_UNAVAILABLE');
  fs.chmodSync(w.cfg, 0o700);
  use(w, { LMCONN_ALLOW_PLAINTEXT: '1' });
  setCred('svc', 'other', 'synthetic-now-encrypted');
  assert.ok(rows(w).find(r => r.field === 'other').value.startsWith('lmc1:'), 'a key that can be created is always used');
  const sealed = use(world(), { LMCONN_ALLOW_PLAINTEXT: '1' });
  setCred('s', 'f', 'synthetic-sealed-first');
  fs.unlinkSync(sealed.key);
  assert.equal(codeOf(() => setCred('s', 'g', 'synthetic-never-plain')), 'KEY_MISSING', 'ALLOW_PLAINTEXT never applies once ciphertext exists');
});

test('an OAuth refresh write with the key gone fails closed and writes nothing', async () => {
  const w = use(world());
  closeDb(w.db);
  const config = { tokenUrl: 'https://token.invalid/rotate', clientId: 'client', clientSecret: 'synthetic-client-secret', authStyle: 'body' };
  const stored = lmconn(w, ['cred', 'store', 'refreshing', '--stdin'], { kind: 'oauth2', accessToken: 'synthetic-old-access', refreshToken: 'synthetic-old-refresh', scopes: ['read'], owner: 'o', source: 'lmauth', issuer: 'https://issuer.invalid', allowedOrigins: ['https://api.invalid'], refresh: config, expiresAt: '2000-01-01' });
  assert.equal(stored.code, 0, stored.out + stored.err);
  fs.unlinkSync(w.key);
  const before = fs.readFileSync(w.db);
  let calls = 0;
  await assert.rejects(request(parseArgs(['request', 'https://api.invalid/use', '--auth', 'refreshing']), async () => { calls++; return Response.json({ access_token: 'synthetic-new-access' }); }), err => err.code === 'KEY_MISSING');
  assert.equal(calls, 0, 'no network call without the key');
  assert.ok(before.equals(fs.readFileSync(w.db)), 'database untouched');
  assert.equal(fs.existsSync(w.key), false);
});

// ---- environment key and Windows stance --------------------------------------------------------------------------------

test('LMCONN_KEY is removed from process.env on first read and never reaches a child process', () => {
  const w = world();
  const key = randomBytes(32).toString('base64');
  const program = `import { setCred, getCred } from ${JSON.stringify(new URL('../src/creds.js', import.meta.url).href)};
    import { spawnSync } from 'node:child_process';
    setCred('svc', 'api_key', 'synthetic-child-env');
    const child = spawnSync(process.execPath, ['-e', 'process.stdout.write(String(process.env.LMCONN_KEY))'], { encoding: 'utf8' });
    process.stdout.write(JSON.stringify({ own: process.env.LMCONN_KEY ?? null, child: child.stdout, value: getCred('svc', 'api_key') }));`;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', program], { env: childEnv(w, { LMCONN_KEY: key }), encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), { own: null, child: 'undefined', value: 'synthetic-child-env' });
  assert.equal(fs.existsSync(w.key), false);
  const cliRun = lmconn(w, ['cred', 'get', 'svc', 'api_key', '--reveal'], undefined, { LMCONN_KEY: key });
  assert.equal(cliRun.envelope.result.value, 'synthetic-child-env');
});

test('Windows stance: a file-based key fails closed with STORE_SECURITY, LMCONN_KEY works (simulated platform)', () => {
  const w = world();
  const key = randomBytes(32).toString('base64');
  const program = `Object.defineProperty(process, 'platform', { value: 'win32' });
    const { setCred, getCred } = await import(${JSON.stringify(new URL('../src/creds.js', import.meta.url).href)});
    const attempt = fn => { try { fn(); return 'ok'; } catch (e) { return e.code; } };
    const file = attempt(() => setCred('svc', 'api_key', 'synthetic-win'));
    process.stdout.write(JSON.stringify({ file }));`;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', program], { env: childEnv(w), encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), { file: 'STORE_SECURITY' });
  assert.equal(fs.existsSync(w.key), false);
  const env = lmconn(w, ['cred', 'set', 'svc', 'api_key', '--stdin'], 'synthetic-win-env', { LMCONN_KEY: key });
  assert.equal(env.code, 0, env.out + env.err);
});

test('Windows only: the file-based key variant of the suite is not run on this platform', { skip: process.platform !== 'win32' ? 'Windows-only: file keys are refused there; Linux covers the simulated stance above' : false }, () => {
  const w = use(world());
  assert.equal(codeOf(() => setCred('svc', 'api_key', 'x')), 'STORE_SECURITY');
});

// ---- schema -----------------------------------------------------------------------------------------------------------------

test('the new operations are published in the cli.schema.v1 document with write access', async () => {
  const { schemaDocument } = await import('../src/schema.js');
  const doc = await schemaDocument();
  for (const name of ['cred_encrypt_existing', 'key_rotate', 'key_backup']) assert.equal(doc.operations.find(o => o.name === name)?.access, 'write', name);
  assert.deepEqual(doc.operations.find(o => o.name === 'key_backup').params.map(p => [p.name, p.occurs]), [['to', '1']]);
  const w = world();
  const call = lmconn(w, ['key_rotate', '--input-json', '{"data":true}']);
  assert.equal(call.code, 1);
  assert.equal(call.envelope.error.code, 'KEY_MISSING', 'rotating a store with no key is refused, not auto-created');
  assert.equal(fs.existsSync(w.key), false);
});
