// Encryption at rest for the credential store (AES-256-GCM, node:crypto only).
// Instance key (keystore.js) wraps data keys (table data_keys); data keys encrypt creds.value as
//   lmc1:<keyId>:<b64 nonce 12 B>:<b64 ciphertext||tag 16 B>
// with AAD = u8 version, len||service, len||field, len||keyId, u64 gen (binds a value to its row and write).
// Once sealed (meta encrypted_required), plaintext rows and unauthenticated policy rows are STORE_TAMPERED.
// Nothing here puts a key, secret or ciphertext into an error message. Design: docs/encryption-at-rest.md.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { securityError } from './oauth-security.js';
import { loadKeys, createKeys, stageRotation, removePrevKey, strictBase64 } from './keystore.js';

export const SAFE_CODES = ['CREDENTIAL_POLICY', 'STORE_SECURITY', 'STORE_TAMPERED', 'STORE_VERSION', 'KEY_MISSING', 'KEY_INVALID', 'KEY_UNAVAILABLE', 'KEY_MISMATCH', 'DECRYPT_FAILED'];
const SCHEMA_VERSION = 2;
const fail = (code, message) => securityError(message, code);
const tampered = (message = 'Credential store failed its integrity check') => fail('STORE_TAMPERED', message);
const decryptFailed = () => fail('DECRYPT_FAILED', 'Credential could not be decrypted (wrong key, tampered or moved value)');

export const SCHEMA = `
  CREATE TABLE IF NOT EXISTS creds (
    service TEXT NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL, updated_at TEXT NOT NULL, gen INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (service, field)
  );
  CREATE TABLE IF NOT EXISTS credential_policy (service TEXT PRIMARY KEY, document TEXT NOT NULL, mac TEXT);
  CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS data_keys (id TEXT PRIMARY KEY, wrapped TEXT NOT NULL, ik_id TEXT NOT NULL, created TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 0);
  CREATE UNIQUE INDEX IF NOT EXISTS data_keys_one_active ON data_keys(active) WHERE active = 1;`;
// An older lmconn inserting or updating plaintext into a sealed store is refused by SQLite itself.
const SEAL_TRIGGERS = ['INSERT', 'UPDATE'].map(op => `CREATE TRIGGER IF NOT EXISTS lmconn_sealed_${op.toLowerCase()} BEFORE ${op} ON creds
  WHEN substr(NEW.value, 1, 5) != 'lmc1:' BEGIN SELECT RAISE(ABORT, 'encrypted store: plaintext refused'); END;`).join('\n');

// Path of each open database, for the key-directory separation check and rotation.
const files = new WeakMap();
export const registerDb = (db, file) => files.set(db, file);
const fileOf = db => files.get(db) ?? null;

// Upgrades a store created by an older lmconn in place (columns only; nothing is encrypted here).
export function migrateSchema(db) {
  if (db.prepare('PRAGMA user_version').get().user_version > SCHEMA_VERSION) throw fail('STORE_VERSION', 'Credential store was written by a newer lmconn');
  const columns = table => db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
  if (columns('creds').includes('gen') && columns('credential_policy').includes('mac')) return;
  db.exec('BEGIN IMMEDIATE');
  try {
    if (!columns('creds').includes('gen')) db.exec('ALTER TABLE creds ADD COLUMN gen INTEGER NOT NULL DEFAULT 0');
    if (!columns('credential_policy').includes('mac')) db.exec('ALTER TABLE credential_policy ADD COLUMN mac TEXT');
    db.exec('COMMIT');
  } catch (err) { db.exec('ROLLBACK'); throw err; }
}

const getMeta = (db, k) => db.prepare('SELECT v FROM meta WHERE k = ?').get(k)?.v ?? null;
const setMeta = (db, k, v) => db.prepare('INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v').run(k, v);
const isCipher = value => typeof value === 'string' && value.startsWith('lmc1:');
const cipherKeyId = value => value.split(':')[1];
const nowIso = () => new Date().toISOString();

export function storeState(db) {
  const sealed = !!(getMeta(db, 'encrypted_required') !== null || getMeta(db, 'policy_set_mac') !== null ||
    db.prepare('PRAGMA user_version').get().user_version >= SCHEMA_VERSION ||
    db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = 'lmconn_sealed_insert'").get());
  return { sealed, required: sealed || process.env.LMCONN_STORE_MODE === 'broker' };
}

// ---- primitives -------------------------------------------------------------------------------

const frame = (...parts) => Buffer.concat(parts.flatMap(part => {
  const bytes = Buffer.from(String(part)), length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return [length, bytes];
}));
function valueAad(service, field, keyId, gen) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(gen));
  return Buffer.concat([Buffer.from([1]), frame(service, field, keyId), counter]);
}
const wrapAad = id => frame('data_keys', id);

function gcmSeal(key, aad, plain) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  const data = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
  return `${nonce.toString('base64')}:${data.toString('base64')}`;
}
// Strict: nonce exactly 12 bytes, at least a full 16-byte tag, canonical base64. Anything else is DECRYPT_FAILED.
function gcmOpen(key, aad, nonceText, dataText) {
  const nonce = strictBase64(nonceText, 12), data = strictBase64(dataText);
  if (!nonce || !data || data.length < 16) throw decryptFailed();
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    decipher.setAAD(aad);
    decipher.setAuthTag(data.subarray(data.length - 16));
    return Buffer.concat([decipher.update(data.subarray(0, data.length - 16)), decipher.final()]);
  } catch { throw decryptFailed(); }
}

const macKey = ik => Buffer.from(crypto.hkdfSync('sha256', ik, Buffer.alloc(0), 'lmconn policy mac', 32));
const mac = (key, ...parts) => crypto.createHmac('sha256', key).update(frame(...parts)).digest('base64');
const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

// ---- keys -------------------------------------------------------------------------------------

function needKeys(db) {
  const keys = loadKeys(fileOf(db));
  if (!keys) throw fail('KEY_MISSING', 'Encryption key not found; the store holds encrypted credentials');
  return keys;
}
function pickIk(keys, id) {
  if (keys.current.id === id) return keys.current.key;
  if (keys.prev?.id === id) return keys.prev.key;
  throw fail('KEY_MISMATCH', 'The encryption key does not match this store');
}

const dekCache = new Map();
function unwrapDek(row, keys) {
  const cacheKey = `${row.id}|${row.ik_id}|${row.wrapped}`;
  if (dekCache.has(cacheKey)) return dekCache.get(cacheKey);
  const parts = row.wrapped.split(':');
  if (parts.length !== 3 || parts[0] !== 'lmw1') throw decryptFailed();
  const key = gcmOpen(pickIk(keys, row.ik_id), wrapAad(row.id), parts[1], parts[2]);
  if (key.length !== 32) throw decryptFailed();
  dekCache.set(cacheKey, key);
  return key;
}
function insertDek(db, keys, active) {
  const key = crypto.randomBytes(32), id = crypto.randomBytes(8).toString('hex');
  const wrapped = `lmw1:${gcmSeal(keys.current.key, wrapAad(id), key)}`;
  db.prepare('INSERT INTO data_keys (id, wrapped, ik_id, created, active) VALUES (?, ?, ?, ?, ?)').run(id, wrapped, keys.current.id, nowIso(), active ? 1 : 0);
}
function activeDek(db, keys) {
  let row = db.prepare('SELECT id, wrapped, ik_id FROM data_keys WHERE active = 1').get();
  if (!row) {
    // One statement under a unique index on the active marker: the loser of a race re-reads the winner's key.
    try { insertDek(db, keys, true); } catch (err) { if (!/UNIQUE|constraint/i.test(String(err?.message))) throw err; }
    row = db.prepare('SELECT id, wrapped, ik_id FROM data_keys WHERE active = 1').get();
  }
  return { id: row.id, key: unwrapDek(row, keys) };
}
const rotationPending = (db, keys) => !!db.prepare('SELECT 1 FROM data_keys WHERE ik_id != ? LIMIT 1').get(keys.current.id) ||
  (getMeta(db, 'mac_ik_id') ?? keys.current.id) !== keys.current.id;

function nextGen(db) {
  return Number(db.prepare("INSERT INTO meta (k, v) VALUES ('gen', '1') ON CONFLICT (k) DO UPDATE SET v = CAST(v AS INTEGER) + 1 RETURNING v").get().v);
}

// ---- policy authentication ---------------------------------------------------------------------

function refreshSetMac(db, keys) {
  const rows = db.prepare('SELECT service FROM credential_policy ORDER BY service').all();
  setMeta(db, 'mac_ik_id', keys.current.id);
  setMeta(db, 'policy_set_mac', mac(macKey(keys.current.key), 'set', getMeta(db, 'encrypted_required') ?? '', JSON.stringify(rows.map(r => r.service))));
}
function remacPolicies(db, keys) {
  const update = db.prepare('UPDATE credential_policy SET mac = ? WHERE service = ?'), mk = macKey(keys.current.key);
  for (const row of db.prepare('SELECT service, document FROM credential_policy').all()) update.run(mac(mk, 'policy', row.service, row.document), row.service);
  refreshSetMac(db, keys);
}

// Every policy row and the set of services must carry a valid MAC once the store is required.
export function verifyPolicies(db) {
  const state = storeState(db);
  if (!state.required) return;
  const rows = db.prepare('SELECT service, document, mac FROM credential_policy ORDER BY service').all();
  const setMac = getMeta(db, 'policy_set_mac');
  if (!rows.length && !setMac && !state.sealed) return;
  if (!setMac) throw tampered();
  const id = getMeta(db, 'mac_ik_id');
  if (!id) throw tampered();
  const mk = macKey(pickIk(needKeys(db), id));
  for (const row of rows) if (!same(row.mac, mac(mk, 'policy', row.service, row.document))) throw tampered('Credential policy failed its integrity check');
  if (!same(setMac, mac(mk, 'set', getMeta(db, 'encrypted_required') ?? '', JSON.stringify(rows.map(r => r.service))))) throw tampered('Credential policy failed its integrity check');
}

// BEGIN IMMEDIATE outside a transaction (no lock-upgrade deadlock between processes), a savepoint inside one.
function atomic(db, work) {
  const nested = db.isTransaction !== false;
  db.exec(nested ? 'SAVEPOINT lmatomic' : 'BEGIN IMMEDIATE');
  try { const result = work(); db.exec(nested ? 'RELEASE lmatomic' : 'COMMIT'); return result; }
  catch (err) { db.exec(nested ? 'ROLLBACK TO lmatomic; RELEASE lmatomic' : 'ROLLBACK'); throw err; }
}

function seal(db, keys) {
  atomic(db, () => {
    setMeta(db, 'encrypted_required', '1');
    remacPolicies(db, keys);
    db.exec(SEAL_TRIGGERS);
    db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
  });
}

// ---- writes -----------------------------------------------------------------------------------

const allowPlaintext = () => process.env.LMCONN_ALLOW_PLAINTEXT === '1';
const hasPlaintext = (db, service, field) => !!(service === undefined
  ? db.prepare("SELECT 1 FROM creds WHERE substr(value, 1, 5) != 'lmc1:' LIMIT 1").get()
  : db.prepare("SELECT 1 FROM creds WHERE substr(value, 1, 5) != 'lmc1:' AND NOT (service = ? AND field = ?) LIMIT 1").get(service, field));
const holdsCiphertext = db => !!(db.prepare('SELECT 1 FROM data_keys LIMIT 1').get() || db.prepare("SELECT 1 FROM creds WHERE substr(value, 1, 5) = 'lmc1:' LIMIT 1").get());

// Every write path calls this first. It may create the key (only a write command may), checks the key against the
// store (canary), makes sure an active data key exists and seals a store that holds no plaintext.
// Returns {plaintext: true} only when LMCONN_ALLOW_PLAINTEXT=1 and no key can be found or created.
export function prepareWrite(db, { service, field, forceEncrypt = false } = {}) {
  const state = storeState(db);
  let keys;
  try {
    keys = loadKeys(fileOf(db));
    if (!keys) {
      if (state.sealed || holdsCiphertext(db)) throw fail('KEY_MISSING', 'Encryption key not found; the store holds encrypted credentials');
      keys = createKeys(fileOf(db));
    }
  } catch (err) {
    if (!forceEncrypt && !state.required && allowPlaintext() && (err.code === 'KEY_UNAVAILABLE' || err.windowsFile)) return { plaintext: true };
    if (SAFE_CODES.includes(err.code)) throw err;
    throw fail('KEY_UNAVAILABLE', 'No encryption key is available; set LMCONN_KEY or LMCONN_KEY_FILE (LMCONN_ALLOW_PLAINTEXT=1 stores plaintext)');
  }
  if (rotationPending(db, keys)) throw fail('KEY_MISMATCH', 'Key rotation is incomplete; run lmconn key rotate to finish it');
  const canary = db.prepare('SELECT id, wrapped, ik_id FROM data_keys LIMIT 1').get();
  if (canary) unwrapDek(canary, keys); // a wrong key fails here, before it can create a mixed store
  const dek = activeDek(db, keys);
  if (!state.sealed && !hasPlaintext(db, service, field)) seal(db, keys);
  return { keys, dek, plaintext: false };
}

export function writeValue(db, service, field, value) {
  const write = prepareWrite(db, { service, field });
  const gen = nextGen(db);
  if (write.plaintext) {
    if (isCipher(value)) throw fail('KEY_UNAVAILABLE', 'A plaintext value may not start with the ciphertext prefix');
    return { value, gen };
  }
  const aad = valueAad(service, field, write.dek.id, gen);
  return { value: `lmc1:${write.dek.id}:${gcmSeal(write.dek.key, aad, Buffer.from(value, 'utf8'))}`, gen };
}

export function writePolicy(db, service, text) {
  const write = prepareWrite(db);
  atomic(db, () => {
    if (write.plaintext) db.prepare('INSERT INTO credential_policy (service, document, mac) VALUES (?, ?, NULL) ON CONFLICT (service) DO UPDATE SET document = excluded.document, mac = NULL').run(service, text);
    else {
      verifyPolicies(db);
      const code = storeState(db).required ? mac(macKey(write.keys.current.key), 'policy', service, text) : null;
      db.prepare('INSERT INTO credential_policy (service, document, mac) VALUES (?, ?, ?) ON CONFLICT (service) DO UPDATE SET document = excluded.document, mac = excluded.mac').run(service, text, code);
      if (code) refreshSetMac(db, write.keys);
    }
  });
}

// ---- reads ------------------------------------------------------------------------------------

function openValue(db, service, field, gen, stored) {
  const parts = stored.split(':');
  if (parts.length !== 4 || !/^[0-9a-f]{16}$/.test(parts[1])) throw decryptFailed();
  const row = db.prepare('SELECT id, wrapped, ik_id FROM data_keys WHERE id = ?').get(parts[1]);
  if (!row) throw decryptFailed();
  const plain = gcmOpen(unwrapDek(row, needKeys(db)), valueAad(service, field, parts[1], gen), parts[2], parts[3]);
  return plain.toString('utf8');
}

export function readValue(db, service, field) {
  const row = db.prepare('SELECT value, gen FROM creds WHERE service = ? AND field = ?').get(service, field);
  if (!row) return null;
  const state = storeState(db);
  if (state.required) verifyPolicies(db);
  if (isCipher(row.value)) return openValue(db, service, field, row.gen, row.value);
  if (state.required) throw tampered('Plaintext credential in an encrypted store; run cred encrypt-existing or restore a backup');
  return row.value;
}

// ---- migration and rotation --------------------------------------------------------------------

function syncFile(file) {
  const fd = fs.openSync(file, 'r+');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function syncDirectory(directory) {
  try { const fd = fs.openSync(directory, 'r'); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } } catch { /* best effort */ }
}

// Encrypts legacy plaintext rows (and with `all`, rows under older data keys), then seals the store.
// Preferred path: build a new database file holding only live data, fsync, rename over the old one (no old free pages,
// no plaintext in the new file's journal). Fallback (inPlace): one transaction, then VACUUM outside it.
// The caller closes the old connection afterwards.
export function encryptExisting(db, { all = false, inPlace = false } = {}) {
  const file = fileOf(db);
  const write = prepareWrite(db, { forceEncrypt: true });
  const { keys, dek } = write;
  const rows = db.prepare('SELECT service, field, value, updated_at, gen FROM creds ORDER BY service, field').all();
  const plain = rows.filter(r => !isCipher(r.value));
  if (storeState(db).sealed && plain.length) throw tampered('Plaintext credential in an encrypted store; restore a backup');
  const stale = all ? rows.filter(r => isCipher(r.value) && cipherKeyId(r.value) !== dek.id) : [];
  const result = { total: rows.length, encrypted: plain.length, reencrypted: stale.length, alreadyEncrypted: rows.length - plain.length - stale.length, rewritten: false };
  const retire = () => { if (all && !rotationPending(db, keys)) removePrevKey(keys); };
  const staleIds = new Set([...plain, ...stale].map(r => `${r.service}\0${r.field}`));
  if (!staleIds.size && storeState(db).sealed) {
    if (all) {
      const used = new Set(rows.map(r => cipherKeyId(r.value)));
      for (const k of db.prepare('SELECT id FROM data_keys WHERE active = 0').all()) if (!used.has(k.id)) db.prepare('DELETE FROM data_keys WHERE id = ?').run(k.id);
      retire();
    }
    return result;
  }
  const convert = (target, row) => {
    if (!staleIds.has(`${row.service}\0${row.field}`)) return { value: row.value, gen: row.gen };
    const text = isCipher(row.value) ? openValue(db, row.service, row.field, row.gen, row.value) : row.value;
    const gen = nextGen(target);
    return { value: `lmc1:${dek.id}:${gcmSeal(dek.key, valueAad(row.service, row.field, dek.id, gen), Buffer.from(text, 'utf8'))}`, gen };
  };
  db.exec('BEGIN IMMEDIATE');
  if (inPlace) {
    try {
      const update = db.prepare('UPDATE creds SET value = ?, gen = ? WHERE service = ? AND field = ?');
      for (const row of rows) if (staleIds.has(`${row.service}\0${row.field}`)) { const c = convert(db, row); update.run(c.value, c.gen, row.service, row.field); }
      seal(db, keys);
      if (all) db.prepare('DELETE FROM data_keys WHERE active = 0 AND id NOT IN (SELECT DISTINCT substr(value, 6, 16) FROM creds)').run();
      db.exec('COMMIT');
    } catch (err) { db.exec('ROLLBACK'); throw err; }
    db.exec('VACUUM');
    retire();
    return { ...result, rewritten: true };
  }
  const temp = path.join(path.dirname(file), `.${path.basename(file)}.migrate.${process.pid}.${crypto.randomBytes(6).toString('hex')}`);
  try {
    fs.closeSync(fs.openSync(temp, 'wx', 0o600));
    const out = new DatabaseSync(temp);
    try {
      out.exec('PRAGMA secure_delete=ON; PRAGMA journal_mode=DELETE;');
      out.exec(SCHEMA);
      out.exec('BEGIN');
      setMeta(out, 'gen', getMeta(db, 'gen') ?? '0');
      const insert = out.prepare('INSERT INTO creds (service, field, value, updated_at, gen) VALUES (?, ?, ?, ?, ?)');
      for (const row of rows) { const c = convert(out, row); insert.run(row.service, row.field, c.value, row.updated_at, c.gen); }
      const used = new Set(out.prepare('SELECT value FROM creds').all().map(r => cipherKeyId(r.value)));
      for (const k of db.prepare('SELECT * FROM data_keys').all()) {
        if (k.active || used.has(k.id)) out.prepare('INSERT INTO data_keys (id, wrapped, ik_id, created, active) VALUES (?, ?, ?, ?, ?)').run(k.id, k.wrapped, k.ik_id, k.created, k.active);
      }
      for (const p of db.prepare('SELECT service, document FROM credential_policy').all()) out.prepare('INSERT INTO credential_policy (service, document, mac) VALUES (?, ?, NULL)').run(p.service, p.document);
      seal(out, keys);
      out.exec('COMMIT');
    } finally { out.close(); }
    syncFile(temp);
    fs.renameSync(temp, file);
    syncDirectory(path.dirname(file));
  } catch (err) {
    try { fs.unlinkSync(temp); } catch { /* not created */ }
    try { db.exec('ROLLBACK'); } catch { /* ended */ }
    throw err;
  }
  db.exec('ROLLBACK'); // releases the lock on the replaced file; nothing was written to it
  if (all && !db.prepare('SELECT 1 FROM data_keys WHERE ik_id != ?').get(keys.current.id)) removePrevKey(keys);
  return { ...result, rewritten: true };
}

// Hygiene rotation: new IK, DEKs rewrapped, rows untouched. After a suspected leak use rotateData + encrypt-existing --all.
// Order: new key file fsynced and switched in (old key kept as .prev), DB rewrap committed, old key retired by the operator.
export function rotateKey(db, hook = () => {}) {
  let keys = needKeys(db);
  if (keys.source !== 'file') throw fail('KEY_UNAVAILABLE', 'Key rotation needs a key file; LMCONN_KEY cannot be rewritten');
  if (!rotationPending(db, keys)) { stageRotation(keys, hook); keys = needKeys(db); }
  db.exec('BEGIN IMMEDIATE');
  try {
    verifyPolicies(db);
    const update = db.prepare('UPDATE data_keys SET wrapped = ?, ik_id = ? WHERE id = ?');
    for (const row of db.prepare('SELECT id, wrapped, ik_id FROM data_keys').all()) {
      if (row.ik_id === keys.current.id) continue;
      const key = unwrapDek(row, keys);
      update.run(`lmw1:${gcmSeal(keys.current.key, wrapAad(row.id), key)}`, keys.current.id, row.id);
    }
    if (getMeta(db, 'policy_set_mac') !== null) remacPolicies(db, keys);
    db.exec('COMMIT');
  } catch (err) { db.exec('ROLLBACK'); throw err; }
  hook('db-committed');
}

// New active data key for new writes; old keys stay while any row names them.
export function rotateData(db) {
  const keys = needKeys(db);
  if (rotationPending(db, keys)) throw fail('KEY_MISMATCH', 'Key rotation is incomplete; run lmconn key rotate to finish it');
  db.exec('BEGIN IMMEDIATE');
  try {
    const canary = db.prepare('SELECT id, wrapped, ik_id FROM data_keys LIMIT 1').get();
    if (canary) unwrapDek(canary, keys);
    db.exec('UPDATE data_keys SET active = 0 WHERE active = 1');
    insertDek(db, keys, true);
    db.exec('COMMIT');
  } catch (err) { db.exec('ROLLBACK'); throw err; }
}
