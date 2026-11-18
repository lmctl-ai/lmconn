// Encryption at rest for the credential store (AES-256-GCM, node:crypto only).
// Instance key (keystore.js) wraps data keys (table data_keys); data keys encrypt creds.value as
//   lmc1:<keyId>:<b64 nonce 12 B>:<b64 ciphertext||tag 16 B>
// with AAD = u8 version, len||service, len||field, len||keyId (binds a value to its row; not to its freshness).
// A store is required (plaintext rows and policy rows without a valid MAC are STORE_TAMPERED) when ANY of: the meta
// marker, a data key, a lmc1 value, or the external sealed record in the key directory exists.
// Nothing here puts a key, secret or ciphertext into an error message. Design: docs/encryption-at-rest.md.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { securityError } from './oauth-security.js';
import { loadKeys, createKeys, stageRotation, removePrevKey, strictBase64, sealedRecordExists, sealedRecordValid, writeSealedRecord, recordCapable } from './keystore.js';

export const isBusy = err => err?.errcode === 5 || /database is locked/i.test(String(err?.message));
export const SAFE_CODES = ['STORE_BUSY', 'CREDENTIAL_POLICY', 'STORE_SECURITY', 'STORE_TAMPERED', 'STORE_VERSION', 'KEY_MISSING', 'KEY_INVALID', 'KEY_UNAVAILABLE', 'KEY_MISMATCH', 'DECRYPT_FAILED'];
const SCHEMA_VERSION = 2;
const fail = (code, message) => securityError(message, code);
const tampered = (message = 'Credential store failed its integrity check') => fail('STORE_TAMPERED', message);
const decryptFailed = () => fail('DECRYPT_FAILED', 'Credential could not be decrypted (wrong key, tampered or moved value)');

export const SCHEMA = `
  CREATE TABLE IF NOT EXISTS creds (
    service TEXT NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL, updated_at TEXT NOT NULL,
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
  if (columns('credential_policy').includes('mac')) return;
  db.exec('BEGIN IMMEDIATE');
  try {
    if (!columns('credential_policy').includes('mac')) db.exec('ALTER TABLE credential_policy ADD COLUMN mac TEXT');
    db.exec('COMMIT');
  } catch (err) { db.exec('ROLLBACK'); throw err; }
}

const getMeta = (db, k) => db.prepare('SELECT v FROM meta WHERE k = ?').get(k)?.v ?? null;
const setMeta = (db, k, v) => db.prepare('INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v').run(k, v);
const isCipher = value => typeof value === 'string' && value.startsWith('lmc1:');
const cipherKeyId = value => value.split(':')[1];
const nowIso = () => new Date().toISOString();

// Sealed state never lives only inside the database: data keys, ciphertext and the sealed record in the key
// directory all count, so an attacker who can write the file (but not the key directory) cannot strip it.
export function storeState(db) {
  const inDb = !!(getMeta(db, 'encrypted_required') !== null || getMeta(db, 'policy_set_mac') !== null ||
    db.prepare('PRAGMA user_version').get().user_version >= SCHEMA_VERSION ||
    db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = 'lmconn_sealed_insert'").get() ||
    db.prepare('SELECT 1 FROM data_keys LIMIT 1').get() ||
    db.prepare("SELECT 1 FROM creds WHERE substr(value, 1, 5) = 'lmc1:' LIMIT 1").get());
  const sealed = inDb || sealedRecordExists(fileOf(db));
  return { sealed, inDb, required: sealed || process.env.LMCONN_STORE_MODE === 'broker' };
}

// The external record is written only after the sealing transaction has committed, never inside it: a rollback or a
// crash must not leave a record behind for a store that is still legacy. A crash between commit and this call leaves a
// sealed database without a record; the next write command regenerates it (idempotent, same path-derived name).
function ensureRecord(db, keys) {
  if (db.isTransaction !== false || !storeState(db).inDb) return;
  writeSealedRecord(keys, fileOf(db));
}
// Callers that own an outer transaction call this right after their COMMIT.
export function afterCommit(db) {
  try {
    if (db.isTransaction !== false) return;
    const keys = loadKeys(fileOf(db));
    if (keys) ensureRecord(db, keys);
  } catch { /* committed already; the next write command regenerates the record */ }
}
const notProven = new WeakSet();
function warnUnproven(db) {
  const state = storeState(db);
  if (!state.inDb || !recordCapable() || notProven.has(db) || sealedRecordExists(fileOf(db))) return;
  notProven.add(db);
  warn('the store is sealed but its external sealed record is missing, so it is not externally proven; the next write command recreates it.');
}

// ---- primitives -------------------------------------------------------------------------------

const frame = (...parts) => Buffer.concat(parts.flatMap(part => {
  const bytes = Buffer.from(String(part)), length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return [length, bytes];
}));
function valueAad(service, field, keyId) {
  return Buffer.concat([Buffer.from([1]), frame(service, field, keyId)]);
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

// The sealed record is written inside the sealing transaction, so another process can briefly see the record before
// the commit. Taking and releasing the write lock waits for that transaction, then the check is repeated once.
function settle(db) {
  if (db.isTransaction !== false) return false;
  db.exec('BEGIN IMMEDIATE');
  db.exec('ROLLBACK');
  return true;
}

// Every policy row and the set of services must carry a valid MAC once the store is required.
export function verifyPolicies(db) {
  try { verifyOnce(db); } catch (err) { if (err.code !== 'STORE_TAMPERED' || !settle(db)) throw err; verifyOnce(db); }
}
function verifyOnce(db) {
  const state = storeState(db);
  if (!state.required) return;
  warnUnproven(db);
  const rows = db.prepare('SELECT service, document, mac FROM credential_policy ORDER BY service').all();
  const setMac = getMeta(db, 'policy_set_mac');
  if (!rows.length && !setMac && !state.sealed) return;
  if (!setMac) throw tampered();
  const id = getMeta(db, 'mac_ik_id');
  if (!id) throw tampered();
  const keys = needKeys(db);
  if (sealedRecordExists(fileOf(db)) && !sealedRecordValid(keys, fileOf(db))) throw fail('KEY_MISMATCH', 'The key does not match the sealed record of this store');
  const mk = macKey(pickIk(keys, id));
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
    const adopted = db.prepare('SELECT service FROM credential_policy WHERE mac IS NULL').all().map(r => r.service);
    if (adopted.length && keys.source === 'env') warn(`LMCONN_KEY mode cannot prove this store was never tampered with: sealing adopted ${adopted.length} unauthenticated policy document(s) (${adopted.join(', ')}) and signed them. Check them, and prefer LMCONN_KEY_FILE for a long-lived store.`);
    setMeta(db, 'encrypted_required', '1');
    remacPolicies(db, keys);
    db.exec(SEAL_TRIGGERS);
    db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
  });
}

// ---- writes -----------------------------------------------------------------------------------

const allowPlaintext = () => process.env.LMCONN_ALLOW_PLAINTEXT === '1';
const warn = text => process.stderr.write(`lmconn: ${text}\n`);

// Every write path calls this first. It may create the key (only a write command may), checks the key against the
// store (canary), makes sure an active data key exists and, for a store that is not yet sealed, encrypts any legacy
// plaintext rows in place and seals it, so a store is never half plaintext and half ciphertext.
// Returns {plaintext: true} only when LMCONN_ALLOW_PLAINTEXT=1 and no key can be found or created.
export function prepareWrite(db, { forceEncrypt = false, upgrade = true } = {}) {
  const state = storeState(db);
  let keys;
  try {
    keys = loadKeys(fileOf(db));
    if (!keys) {
      if (state.sealed) throw fail('KEY_MISSING', 'Encryption key not found; the store holds encrypted credentials');
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
  if (state.sealed || !upgrade) { const dek = activeDek(db, keys); if (state.sealed) ensureRecord(db, keys); return { keys, dek, plaintext: false }; }
  const result = atomic(db, () => {
    const dek = activeDek(db, keys);
    const legacy = db.prepare("SELECT service, field, value FROM creds WHERE substr(value, 1, 5) != 'lmc1:'").all();
    const update = db.prepare('UPDATE creds SET value = ? WHERE service = ? AND field = ?');
    for (const row of legacy) update.run(sealValue(dek, row.service, row.field, row.value), row.service, row.field);
    seal(db, keys);
    db.prepare("DELETE FROM meta WHERE k = 'plaintext_written'").run();
    if (legacy.length) warn(`${legacy.length} plaintext credential(s) were encrypted in place and the store is now sealed (no plaintext allowed). Run cred encrypt-existing to also rewrite the file and drop old plaintext pages.`);
    return { keys, dek, plaintext: false };
  });
  ensureRecord(db, keys);
  return result;
}

const sealValue = (dek, service, field, text) =>
  `lmc1:${dek.id}:${gcmSeal(dek.key, valueAad(service, field, dek.id), Buffer.from(text, 'utf8'))}`;

export function writeValue(db, service, field, value) {
  const write = prepareWrite(db);
  if (write.plaintext) {
    if (isCipher(value)) throw fail('KEY_UNAVAILABLE', 'A plaintext value may not start with the ciphertext prefix');
    warn('LMCONN_ALLOW_PLAINTEXT=1: this credential was stored as PLAINTEXT because no encryption key is available. The next encrypted write will encrypt every plaintext row in place.');
    setMeta(db, 'plaintext_written', '1');
    return value;
  }
  return sealValue(write.dek, service, field, value);
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

function openValue(db, service, field, stored) {
  const parts = stored.split(':');
  if (parts.length !== 4 || !/^[0-9a-f]{16}$/.test(parts[1])) throw decryptFailed();
  const row = db.prepare('SELECT id, wrapped, ik_id FROM data_keys WHERE id = ?').get(parts[1]);
  if (!row) throw decryptFailed();
  const plain = gcmOpen(unwrapDek(row, needKeys(db)), valueAad(service, field, parts[1]), parts[2], parts[3]);
  return plain.toString('utf8');
}

export function readValue(db, service, field, settled = false) {
  const row = db.prepare('SELECT value FROM creds WHERE service = ? AND field = ?').get(service, field);
  if (!row) return null;
  const state = storeState(db);
  if (state.required) verifyPolicies(db);
  if (isCipher(row.value)) return openValue(db, service, field, row.value);
  if (state.required && !settled && settle(db)) return readValue(db, service, field, true);
  if (state.required) throw tampered(`Plaintext value in an encrypted store at service ${JSON.stringify(service)}, field ${JSON.stringify(field)}; repair with cred delete SERVICE FIELD or overwrite it with cred set`);
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
  const wasSealed = storeState(db).sealed;
  db.exec('BEGIN IMMEDIATE'); // the data key and every row change commit together or not at all
  let open = true;
  const finish = sql => { open = false; db.exec(sql); };
  try {
    const { keys, dek } = prepareWrite(db, { forceEncrypt: true, upgrade: false });
    const rows = db.prepare('SELECT service, field, value, updated_at FROM creds ORDER BY service, field').all();
    const plain = rows.filter(r => !isCipher(r.value));
    if (wasSealed && plain.length) throw tampered(`Plaintext credential in an encrypted store: service ${JSON.stringify(plain[0].service)}, field ${JSON.stringify(plain[0].field)}; delete it (cred delete SERVICE FIELD) and set it again`);
    const stale = all ? rows.filter(r => isCipher(r.value) && cipherKeyId(r.value) !== dek.id) : [];
    const result = { total: rows.length, encrypted: plain.length, reencrypted: stale.length, alreadyEncrypted: rows.length - plain.length - stale.length, rewritten: false };
    const retire = () => { if (all && !rotationPending(db, keys)) removePrevKey(keys); };
    const staleIds = new Set([...plain, ...stale].map(r => `${r.service}\0${r.field}`));
    if (!staleIds.size && getMeta(db, 'encrypted_required') !== null) {
      if (all) {
        const used = new Set(rows.map(r => cipherKeyId(r.value)));
        for (const k of db.prepare('SELECT id FROM data_keys WHERE active = 0').all()) if (!used.has(k.id)) db.prepare('DELETE FROM data_keys WHERE id = ?').run(k.id);
      }
      finish('COMMIT');
      retire();
      return result;
    }
    const convert = row => {
      if (!staleIds.has(`${row.service}\0${row.field}`)) return row.value;
      return sealValue(dek, row.service, row.field, isCipher(row.value) ? openValue(db, row.service, row.field, row.value) : row.value);
    };
    const runInPlace = () => {
      const update = db.prepare('UPDATE creds SET value = ? WHERE service = ? AND field = ?');
      for (const row of rows) if (staleIds.has(`${row.service}\0${row.field}`)) update.run(convert(row), row.service, row.field);
      seal(db, keys);
      if (all) db.prepare('DELETE FROM data_keys WHERE active = 0 AND id NOT IN (SELECT DISTINCT substr(value, 6, 16) FROM creds)').run();
      finish('COMMIT');
      writeSealedRecord(keys, file);
      db.exec('VACUUM');
      retire();
      return { ...result, rewritten: true };
    };
    if (inPlace) return runInPlace();
    const temp = path.join(path.dirname(file), `.${path.basename(file)}.migrate.${process.pid}.${crypto.randomBytes(6).toString('hex')}`);
    try {
      fs.closeSync(fs.openSync(temp, 'wx', 0o600));
      const out = new DatabaseSync(temp);
      try {
        out.exec('PRAGMA secure_delete=ON; PRAGMA journal_mode=DELETE;');
        out.exec(SCHEMA);
        out.exec('BEGIN');
        const insert = out.prepare('INSERT INTO creds (service, field, value, updated_at) VALUES (?, ?, ?, ?)');
        for (const row of rows) insert.run(row.service, row.field, convert(row), row.updated_at);
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
      // Windows cannot rename over a file this process holds open: fall back to one transaction plus VACUUM.
      if (['EPERM', 'EBUSY', 'EACCES'].includes(err.code)) return runInPlace();
      throw err;
    }
    finish('ROLLBACK'); // releases the lock on the replaced file; nothing was written to it
    writeSealedRecord(keys, file); // after the new file is committed and in place
    if (all && !db.prepare('SELECT 1 FROM data_keys WHERE ik_id != ?').get(keys.current.id)) removePrevKey(keys);
    return { ...result, rewritten: true };
  } catch (err) {
    if (open) { try { db.exec('ROLLBACK'); } catch { /* ended */ } }
    throw err;
  }
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
  if (storeState(db).inDb) writeSealedRecord(keys, fileOf(db));
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
