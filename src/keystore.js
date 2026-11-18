// Instance key (IK) for encryption at rest: sources, key-file handling, rotation and backup.
// Source order: LMCONN_KEY (base64), LMCONN_KEY_FILE, default ${XDG_CONFIG_HOME:-~/.config}/lmconn/instance.key.
// Key bytes never reach stdout, stderr, error text or a child process environment.
// Design and limits: docs/encryption-at-rest.md.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { homedir } from 'node:os';
import { securityError } from './oauth-security.js';
import { secureKeyDirectory } from './store-path.js';

const keyError = (code, message) => securityError(message, code);
const insecure = (message = 'Key file is not private or safe') => securityError(message, 'STORE_SECURITY');
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;

// LMCONN_KEY is read once and removed from process.env so no child inherits it.
let envKey; // undefined: never seen; {error: true}: invalid; {key}: loaded
export function resetKeyCache() { envKey = undefined; }

export const keyId = ik => crypto.createHash('sha256').update(ik).digest('hex').slice(0, 16);
const entry = key => ({ key, id: keyId(key) });

// Strict base64 (of exactly `length` bytes when given): no whitespace, no truncation, canonical padding.
export function strictBase64(text, length) {
  if (typeof text !== 'string' || text.length % 4 !== 0 || !B64.test(text)) return null;
  const bytes = Buffer.from(text, 'base64');
  return (length === undefined || bytes.length === length) && bytes.toString('base64') === text ? bytes : null;
}
const parseKey = text => {
  const key = strictBase64(text, 32);
  if (!key) throw keyError('KEY_INVALID', 'Encryption key must be 32 bytes of strict base64');
  return key;
};

const refuseRelative = name => { throw insecure(`${name} must be an absolute path`); };
export function keyFilePath() {
  const file = process.env.LMCONN_KEY_FILE;
  if (file) return path.isAbsolute(file) ? path.resolve(file) : refuseRelative('LMCONN_KEY_FILE');
  const xdg = process.env.XDG_CONFIG_HOME;
  if (xdg && !path.isAbsolute(xdg)) refuseRelative('XDG_CONFIG_HOME');
  return path.join(xdg || path.join(homedir(), '.config'), 'lmconn', 'instance.key');
}

function realDirectory(file) {
  const directory = path.dirname(path.resolve(file));
  try { return fs.realpathSync(directory); } catch { return directory; }
}
const within = (inner, outer) => inner === outer || inner.startsWith(outer.endsWith(path.sep) ? outer : outer + path.sep);
// Equal, inside, or containing: any of these puts the key next to (or into) the data it protects.
export const overlapping = (a, b) => { const x = realDirectory(a), y = realDirectory(b); return within(x, y) || within(y, x); };
export const insideDirectory = (file, other) => within(realDirectory(file), realDirectory(other));

const pause = ms => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

// Returns the key bytes, or null when the file (or its directory) does not exist. Loose modes are refused, not repaired:
// a key readable by others may already have been read.
function readKeyFile(file) {
  if (!fs.existsSync(path.dirname(file))) return null;
  secureKeyDirectory(path.dirname(file));
  for (let attempt = 0; ; attempt++) {
    let fd;
    try {
      try { fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0)); }
      catch (err) { if (err.code === 'ENOENT') return null; throw insecure(); }
      const st = fs.fstatSync(fd), named = fs.lstatSync(file);
      if (!st.isFile() || named.isSymbolicLink() || named.dev !== st.dev || named.ino !== st.ino) throw insecure();
      if (process.geteuid && st.uid !== process.geteuid()) throw insecure();
      if (st.mode & 0o177) throw insecure('Key file must not be readable or writable by others (mode 0600); rotate the key');
      // A concurrent creator briefly holds a second link to the temp file; wait it out.
      if (st.nlink !== 1) { if (attempt < 100) { pause(10); continue; } throw insecure(); }
      if (st.size > 256) throw keyError('KEY_INVALID', 'Encryption key file is invalid');
      return parseKey(fs.readFileSync(fd, 'utf8').replace(/\r?\n$/, ''));
    } finally { if (fd !== undefined) fs.closeSync(fd); }
  }
}

// -> {current: {key, id}, prev: {key, id}|null, source, file} or null when no key exists anywhere.
// Called at the top of the bin entry (before any command can spawn a child) and again by loadKeys.
// The key stays readable in /proc/PID/environ by the same uid; deleting only protects children.
export function consumeEnvKey() {
  if (process.env.LMCONN_KEY === undefined) return;
  const text = process.env.LMCONN_KEY;
  delete process.env.LMCONN_KEY;
  try { envKey = { key: parseKey(text) }; } catch { envKey = { error: true }; }
}

export function loadKeys(dbFile) {
  consumeEnvKey();
  if (envKey?.error) throw keyError('KEY_INVALID', 'LMCONN_KEY must be 32 bytes of strict base64');
  if (envKey) return { current: entry(envKey.key), prev: null, source: 'env', file: null };
  const file = keyFilePath();
  if (process.platform === 'win32') throw Object.assign(insecure('File-based keys need native Windows ACL support; use LMCONN_KEY'), { windowsFile: true });
  if (dbFile && overlapping(file, dbFile)) throw insecure('The key directory must not be inside, equal to or contain the database directory');
  const key = readKeyFile(file);
  if (!key) return null;
  const prev = readKeyFile(file + '.prev');
  return { current: entry(key), prev: prev ? entry(prev) : null, source: 'file', file };
}

function writeSecret(file, bytes, { exclusive = true } = {}) {
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | (exclusive ? fs.constants.O_EXCL : 0) | (fs.constants.O_NOFOLLOW || 0), 0o600);
  try { fs.fchmodSync(fd, 0o600); fs.writeSync(fd, bytes.toString('base64') + '\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function syncDirectory(directory) {
  try { const fd = fs.openSync(directory, 'r'); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } } catch { /* best effort */ }
}
const unavailable = err => (err.code === 'STORE_SECURITY' || err.code === 'KEY_INVALID' ? err
  : keyError('KEY_UNAVAILABLE', 'Encryption key could not be created'));

// Race-free: temp file in the same directory, fsync, link() into place; the loser re-reads the winner's key.
function linkSecret(file, bytes) {
  const directory = path.dirname(file);
  const temp = path.join(directory, `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}`);
  writeSecret(temp, bytes);
  try { fs.linkSync(temp, file); return true; }
  catch (err) { if (err.code === 'EEXIST') return false; throw err; }
  finally { try { fs.unlinkSync(temp); } catch { /* best effort */ } syncDirectory(directory); }
}

// Write commands only. Creates the key file (never a new key while a store holds ciphertext: the caller checks that).
export function createKeys(dbFile) {
  if (process.platform === 'win32') throw Object.assign(insecure('File-based keys need native Windows ACL support; use LMCONN_KEY'), { windowsFile: true });
  const file = keyFilePath();
  if (dbFile && overlapping(file, dbFile)) throw insecure('The key directory must not be inside, equal to or contain the database directory');
  let created = false;
  try { secureKeyDirectory(path.dirname(file)); created = linkSecret(file, crypto.randomBytes(32)); }
  catch (err) { throw unavailable(err); }
  const keys = loadKeys(dbFile);
  if (!keys) throw keyError('KEY_UNAVAILABLE', 'Encryption key could not be created');
  if (created) {
    process.stderr.write(`lmconn: created a new encryption key at ${file}\n` +
      'lmconn: BACK IT UP SEPARATELY from the credential database (lmconn key backup --to FILE). Losing it loses every stored credential.\n');
  }
  return keys;
}

// Key rotation, file side. Order: new key written and fsynced, old key kept as .prev, then the new key switched in.
// The caller commits the DB rewrap afterwards; readers pick the key by ik_id from the current file and .prev.
export function stageRotation(keys, hook = () => {}) {
  if (keys.source !== 'file') throw keyError('KEY_UNAVAILABLE', 'Key rotation needs a key file; LMCONN_KEY cannot be rewritten');
  const { file } = keys, directory = path.dirname(file), fresh = crypto.randomBytes(32);
  const temp = path.join(directory, `.${path.basename(file)}.new.${process.pid}.${crypto.randomBytes(6).toString('hex')}`);
  try { writeSecret(temp, fresh); } catch { throw keyError('KEY_UNAVAILABLE', 'New key could not be written'); }
  hook('new-key-written');
  const prev = file + '.prev';
  const abandon = err => {
    try { fs.unlinkSync(temp); } catch { /* already gone */ }
    return err.code?.startsWith('KEY_') || err.code === 'STORE_SECURITY' ? err : keyError('KEY_UNAVAILABLE', 'Key rotation failed');
  };
  try {
    if (!readKeyFile(prev)) linkSecret(prev, keys.current.key);
    if (!readKeyFile(prev)?.equals(keys.current.key)) throw keyError('KEY_UNAVAILABLE', 'instance.key.prev exists; finish the previous rotation with cred encrypt-existing --all first');
  } catch (err) { throw abandon(err); }
  hook('prev-written');
  try { fs.renameSync(temp, file); syncDirectory(directory); } catch (err) { throw abandon(err); }
  hook('key-switched');
}

export function removePrevKey(keys) {
  if (keys.source === 'file') try { fs.unlinkSync(keys.file + '.prev'); } catch { /* none */ }
}

// Sync folders are best effort: a key copied there next to the database defeats the point.
const SYNC_FRAGMENTS = ['dropbox', 'icloud', 'mobile documents', 'onedrive', 'my drive', 'google drive', 'googledrive', 'pcloud', 'nextcloud', 'syncthing'];
const SYNC_NAMES = ['box', 'mega', 'sync'];
const inSyncFolder = file => realDirectory(file).toLowerCase().split(path.sep).some(part => SYNC_NAMES.includes(part) || SYNC_FRAGMENTS.some(name => part.includes(name)));
export function backupKey(keys, target, dbFile) {
  if (process.platform === 'win32') throw Object.assign(insecure('Key backup needs native Windows ACL support'), { windowsFile: true });
  const file = path.resolve(target);
  if (!fs.existsSync(path.dirname(file))) throw keyError('USAGE', 'Backup target directory does not exist');
  if (insideDirectory(file, dbFile)) throw insecure('Refusing to back up the key into the database directory');
  if (inSyncFolder(file)) throw insecure('Refusing to back up the key into a sync folder');
  try { writeSecret(file, keys.current.key); }
  catch (err) { throw keyError(err.code === 'EEXIST' ? 'USAGE' : 'KEY_UNAVAILABLE', err.code === 'EEXIST' ? 'Backup target already exists' : 'Key backup could not be written'); }
  syncDirectory(path.dirname(file));
}

// External sealed record: sealed.<sha256 of the database realpath> in the key directory, content = HMAC over that
// path under HKDF(IK, "lmconn sealed"). It outlives any edit of the database, so stripping every marker inside the
// file cannot turn a sealed store back into a legacy one. Not written for LMCONN_KEY (no key directory) or Windows.
function sealedMac(ik, real) {
  const key = Buffer.from(crypto.hkdfSync('sha256', ik, Buffer.alloc(0), 'lmconn sealed', 32));
  return crypto.createHmac('sha256', key).update(real).digest('base64');
}
function sealedPath(dbFile) {
  const real = fs.realpathSync(dbFile);
  return { real, file: path.join(path.dirname(keyFilePath()), `sealed.${crypto.createHash('sha256').update(real).digest('hex')}`) };
}
export function sealedRecordExists(dbFile) {
  if (process.platform === 'win32' || !dbFile) return false;
  try { fs.lstatSync(sealedPath(dbFile).file); return true; } catch (err) { if (err.code === 'ENOENT') return false; throw insecure(); }
}
export function sealedRecordValid(keys, dbFile) {
  const { real, file } = sealedPath(dbFile);
  let text;
  try { text = fs.readFileSync(file, 'utf8').trim(); } catch { return false; }
  return [keys.current, keys.prev].some(k => k && text === sealedMac(k.key, real));
}
export function writeSealedRecord(keys, dbFile) {
  if (keys.source !== 'file' || process.platform === 'win32') return;
  const { real, file } = sealedPath(dbFile);
  try { if (fs.readFileSync(file, 'utf8').trim() === sealedMac(keys.current.key, real)) return; } catch { /* write it */ }
  const temp = path.join(path.dirname(file), `.sealed.${process.pid}.${crypto.randomBytes(6).toString('hex')}`);
  try {
    secureKeyDirectory(path.dirname(file));
    const fd = fs.openSync(temp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
    try { fs.fchmodSync(fd, 0o600); fs.writeSync(fd, sealedMac(keys.current.key, real) + '\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(temp, file);
    syncDirectory(path.dirname(file));
  } catch (err) {
    try { fs.unlinkSync(temp); } catch { /* none */ }
    throw err.code === 'STORE_SECURITY' ? err : keyError('KEY_UNAVAILABLE', 'The sealed record could not be written next to the key');
  }
}
