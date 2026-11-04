// Credential store: one SQLite database, zero dependencies (node:sqlite).
// Secrets never appear on stdout of `cred list`; only `cred get --reveal`
// prints one, for piping into other commands.

import { DatabaseSync } from 'node:sqlite';
import { existsSync, lstatSync } from 'node:fs';
import { secureStorePath } from './store-path.js';
import { securityError } from './oauth-security.js';
import { homedir } from 'node:os';
import { join } from 'node:path';

export function dbPath() {
  if (process.env.LMCONN_DB) return process.env.LMCONN_DB;
  // Repo was renamed lmconnectors -> lmconn; keep reading the old store.
  const legacy = join(homedir(), '.lmconnectors', 'creds.db');
  const current = join(homedir(), '.lmconn', 'creds.db');
  if (!existsSync(current) && existsSync(legacy)) return legacy;
  return current;
}

// One cached connection per path: opening a DatabaseSync per call leaks a
// handle on every operation, and on Windows an open handle makes the file
// undeletable (EBUSY in test teardown). closeDb() exists for that teardown.
const cache = new Map();

function refuseWindowsProtected(db) {
  if (process.platform !== 'win32') return;
  const table = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='credential_policy'").get();
  if (table && db.prepare('SELECT document FROM credential_policy').all().some(row => JSON.parse(row.document).noReveal)) {
    throw securityError('Protected credential stores require native Windows ACL support', 'STORE_SECURITY');
  }
}

export function openDb(path = dbPath()) {
  if (process.env.LMCONN_STORE_MODE && !['legacy', 'broker'].includes(process.env.LMCONN_STORE_MODE)) throw securityError('Unknown credential store mode');
  const secured = secureStorePath(path, process.env.LMCONN_STORE_MODE === 'broker');
  const cached = cache.get(path);
  if (cached) {
    if (cached.identity.dev !== secured.identity.dev || cached.identity.ino !== secured.identity.ino) throw new Error('Credential store identity changed');
    refuseWindowsProtected(cached.db);
    return cached.db;
  }
  const db = new DatabaseSync(secured.file);
  try {
    refuseWindowsProtected(db);
    const st = lstatSync(secured.file);
    if (st.dev !== secured.identity.dev || st.ino !== secured.identity.ino) throw new Error('Credential store identity changed');
    db.exec(`PRAGMA secure_delete=ON;
      PRAGMA journal_mode=DELETE;
      CREATE TABLE IF NOT EXISTS creds (
        service TEXT NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL, updated_at TEXT NOT NULL,
        PRIMARY KEY (service, field)
      );
      CREATE TABLE IF NOT EXISTS credential_policy (service TEXT PRIMARY KEY, document TEXT NOT NULL);`);
    cache.set(path, { db, identity: secured.identity });
    return db;
  } catch (err) { db.close(); throw err; }
}

export function closeDb(path = dbPath()) {
  const db = cache.get(path);
  if (db) { db.db.close(); cache.delete(path); }
}

export function setCred(service, field, value, db = openDb()) {
  db.prepare(
    'INSERT INTO creds (service, field, value, updated_at) VALUES (?, ?, ?, ?) ' +
    'ON CONFLICT (service, field) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at',
  ).run(service, field, value, new Date().toISOString());
}

export function getCred(service, field, db = openDb()) {
  const row = db.prepare('SELECT value FROM creds WHERE service = ? AND field = ?').get(service, field);
  return row ? row.value : null;
}

// Names and timestamps only, never values.
export function listCreds(db = openDb()) {
  return db.prepare('SELECT service, field, updated_at FROM creds ORDER BY service, field').all();
}

export function deleteCred(service, field, db = openDb()) {
  const r = db.prepare('DELETE FROM creds WHERE service = ? AND field = ?').run(service, field);
  return r.changes > 0;
}
