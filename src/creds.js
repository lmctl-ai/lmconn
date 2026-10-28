// Credential store: one SQLite database, zero dependencies (node:sqlite).
// Secrets never appear on stdout of `cred list`; only `cred get --reveal`
// prints one, for piping into other commands.

import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, chmodSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

export function dbPath() {
  return process.env.LMCONN_DB || join(homedir(), '.lmconnectors', 'creds.db');
}

export function openDb(path = dbPath()) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(path);
  db.exec(`CREATE TABLE IF NOT EXISTS creds (
    service TEXT NOT NULL,
    field TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (service, field)
  )`);
  try { chmodSync(path, 0o600); } catch { /* best effort */ }
  return db;
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
