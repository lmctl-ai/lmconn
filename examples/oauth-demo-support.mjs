import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { closeDb } from '../src/creds.js';

export async function withPrivateStore(action) {
  const directory = mkdtempSync(join(tmpdir(), 'lmconn-oauth-example-'));
  const previous = process.env.LMCONN_DB;
  process.env.LMCONN_DB = join(directory, 'creds.db');
  try { await action(); }
  finally {
    closeDb();
    if (previous === undefined) delete process.env.LMCONN_DB;
    else process.env.LMCONN_DB = previous;
    rmSync(directory, { recursive: true, force: true });
  }
}

export async function followAuthorization(idp, port, url) {
  idp.registerClient({ clientId: 'demo-client', clientSecret: 'synthetic-client-secret', redirectUris: [`http://127.0.0.1:${port}/callback`], authStyle: 'header' });
  const response = await fetch(url);
  await response.arrayBuffer();
}
