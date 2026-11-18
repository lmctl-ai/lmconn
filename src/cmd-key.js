// key area: rotate the instance key or its data keys, back the key up. Key bytes are never printed.
import { openDb, dbPath } from './creds.js';
import { emit, ok, emitFail } from './result.js';
import { rotateKey, rotateData, SAFE_CODES } from './crypto-store.js';
import { loadKeys, backupKey } from './keystore.js';

export const ops = [
  { name: 'key rotate', access: 'write', description: 'Rotate the instance key (rewrap data keys, rows untouched); data starts a new data key for new writes instead', params: [
    { name: 'data', type: 'boolean', occurs: '?', description: 'Start a new data key for new writes (use with cred encrypt-existing --all after a suspected leak)' },
  ] },
  { name: 'key backup', access: 'write', description: 'Write a copy of the instance key to a new 0600 file outside the database directory; never prints the key', params: [
    { name: 'to', type: 'string', occurs: '1', description: 'New file to create (must not exist; not in the database directory or a sync folder)' },
  ] },
];

export async function run(args) {
  const [command, ...options] = args;
  const usage = () => emitFail('USAGE', 'Usage: key rotate [--data], key backup --to FILE');
  if (command === 'rotate') { if (!(options.length === 0 || (options.length === 1 && options[0] === '--data'))) return usage(); }
  else if (command === 'backup') { if (!(options.length === 2 && options[0] === '--to' && options[1] && !options[1].startsWith('--'))) return usage(); }
  else return usage();
  let result;
  try {
    if (command === 'backup') {
      const keys = loadKeys(dbPath());
      if (!keys) return emitFail('KEY_MISSING', 'Encryption key not found');
      backupKey(keys, options[1], dbPath());
      process.stderr.write('lmconn: key backed up. Keep it SEPARATE from the database and from home-directory backups; a backup holding both is not encrypted.\n');
      result = { backedUp: true, path: options[1] };
    } else if (options.length) {
      rotateData(openDb());
      result = { rotated: 'data' };
    } else {
      rotateKey(openDb());
      process.stderr.write('lmconn: instance key rotated; the old key is kept as instance.key.prev. Older key backups are now STALE: run key backup --to FILE again. Rotating the instance key does not help after a leak: run key rotate --data, then cred encrypt-existing --all.\n');
      result = { rotated: 'instance' };
    }
  } catch (err) {
    // Never echo underlying errors: they can contain paths or key material.
    if (SAFE_CODES.includes(err.code) || err.code === 'USAGE') return emitFail(err.code, err.message);
    return emitFail('KEY_ERROR', 'Key operation failed');
  }
  emit(ok(result));
  return 0;
}
