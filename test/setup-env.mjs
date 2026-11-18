// Loaded with `node --test --import` (package.json and test.lms): keeps every test process away from the real
// ~/.config/lmconn key. A write creates the key file on first use; here it lands in a throwaway directory.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import cp from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';

const config = mkdtempSync(join(tmpdir(), 'lmconn-test-config-'));
process.env.XDG_CONFIG_HOME = config;
delete process.env.LMCONN_KEY;
delete process.env.LMCONN_KEY_FILE;
process.on('exit', () => rmSync(config, { recursive: true, force: true }));

// Windows has no file-based key (STORE_SECURITY by design), so the whole suite runs encrypted through LMCONN_KEY.
// This key is a test-only constant, not a secret. lmconn removes LMCONN_KEY from process.env as soon as it reads
// it, so children that tests spawn afterwards would lose it: spawn/spawnSync put it back unless the caller passes
// its own LMCONN_KEY in `env`.
if (process.platform === 'win32') {
  const key = Buffer.alloc(32, 7).toString('base64');
  process.env.LMCONN_KEY = key;
  const withKey = fn => function (command, ...rest) {
    let at = rest.findIndex(arg => arg && typeof arg === 'object' && !Array.isArray(arg));
    if (at === -1) { rest.push({}); at = rest.length - 1; }
    const env = { ...(rest[at].env ?? process.env) };
    if (!('LMCONN_KEY' in env)) env.LMCONN_KEY = key;
    rest[at] = { ...rest[at], env };
    return fn.call(this, command, ...rest);
  };
  cp.spawn = withKey(cp.spawn);
  cp.spawnSync = withKey(cp.spawnSync);
  syncBuiltinESMExports();
}
