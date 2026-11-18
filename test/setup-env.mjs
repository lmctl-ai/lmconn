// Loaded with `node --test --import` (see package.json): keeps every test process away from the real
// ~/.config/lmconn key. A write command creates the key file on first use; here it lands in a throwaway directory.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const config = mkdtempSync(join(tmpdir(), 'lmconn-test-config-'));
process.env.XDG_CONFIG_HOME = config;
delete process.env.LMCONN_KEY;
delete process.env.LMCONN_KEY_FILE;
// Windows has no file-based key yet (STORE_SECURITY); the old suites exercise legacy plaintext there.
if (process.platform === 'win32') process.env.LMCONN_ALLOW_PLAINTEXT = '1';
process.on('exit', () => rmSync(config, { recursive: true, force: true }));
