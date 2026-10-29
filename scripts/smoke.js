// Smoke test for a compiled lmconn binary. Runs under bun on any OS:
//   bun scripts/smoke.js ./lmconn-linux-x64
// Exercises the same contracts as the node test suite, against the binary:
// JSON envelope on stdout, exit codes, sqlite cred store, full op schema.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const bin = process.argv[2];
if (!bin) { console.error('usage: bun scripts/smoke.js <path-to-lmconn-binary>'); process.exit(2); }

const dir = mkdtempSync(join(tmpdir(), 'lmconn-smoke-'));
const db = join(dir, 'creds.db');
const version = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

let failures = 0;
function run(args, input) {
  const r = spawnSync(bin, args, { input, env: { ...process.env, LMCONN_DB: db }, encoding: 'utf8' });
  let envelope = null;
  try { envelope = JSON.parse(r.stdout.trim()); } catch { /* leave null */ }
  return { ...r, envelope };
}
function check(label, cond, detail = '') {
  if (cond) { console.log(`ok   ${label}`); return; }
  failures++;
  console.log(`FAIL ${label}${detail ? ` — ${detail}` : ''}`);
}

let r = run(['--version']);
check('--version', r.status === 0 && r.envelope?.ok && r.envelope.result.version === version,
  `status=${r.status} stdout=${r.stdout.slice(0, 200)}`);

r = run(['--cli-schema', '--json']);
const ops = r.envelope?.operations ?? (() => { try { return JSON.parse(r.stdout).operations; } catch { return null; } })();
check('--cli-schema lists 14 operations', r.status === 0 && Array.isArray(ops) && ops.length === 14,
  `got ${ops?.length}`);
const opNames = new Set((ops ?? []).map((o) => o.name));
check('--cli-schema lists the oauth ops', ['oauth_authorize', 'oauth_refresh', 'oauth_status'].every((n) => opNames.has(n)),
  `names=${[...opNames].filter((n) => n.startsWith('oauth_')).join(',') || 'none'}`);

r = run(['cred', 'set', 'smoke', 'api_key', '--stdin'], 'smoke-token-123');
check('cred set (stdin)', r.status === 0 && r.envelope?.ok === true, r.stdout.slice(0, 200));

r = run(['cred', 'get', 'smoke', 'api_key', '--reveal']);
check('cred get --reveal round-trips', r.status === 0 && r.envelope?.result?.value === 'smoke-token-123', r.stdout.slice(0, 200));

r = run(['cred', 'list']);
check('cred list shows name only', r.status === 0 && r.envelope?.result?.some((c) => c.service === 'smoke') && !r.stdout.includes('smoke-token-123'));

r = run(['cred', 'delete', 'smoke', 'api_key']);
check('cred delete', r.status === 0 && r.envelope?.result?.deleted === true);

r = run(['llm', 'providers']);
check('llm providers lists 7', r.status === 0 && Array.isArray(r.envelope?.result) && r.envelope.result.length === 7,
  `got ${r.envelope?.result?.length}`);

r = run(['oauth', 'status', 'not-a-service']);
// status is read-only: an unknown service is a clean envelope, either ok:true with authorized:false
// (pinned design) or ok:false with an error code and a nonzero exit; never a crash, never a token.
check('oauth status on an unknown service is a clean envelope',
  (r.status === 0 && r.envelope?.ok === true && r.envelope.result?.authorized === false && r.envelope.result?.service === 'not-a-service') ||
  (r.status !== 0 && r.envelope?.ok === false && typeof r.envelope?.error?.code === 'string'),
  `status=${r.status} stdout=${r.stdout.slice(0, 200)}`);
check('oauth status prints nothing secret-shaped', !/(access|refresh)_token"\s*:\s*"[^"]+|Bearer\s+\S+|ya29\.|gho_|ghp_/i.test(r.stdout),
  r.stdout.slice(0, 200));

r = run(['bogus-area']);
check('unknown area exits 2 with USAGE', r.status === 2 && r.envelope?.error?.code === 'USAGE', `status=${r.status}`);

rmSync(dir, { recursive: true, force: true });
if (failures) { console.error(`${failures} smoke check(s) failed`); process.exit(1); }
console.log('smoke: all checks passed');
