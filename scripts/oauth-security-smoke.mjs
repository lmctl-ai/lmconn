// Native binary qualification with local canaries. Run: node scripts/oauth-security-smoke.mjs /absolute/binary
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createServer } from 'node:http';
const binary = resolve(process.argv[2]), dir = mkdtempSync(join(tmpdir(), 'lmconn-native-security-'));
const token = 'NATIVE_SECRET_CANARY_&+/', refresh = 'NATIVE_REFRESH_CANARY';
const environment = { ...process.env, LMCONN_DB: join(dir, 'db') };
async function invoke(args, input) {
  const child = spawn(binary, args, { env: environment, stdio: ['pipe', 'pipe', 'pipe'] });
  let out = '', err = '';
  child.stdout.on('data', data => out += data); child.stderr.on('data', data => err += data);
  const done = new Promise((ok, no) => { child.once('error', no); child.once('close', code => ok(code)); });
  child.stdin.end(input); const code = await done;
  return { code, out, err, json: JSON.parse(out) };
}
let mode = 'normal', firstAuth, foreignAuth, foreignRequests = 0, tokenCalls = 0, stalledConnectionClosed = false;
const foreign = createServer((req, res) => { foreignRequests++; foreignAuth = req.headers.authorization; res.end(JSON.stringify({ encoded: Buffer.from(token).toString('base64') })); });
const idp = createServer((req, res) => {
  res.setHeader('content-type', 'application/json');
  if (req.url === '/device') res.end(JSON.stringify({ device_code: 'DEVICE', user_code: mode === 'terminal' ? 'HUMAN\x1b]52;c;AAAA\x07' : 'HUMAN', verification_uri: 'http://127.0.0.1/verify', expires_in: mode === 'stall' ? 2 : 20, interval: 1 }));
  else if (req.url === '/token') {
    tokenCalls++;
    if (mode === 'stall') { res.writeHead(200); res.write('{'); res.on('close', () => stalledConnectionClosed = true); }
    else res.end(JSON.stringify({ access_token: token, refresh_token: refresh, scope: mode === 'echo' ? token + ' ' + refresh : 'read' }));
  } else if (req.url === '/redirect') { firstAuth = req.headers.authorization; res.writeHead(302, { location: foreignOrigin + '/end' }).end(); }
  else res.end(JSON.stringify({ echo: req.headers.authorization, encoded: Buffer.from(token).toString('base64') }));
});
await Promise.all([new Promise(ok => foreign.listen(0, '127.0.0.1', ok)), new Promise(ok => idp.listen(0, '127.0.0.1', ok))]);
const origin = 'http://127.0.0.1:' + idp.address().port, foreignOrigin = 'http://127.0.0.1:' + foreign.address().port;
try {
  const args = name => ['oauth', 'device', name, '--client-id', 'public', '--device-url', origin + '/device', '--token-url', origin + '/token', '--scope', 'read'];
  let r = await invoke(args('healthy')); assert.equal(r.code, 0, r.out); assert.ok(!(r.out + r.err).includes(token));
  mode = 'echo'; r = await invoke(args('echo')); assert.equal(r.code, 1); assert.ok(!(r.out + r.err).includes(token) && !(r.out + r.err).includes(refresh));
  mode = 'terminal'; const before = tokenCalls; r = await invoke(args('terminal')); assert.equal(r.code, 1); assert.equal(tokenCalls, before); assert.ok(!r.err.includes('\x1b'));
  mode = 'stall'; r = await invoke(args('stall')); assert.equal(r.code, 1); assert.equal(r.json.error.code, 'EXPIRED'); assert.ok(stalledConnectionClosed);
  if (process.platform !== 'win32') {
    r = await invoke(['cred', 'store', 'protected', '--stdin'], JSON.stringify({ kind: 'bearer', accessToken: token, scopes: ['read'], owner: 'native', source: 'lmauth', issuer: origin, allowedOrigins: [origin] })); assert.equal(r.code, 0, r.out);
    const count = foreignRequests; r = await invoke(['http', 'request', foreignOrigin + '/wrong', '--auth', 'protected']); assert.equal(r.code, 1); assert.equal(foreignRequests, count);
    mode = 'normal'; r = await invoke(['http', 'request', origin + '/resource', '--auth', 'protected']); assert.equal(r.code, 0); assert.equal(r.json.result.bodyOmitted, true); assert.ok(!r.out.includes(Buffer.from(token).toString('base64')));
    r = await invoke(['http', 'request', origin + '/redirect', '--auth', 'protected']); assert.equal(r.code, 0); assert.equal(firstAuth, 'Bearer ' + token); assert.equal(foreignAuth, undefined);
    r = await invoke(['cred', 'get', 'protected', 'api_key', '--reveal']); assert.equal(r.code, 1); assert.ok(!r.out.includes(token));
  }
  console.log('PASS native device, hostile metadata/UI, in-flight body expiry, broker binding/reveal and redirect controls');
} finally {
  idp.closeAllConnections(); foreign.closeAllConnections();
  await Promise.all([new Promise(ok => idp.close(ok)), new Promise(ok => foreign.close(ok))]);
  rmSync(dir, { recursive: true, force: true });
}
