#!/usr/bin/env node
/**
 * Headless n8n 2.45.4 cross-validation against the shared strict mock IdP.
 * Run: node scripts/verify-n8n-oauth.mjs (n8n must be on PATH).
 * Not in CI: n8n is a separately installed prerequisite, not a dependency.
 *
 * Uses fresh N8N_USER_FOLDER/SQLite state; never touches an existing account.
 * Requires free loopback ports 5556, 5678 and 5679. Cleans up processes/state.
 * REST sequence: POST /rest/owner/setup -> session cookie; POST /rest/credentials
 * (oAuth2Api); GET /rest/oauth2-credential/auth?id=ID -> authorization URL;
 * GET authorize without redirects -> GET callback with the n8n session cookie.
 * Success requires n8n success pages for header, body and PKCE flows.
 * The lmmock audit must contain one authorize/token pair per flow.
 *
 * The standalone mock launcher does not expose idp.log.
 * Instead --idp-child runs that same createMockIdP
 * implementation/configuration and exposes only redacted observations via IPC.
 * Verified end-to-end with n8n 2.45.4 on 2026-10-28.
 * No replacement OAuth client or token exchange is implemented here: n8n does it.
 * Child output, cookies, authorization URLs, codes, and tokens are never printed.
 */
import { spawn, fork, execFile } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:net';
import { randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';

const self = fileURLToPath(import.meta.url);
if (process.argv.includes('--idp-child')) {
  const { createMockIdP } = await import('./mock-idp.js');
  const idp = await createMockIdP({ port: 5556 });
  idp.registerClient({ clientId: 'demo-client', clientSecret: 'demo-secret',
    redirectUris: ['http://localhost:5678/rest/oauth2-credential/callback'], authStyle: 'both' });
  process.on('message', message => {
    if (message === 'log') process.send({ type: 'log', entries: idp.log.map(entry => ({
      method: entry.method, path: entry.path, authStyle: entry.authStyle,
      grantType: entry.params.grant_type,
    })) });
  });
  process.send({ type: 'ready' });
} else {
  await main();
}

function check(condition, message) {
  if (!condition) throw new Error(message);
  console.log(`PASS ${message}`);
}
async function freePort(port) {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once('error', () => reject(new Error(`port ${port} is occupied; stop the existing service before running`)));
    server.listen(port, '127.0.0.1', resolve);
  });
  await new Promise(resolve => server.close(resolve));
}
function messageFrom(child, type) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error(`mock ${type} timed out`)), 10000);
    const onMessage = message => { if (message.type === type) finish(null, message); };
    const onExit = () => finish(new Error('mock exited unexpectedly'));
    function finish(error, value) {
      clearTimeout(timer); child.off('message', onMessage); child.off('exit', onExit);
      if (error) reject(error); else resolve(value);
    }
    child.on('message', onMessage); child.once('exit', onExit);
  });
}
async function stop(child) {
  if (!child || !child.pid || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise(resolve => child.once('exit', resolve));
  const kill = signal => {
    try {
      if (process.platform !== 'win32') process.kill(-child.pid, signal);
      else child.kill(signal);
    } catch { /* Already exited. */ }
  };
  kill('SIGTERM');
  const timer = setTimeout(() => kill('SIGKILL'), 5000);
  await exited; clearTimeout(timer);
}
async function main() {
  let folder; let n8n; let idp;
  let phase = 'preflight';
  let cancelled = false;
  const interrupted = () => { cancelled = true; void stop(n8n); void stop(idp); };
  process.once('SIGINT', interrupted); process.once('SIGTERM', interrupted);
  try {
    let version;
    try { version = (await promisify(execFile)('n8n', ['--version'], { timeout: 30000 })).stdout.trim(); }
    catch { throw new Error('n8n --version failed; install n8n 2.45.4 on PATH'); }
    check(version === '2.45.4', 'installed n8n version is 2.45.4');
    for (const port of [5556, 5678, 5679]) await freePort(port);
    folder = await mkdtemp(join(tmpdir(), 'lmconn-n8n-oauth-'));
    phase = 'mock startup';
    idp = fork(self, ['--idp-child'], { detached: process.platform !== 'win32', stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
    await messageFrom(idp, 'ready');
    phase = 'n8n startup';
    // Give this isolated instance an explicit loopback mock allowlist.
    const env = {
      PATH: process.env.PATH, HOME: folder, USERPROFILE: folder, SystemRoot: process.env.SystemRoot,
      N8N_USER_FOLDER: folder, DB_TYPE: 'sqlite', N8N_PORT: '5678', N8N_HOST: 'localhost',
      N8N_LISTEN_ADDRESS: '127.0.0.1', N8N_PROTOCOL: 'http', N8N_SECURE_COOKIE: 'false',
      N8N_EDITOR_BASE_URL: 'http://localhost:5678', N8N_DIAGNOSTICS_ENABLED: 'false',
      N8N_VERSION_NOTIFICATIONS_ENABLED: 'false', N8N_TEMPLATES_ENABLED: 'false',
      N8N_PERSONALIZATION_ENABLED: 'false', N8N_SSRF_ALLOWED_HOSTNAMES: '127.0.0.1',
      N8N_ENCRYPTION_KEY: randomBytes(32).toString('hex'), N8N_LOG_LEVEL: 'error',
    };
    n8n = spawn('n8n', ['start'], { env, detached: process.platform !== 'win32', stdio: 'ignore' });
    let spawnFailed = false;
    n8n.on('error', () => { spawnFailed = true; });
    const origin = 'http://localhost:5678';
    const deadline = Date.now() + 120000;
    let ready = false;
    while (Date.now() < deadline) {
      if (cancelled || spawnFailed || n8n.exitCode !== null || n8n.signalCode !== null) throw new Error('n8n did not start; verify n8n 2.45.4 is installed on PATH');
      try { ready = (await fetch(`${origin}/healthz/readiness`, { signal: AbortSignal.timeout(1000) })).ok; } catch { /* Starting. */ }
      if (ready) break;
      await delay(500);
    }
    check(ready, 'n8n became ready using isolated temporary state');
    const cookies = new Map();
    async function n8nFetch(path, options = {}) {
      if (cancelled) throw new Error('verification interrupted');
      const response = await fetch(`${origin}${path}`, { ...options, redirect: 'manual', signal: AbortSignal.timeout(15000),
        headers: { 'content-type': 'application/json', cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join('; '), ...options.headers } });
      for (const cookie of response.headers.getSetCookie()) {
        const pair = cookie.split(';')[0]; const index = pair.indexOf('=');
        cookies.set(pair.slice(0, index), pair.slice(index + 1));
      }
      if (!response.ok) throw new Error(`n8n returned HTTP ${response.status} during ${phase}`);
      return response;
    }
    phase = 'owner setup';
    await n8nFetch('/rest/owner/setup', { method: 'POST', body: JSON.stringify({
      email: 'oauth-test@example.com', firstName: 'OAuth', lastName: 'Verifier', password: `Aa1!${randomBytes(24).toString('hex')}`,
    }) });
    check(cookies.size > 0, 'owner setup issued a session cookie');
    for (const variant of [{name:'header',authentication:'header',usePkce:false},{name:'body',authentication:'body',usePkce:false},{name:'pkce',authentication:'header',usePkce:true}]) {
    phase = 'credential creation '+variant.name;
    const created = await (await n8nFetch('/rest/credentials', { method: 'POST', body: JSON.stringify({
      name: 'lmmock OAuth verification '+variant.name, type: 'oAuth2Api', data: {
        grantType: 'authorizationCode', authUrl: 'http://127.0.0.1:5556/authorize',
        accessTokenUrl: 'http://127.0.0.1:5556/token', clientId: 'demo-client', clientSecret: 'demo-secret',
        scope: 'openid profile', authentication: variant.authentication, usePkce: variant.usePkce, authQueryParameters: '',
      },
    }) })).json();
    check(typeof created.data?.id === 'string', 'n8n created a Generic OAuth2 credential');
    phase = 'authorization URL';
    const auth = await (await n8nFetch(`/rest/oauth2-credential/auth?id=${encodeURIComponent(created.data.id)}`)).json();
    const url = new URL(auth.data);
    check(url.origin === 'http://127.0.0.1:5556' && url.pathname === '/authorize' && !!url.searchParams.get('state'), 'n8n generated a mock authorize URL with state');
    phase = 'mock authorize';
    const redirect = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(10000) });
    check(redirect.status === 302, 'mock accepted the n8n client and exact redirect URI');
    const callback = new URL(redirect.headers.get('location'));
    check(callback.origin === origin && callback.pathname === '/rest/oauth2-credential/callback', 'mock redirected to the n8n callback');
    phase = 'n8n callback and token exchange';
    const html = await (await n8nFetch(callback.pathname + callback.search)).text();
    check(html.includes('<h1>Connection successful</h1>'), 'n8n callback confirmed token exchange and persistence: '+variant.name);
    }
    phase = 'mock request audit';
    const pending = messageFrom(idp, 'log'); idp.send('log');
    const { entries } = await pending;
    const authorize = entries.filter(entry => entry.path === '/authorize');
    const token = entries.filter(entry => entry.path === '/token');
    check(authorize.length === 3 && token.length === 3 && token.every(entry => entry.method === 'POST' && entry.grantType === 'authorization_code') && token.map(entry => entry.authStyle).join(',') === 'header,body,header',
    'lmmock observed all three n8n flows with header/body client authentication');
  } catch (error) {
    // Our messages contain only fixed descriptions/statuses; never print remote bodies or URLs.
    const safe = error instanceof TypeError || error instanceof SyntaxError ? 'unexpected transport or response format' : error.message;
    console.error(`FAIL ${phase}: ${safe}`);
    process.exitCode = 1;
  } finally {
    await Promise.all([stop(n8n), stop(idp)]);
    if (folder) await rm(folder, { recursive: true, force: true });
    process.off('SIGINT', interrupted); process.off('SIGTERM', interrupted);
  }
}
