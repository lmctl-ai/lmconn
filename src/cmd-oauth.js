import { createServer } from 'node:http';
import { randomBytes, createHash } from 'node:crypto';
import { createInterface } from 'node:readline';
import { getCred, setCred, deleteCred, openDb } from './creds.js';
import { emit, ok, emitFail } from './result.js';
// Vendor endpoints/scopes mined from n8n's credential definitions; JSON
// import attribute so the table is embedded in bun-compiled binaries.
import presets from './oauth-presets.json' with { type: 'json' };

const fields = ['client-id', 'client-secret', 'auth-url', 'token-url', 'scope', 'auth-query', 'auth-style'];
const fieldName = (name) => 'oauth_' + name.replaceAll('-', '_');
const presetKey = (name) => name.replaceAll('-', '_');
const serviceParam = { name: 'service', type: 'string', positional: true, description: 'Credential service name' };
export const ops = [
  { name: 'oauth_authorize', access: 'write', description: 'Authorize with a loopback callback and PKCE', params: [
    serviceParam,
    ...fields.map(name => ({ name, type: 'string', occurs: '?', description: `Override stored ${fieldName(name)}` })),
    { name: 'port', type: 'number', occurs: '?', default: 0, description: 'Loopback port (0 chooses an ephemeral port)' },
    { name: 'timeout', type: 'number', occurs: '?', default: 300000, description: 'Authorization deadline in milliseconds' },
    { name: 'no-pkce', type: 'boolean', occurs: '?', description: 'Disable PKCE for legacy providers' },
    { name: 'manual', type: 'boolean', occurs: '?', description: 'Read a full redirect URL from stdin' },
  ] },
  { name: 'oauth_refresh', access: 'write', description: 'Refresh stored OAuth credentials', params: [serviceParam] },
  { name: 'oauth_status', access: 'read', description: 'Show OAuth status without tokens', params: [serviceParam] },
];

class OAuthError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const error = (code, message) => new OAuthError(code, message);
const usage = () => error('USAGE', 'Usage: oauth authorize <service> [options] | refresh <service> | status <service>');

function parse(args) {
  const [command, service, ...rest] = args;
  if (!['authorize', 'refresh', 'status'].includes(command) || !service || service.startsWith('-')) throw usage();
  const options = {};
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '--json') continue;
    if (command !== 'authorize' || !rest[i].startsWith('--')) throw usage();
    const key = rest[i].slice(2);
    if (Object.hasOwn(options, key)) throw usage();
    if (['manual', 'no-pkce'].includes(key)) options[key] = true;
    else if ([...fields, 'port', 'timeout'].includes(key)) {
      if (rest[i + 1] === undefined || rest[i + 1].startsWith('--')) throw usage();
      options[key] = rest[++i];
    } else throw usage();
  }
  options.port = Number(options.port ?? 0);
  options.timeout = Number(options.timeout ?? 300000);
  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65535 ||
      !Number.isSafeInteger(options.timeout) || options.timeout < 1 || options.timeout > 2147483647) throw usage();
  return { command, service, options };
}

function config(service, options, authorize) {
  // Resolution order: flag > cred store > vendor preset (oauth-presets.json).
  const preset = presets[service] || {};
  const cfg = {};
  for (const name of fields) cfg[name] = options[name] ?? getCred(service, fieldName(name)) ?? preset[presetKey(name)] ?? '';
  cfg['auth-style'] ||= 'header';
  for (const name of ['client-id', 'token-url', ...(authorize ? ['auth-url'] : [])]) {
    if (!cfg[name]) throw error('MISSING_CONFIG', `Missing ${fieldName(name)}; set with cred set ${service} ${fieldName(name)} --value ...${presets[service] ? '' : ', or use a service from src/oauth-presets.json'}`);
  }
  if (!['header', 'body'].includes(cfg['auth-style'])) throw error('USAGE', 'auth-style must be header or body');
  for (const name of ['token-url', ...(authorize ? ['auth-url'] : [])]) {
    let url;
    try { url = new URL(cfg[name]); } catch { throw error('USAGE', `${fieldName(name)} must be an HTTP(S) URL`); }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) throw error('USAGE', `${fieldName(name)} must be an HTTP(S) URL without userinfo or fragment`);
  }
  return cfg;
}

async function exchange(cfg, params, signal) {
  const body = new URLSearchParams(params);
  const headers = { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' };
  if (cfg['auth-style'] === 'header') headers.Authorization = 'Basic ' + Buffer.from(`${cfg['client-id']}:${cfg['client-secret']}`).toString('base64');
  else { body.set('client_id', cfg['client-id']); body.set('client_secret', cfg['client-secret']); }
  const response = await fetch(cfg['token-url'], { method: 'POST', headers, body, signal, redirect: 'error' });
  const text = await response.text();
  let token;
  try { token = JSON.parse(text); } catch { token = Object.fromEntries(new URLSearchParams(text)); }
  if (token?.error === 'invalid_grant') throw error('RECONNECT', 'OAuth grant rejected; run oauth authorize again');
  if (!response.ok || !token || typeof token !== 'object' || token.error || typeof token.access_token !== 'string' || !token.access_token) {
    throw error('OAUTH_ERROR', 'OAuth token exchange failed');
  }
  if (token.refresh_token !== undefined && (typeof token.refresh_token !== 'string' || !token.refresh_token)) throw error('OAUTH_ERROR', 'Invalid OAuth token response');
  if (token.token_type !== undefined && typeof token.token_type !== 'string') throw error('OAUTH_ERROR', 'Invalid OAuth token response');
  if (token.scope !== undefined && typeof token.scope !== 'string') throw error('OAUTH_ERROR', 'Invalid OAuth token response');
  let expiresAt = null;
  if (token.expires_in !== undefined) {
    const seconds = Number(token.expires_in);
    const date = new Date(Date.now() + seconds * 1000);
    if (!Number.isFinite(seconds) || seconds < 0 || !Number.isFinite(date.getTime())) throw error('OAUTH_ERROR', 'Invalid OAuth expiry');
    expiresAt = date.toISOString();
  }
  return { token, expiresAt };
}

function save(service, cfg, { token, expiresAt }, refresh) {
  const db = openDb();
  db.exec('BEGIN');
  try {
    for (const name of fields) setCred(service, fieldName(name), cfg[name], db);
    setCred(service, 'oauth_access_token', token.access_token, db);
    if (token.refresh_token) setCred(service, 'oauth_refresh_token', token.refresh_token, db);
    else if (!refresh) deleteCred(service, 'oauth_refresh_token', db);
    if (expiresAt) setCred(service, 'oauth_expires_at', expiresAt, db);
    else deleteCred(service, 'oauth_expires_at', db);
    setCred(service, 'oauth_token_type', token.token_type || 'Bearer', db);
    if (token.scope !== undefined) setCred(service, 'oauth_scope', token.scope, db);
    db.exec('COMMIT');
  } catch (err) { db.exec('ROLLBACK'); throw err; }
  return { service, expiresAt, hasRefreshToken: !!getCred(service, 'oauth_refresh_token'), scope: getCred(service, 'oauth_scope') || '' };
}

export function status(service) {
  const expiresAt = getCred(service, 'oauth_expires_at');
  return { service, authorized: !!getCred(service, 'oauth_access_token'), expiresAt,
    expired: expiresAt !== null && (!Number.isFinite(Date.parse(expiresAt)) || Date.parse(expiresAt) <= Date.now()),
    hasRefreshToken: !!getCred(service, 'oauth_refresh_token'), scope: getCred(service, 'oauth_scope') || '', tokenUrl: getCred(service, 'oauth_token_url') };
}

// Silent helper for HTTP connector integration: stores fresh tokens, returns metadata only.
export async function refresh(service) {
  const cfg = config(service, {}, false);
  const refreshToken = getCred(service, 'oauth_refresh_token');
  if (!refreshToken) throw error('RECONNECT', 'No refresh token; run oauth authorize again');
  const signal = AbortSignal.timeout(30000);
  try { return save(service, cfg, await exchange(cfg, { grant_type: 'refresh_token', refresh_token: refreshToken }, signal), true); }
  catch (err) {
    if (signal.aborted) throw error('TIMEOUT', 'OAuth refresh timed out');
    if (err instanceof OAuthError) throw err;
    throw error('OAUTH_ERROR', 'OAuth refresh failed');
  }
}

async function authorize(service, options, hooks) {
  const cfg = config(service, options, true);
  const state = randomBytes(32).toString('base64url');
  const verifier = randomBytes(32).toString('base64url');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeout);
  let server, reader, browser;
  let accept, reject;
  let received = false;
  const callback = new Promise((resolve, fail) => { accept = resolve; reject = fail; });
  // The callback may fail while listen/onListening is still in progress.
  callback.catch(() => {});
  const abort = () => reject(error('TIMEOUT', 'OAuth authorization timed out'));
  controller.signal.addEventListener('abort', abort, { once: true });
  let redirectUri;
  function receive(raw, response) {
    if (received) { response?.writeHead(409).end('Callback already received'); return; }
    received = true;
    browser = response;
    try {
      const url = new URL(raw);
      const expected = new URL(redirectUri);
      if (url.origin !== expected.origin || url.pathname !== '/callback' || url.searchParams.getAll('state').length !== 1 || url.searchParams.get('state') !== state) throw error('OAUTH_ERROR', 'OAuth callback state or redirect mismatch');
      if (url.searchParams.has('error')) throw error('OAUTH_ERROR', 'OAuth authorization was denied');
      const code = url.searchParams.get('code');
      if (!code || url.searchParams.getAll('code').length !== 1) throw error('OAUTH_ERROR', 'OAuth callback is missing a valid code');
      accept(code);
    } catch (err) { reject(err instanceof OAuthError ? err : error('OAUTH_ERROR', 'Invalid OAuth redirect URL')); }
  }
  try {
    server = createServer((req, res) => {
      if (req.method !== 'GET' || !req.url?.startsWith('/callback?')) { res.writeHead(404).end('Not found'); return; }
      receive(new URL(req.url, redirectUri).href, res);
    });
    await new Promise((resolve, fail) => {
      server.once('error', fail);
      server.listen(options.port, '127.0.0.1', resolve);
    });
    server.on('error', () => reject(error('OAUTH_ERROR', 'OAuth callback server failed')));
    const port = server.address().port;
    redirectUri = `http://127.0.0.1:${port}/callback`;
    const url = new URL(cfg['auth-url']);
    for (const [key, value] of new URLSearchParams(cfg['auth-query'])) url.searchParams.set(key, value);
    // Reserved protocol parameters always win over extra provider query parameters.
    for (const key of ['code_challenge', 'code_challenge_method', 'client_secret', 'code_verifier', 'code', 'access_token', 'refresh_token', 'id_token']) url.searchParams.delete(key);
    for (const [key, value] of Object.entries({ response_type: 'code', client_id: cfg['client-id'], redirect_uri: redirectUri, scope: cfg.scope, state })) url.searchParams.set(key, value);
    if (!options['no-pkce']) {
      url.searchParams.set('code_challenge', createHash('sha256').update(verifier).digest('base64url'));
      url.searchParams.set('code_challenge_method', 'S256');
    }
    if (options.manual) {
      reader = createInterface({ input: hooks.stdin || process.stdin, terminal: false });
      reader.once('line', line => receive(line.trim()));
      reader.once('close', () => { if (!received) reject(error('OAUTH_ERROR', 'No redirect URL supplied on stdin')); });
      reader.on('error', () => reject(error('OAUTH_ERROR', 'Could not read redirect URL')));
    }
    process.stderr.write(`Authorize URL: ${url.href}\n`);
    if (options.manual) process.stderr.write('Paste the full redirect URL on stdin:\n');
    if (hooks.onListening) Promise.resolve().then(() => hooks.onListening(port, url.href)).catch(() => reject(error('OAUTH_ERROR', 'OAuth callback failed')));
    if (controller.signal.aborted) abort();
    const code = await callback;
    const params = { grant_type: 'authorization_code', code, redirect_uri: redirectUri };
    if (!options['no-pkce']) params.code_verifier = verifier;
    const result = save(service, cfg, await exchange(cfg, params, controller.signal), false);
    if (browser) {
      browser.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      await new Promise(resolve => browser.end('<!doctype html><title>Authorized</title><p>You can close this tab.</p>', resolve));
    }
    return result;
  } catch (err) {
    const safe = controller.signal.aborted ? error('TIMEOUT', 'OAuth authorization timed out') : err instanceof OAuthError ? err : error('OAUTH_ERROR', 'OAuth authorization failed');
    if (browser && !browser.writableEnded) {
      browser.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
      await new Promise(resolve => browser.end(safe.message, resolve));
    }
    throw safe;
  } finally {
    clearTimeout(timer);
    controller.signal.removeEventListener('abort', abort);
    if (reader) { reader.close(); (hooks.stdin || process.stdin).pause(); }
    if (server) { server.close(); server.closeAllConnections(); }
  }
}

export async function run(args, hooks = {}) {
  try {
    const { command, service, options } = parse(args);
    const result = command === 'status' ? status(service) : command === 'refresh' ? await refresh(service) : await authorize(service, options, hooks);
    emit(ok(result));
    return 0;
  } catch (err) {
    return err instanceof OAuthError ? emitFail(err.code, err.message) : emitFail('OAUTH_ERROR', 'OAuth operation failed');
  }
}
