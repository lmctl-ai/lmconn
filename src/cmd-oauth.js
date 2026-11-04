// auto-follow exists for demos and mock-IdP tests; real providers need a human at the browser.
import { createServer } from 'node:http';
import { randomBytes, createHash } from 'node:crypto';
import { createInterface } from 'node:readline';
import { getCred, setCred, deleteCred, openDb } from './creds.js';
import { emit, ok, emitFail } from './result.js';
// Vendor endpoints/scopes mined from n8n's credential definitions; JSON
// import attribute so the table is embedded in bun-compiled binaries.
import presets from './oauth-presets.json' with { type: 'json' };
import { endpoint, tokenResult, safeMetadata, unsafeText, callbackParameters, securityError } from './oauth-security.js';
import { providerDeadline } from './oauth-deadline.js';
import { refuseLegacyWrite, checkRefresh, policy, putPolicy } from './credential-policy.js';

const fields = ['client-id', 'client-secret', 'auth-url', 'device-url', 'token-url', 'scope', 'auth-query', 'auth-style', 'owner', 'source'];
const deviceFields = ['client-id', 'device-url', 'token-url', 'scope', 'owner', 'source'];
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
    { name: 'auto-follow', type: 'boolean', occurs: '?', description: 'Follow authorization redirects automatically for demos and mock IdPs' },
    { name: 'manual', type: 'boolean', occurs: '?', description: 'Read a full redirect URL from stdin' },
  ] },
  { name: 'oauth_refresh', access: 'write', description: 'Refresh stored OAuth credentials', params: [serviceParam] },
  { name: 'oauth_status', access: 'read', description: 'Show OAuth status without tokens', params: [serviceParam] },
  { name: 'oauth_list', access: 'read', description: 'List OAuth credential metadata without tokens', params: [] },
  { name: 'oauth_device', access: 'write', description: 'Authorize with an OAuth2 device code', params: [
    serviceParam,
    ...deviceFields.map(name => ({ name, type: 'string', occurs: '?', description: `Override stored ${fieldName(name)}` })),
  ] },
];

class OAuthError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const error = (code, message) => new OAuthError(code, message);
const usage = () => error('USAGE', 'Usage: oauth authorize <service> [options] | device <service> [options] | refresh <service> | status <service> | list');

function parse(args) {
  const [command, service, ...rest] = args;
  if (!['authorize', 'device', 'refresh', 'status', 'list'].includes(command) || (command !== 'list' && (!service || service.startsWith('-')))) throw usage();
  const options = {};
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '--json') continue;
    if (!['authorize', 'device'].includes(command) || !rest[i].startsWith('--')) throw usage();
    const key = rest[i].slice(2);
    if (Object.hasOwn(options, key)) throw usage();
    if (command === 'authorize' && ['manual', 'no-pkce', 'auto-follow'].includes(key)) options[key] = true;
    else if ([...(command === 'device' ? deviceFields : fields), ...(command === 'authorize' ? ['port', 'timeout'] : [])].includes(key)) {
      if (rest[i + 1] === undefined || rest[i + 1].startsWith('--')) throw usage();
      options[key] = rest[++i];
    } else throw usage();
  }
  if (options.manual && options['auto-follow']) throw usage();
  options.port = Number(options.port ?? 0);
  options.timeout = Number(options.timeout ?? 300000);
  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65535 ||
      !Number.isSafeInteger(options.timeout) || options.timeout < 1 || options.timeout > 2147483647) throw usage();
  if (command === 'list' && (service !== undefined || rest.length)) throw usage();
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
  for (const name of ['token-url', ...(authorize ? ['auth-url'] : [])]) endpoint(cfg[name], fieldName(name));
  cfg.previousRefresh = getCred(service, 'oauth_refresh_token');
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
  return tokenResult(token, cfg);
}

function save(service, cfg, { token, expiresAt }, refresh, guard = () => {}) {
  const db = openDb();
  db.exec('BEGIN');
  try {
    const previous = policy(service, db);
    if (previous?.noReveal && !refresh) throw securityError('Protected grants require cred store');
    if (!previous?.noReveal && !refresh) putPolicy(service, { noReveal: false, kind: 'oauth2', issuer: endpoint(cfg['token-url']).origin, owner: cfg.owner || null, origins: [], refresh: { tokenUrl: endpoint(cfg['token-url']).href, clientId: cfg['client-id'], authStyle: cfg['auth-style'] } }, db);
    setCred(service, 'oauth_kind', 'oauth2', db);
    for (const name of fields) setCred(service, fieldName(name), cfg[name], db);
    setCred(service, 'oauth_access_token', token.access_token, db);
    if (token.refresh_token) setCred(service, 'oauth_refresh_token', token.refresh_token, db);
    else if (!refresh) deleteCred(service, 'oauth_refresh_token', db);
    if (expiresAt) setCred(service, 'oauth_expires_at', expiresAt, db);
    else deleteCred(service, 'oauth_expires_at', db);
    setCred(service, 'oauth_token_type', token.token_type || 'Bearer', db);
    if (token.scope !== undefined) setCred(service, 'oauth_scope', token.scope, db);
    guard();
    db.exec('COMMIT');
  } catch (err) { db.exec('ROLLBACK'); throw err; }
  return safeMeta(service, { service, expiresAt, hasRefreshToken: !!getCred(service, 'oauth_refresh_token'), scope: getCred(service, 'oauth_scope') || '' });
}

function safeMeta(service, value) { return safeMetadata(value, ['api_key', 'oauth_access_token', 'oauth_refresh_token', 'oauth_client_secret'].map(field => getCred(service, field))); }

export function status(service) {
  const expiresAt = getCred(service, 'oauth_expires_at');
  return safeMeta(service, { service, authorized: !!(getCred(service, 'oauth_access_token') || (getCred(service, 'oauth_kind') === 'bearer' && getCred(service, 'api_key'))), expiresAt,
    expired: expiresAt !== null && (!Number.isFinite(Date.parse(expiresAt)) || Date.parse(expiresAt) <= Date.now()),
    hasRefreshToken: !!getCred(service, 'oauth_refresh_token'), scope: getCred(service, 'oauth_scope') || '', tokenUrl: getCred(service, 'oauth_token_url') });
}

export function list() {
  const db = openDb();
  const services = db.prepare("SELECT DISTINCT c.service FROM creds c WHERE c.field='oauth_access_token' OR (c.field='api_key' AND EXISTS (SELECT 1 FROM creds k WHERE k.service=c.service AND k.field='oauth_kind' AND k.value='bearer')) ORDER BY service").all();
  return services.map(({ service }) => safeMeta(service, ({
    service, provider: service, handle: service, kind: getCred(service, 'oauth_kind', db) || 'oauth2', owner: getCred(service, 'oauth_owner', db) || '',
    source: getCred(service, 'oauth_source', db) || '', scopes: getCred(service, 'oauth_scope', db) || '',
    expiresAt: getCred(service, 'oauth_expires_at', db), hasRefreshToken: !!getCred(service, 'oauth_refresh_token', db),
  })));
}

async function deviceAuthorize(service, options, hooks) {
  refuseLegacyWrite(service);
  const cfg = config(service, options, false);
  if (!cfg['device-url']) throw error('MISSING_CONFIG', 'Missing oauth_device_url');
  const deviceUrl = endpoint(cfg['device-url'], 'oauth_device_url'), tokenUrl = endpoint(cfg['token-url'], 'oauth_token_url');
  const deviceResponse = await fetch(deviceUrl, {
    method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: cfg['client-id'], scope: cfg.scope }), redirect: 'error',
  });
  const receivedAt = (hooks.now || (() => performance.now()))();
  let grant;
  try { grant = await deviceResponse.json(); } catch { throw error('OAUTH_ERROR', 'OAuth device authorization failed'); }
  const expirySeconds = Number(grant?.expires_in), pollSeconds = Number(grant?.interval ?? 5);
  const deviceCode = grant?.device_code, userCode = grant?.user_code;
  if (!deviceResponse.ok || typeof deviceCode !== 'string' || !deviceCode || typeof userCode !== 'string' || !userCode || unsafeText(userCode) ||
      typeof grant.verification_uri !== 'string' || (grant.verification_uri_complete !== undefined && typeof grant.verification_uri_complete !== 'string') ||
      (!Number.isSafeInteger(expirySeconds) || !Number.isSafeInteger(expirySeconds * 1000)) || expirySeconds < 1 || (!Number.isSafeInteger(pollSeconds) || !Number.isSafeInteger(pollSeconds * 1000)) || pollSeconds < 1 ||
      (!Number.isFinite(receivedAt + expirySeconds * 1000) || receivedAt + expirySeconds * 1000 > Number.MAX_SAFE_INTEGER)) throw error('OAUTH_ERROR', 'OAuth device authorization response is invalid');
  const verification = endpoint(grant.verification_uri, 'verification_uri');
  const complete = grant.verification_uri_complete ? endpoint(grant.verification_uri_complete, 'verification_uri_complete') : null;
  process.stderr.write(`Open ${(complete || verification).href} and enter code ${userCode}\n`);
  const lifetime = providerDeadline(receivedAt + expirySeconds * 1000, hooks);
  let intervalMs = pollSeconds * 1000;
  try {
    while (true) {
      await lifetime.sleep(intervalMs);
      lifetime.check();
      let response, token;
      try {
        response = await lifetime.race(fetch(tokenUrl, {
          method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: deviceCode, client_id: cfg['client-id'] }),
          redirect: 'error', signal: lifetime.signal,
        }));
        token = await lifetime.race(response.json());
      } catch (err) { lifetime.check(); throw error('OAUTH_ERROR', 'OAuth device token request or response failed'); }
      lifetime.check();
      if (token?.error === 'authorization_pending') continue;
      if (token?.error === 'slow_down') { intervalMs += 5000; if (!Number.isSafeInteger(intervalMs)) throw error('OAUTH_ERROR', 'Invalid OAuth interval'); continue; }
      if (token?.error === 'access_denied') throw error('DENIED', 'OAuth device authorization was denied');
      if (token?.error === 'expired_token') throw error('RECONNECT', 'OAuth device code expired; start authorization again');
      if (!response.ok) throw error('OAUTH_ERROR', 'OAuth device token exchange failed');
      const result = tokenResult(token, cfg);
      lifetime.check();
      return save(service, cfg, result, false, lifetime.check);
    }
  } finally { lifetime.close(); }
}

// Silent helper for HTTP connector integration: stores fresh tokens, returns metadata only.
export async function refresh(service) {
  const cfg = config(service, {}, false);
  const refreshToken = getCred(service, 'oauth_refresh_token');
  if (!refreshToken) throw error('RECONNECT', 'No refresh token; run oauth authorize again');
  checkRefresh(service, cfg);
  const signal = AbortSignal.timeout(30000);
  try { return save(service, cfg, await exchange(cfg, { grant_type: 'refresh_token', refresh_token: refreshToken }, signal), true); }
  catch (err) {
    if (signal.aborted) throw error('TIMEOUT', 'OAuth refresh timed out');
    if (err instanceof OAuthError) throw err;
    throw error('OAUTH_ERROR', 'OAuth refresh failed');
  }
}

async function authorize(service, options, hooks) {
  refuseLegacyWrite(service);
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
    let parsed;
    try { parsed = callbackParameters(raw, redirectUri, state); }
    catch {
      response?.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }).end('Invalid OAuth callback');
      return;
    }
    received = true;
    browser = response;
    if (parsed.denied) reject(error('OAUTH_ERROR', 'OAuth authorization was denied'));
    else accept(parsed.code);
  }

  try {
    server = createServer((req, res) => {
      if (req.method !== 'GET' || !req.url?.startsWith('/callback?')) { res.writeHead(404).end('Not found'); return; }
      if (req.headers.host !== new URL(redirectUri).host) { res.writeHead(400).end('Invalid OAuth callback'); return; }
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
      reader.on('line', line => receive(line));
      reader.once('close', () => { if (!received) reject(error('OAUTH_ERROR', 'No redirect URL supplied on stdin')); });
      reader.on('error', () => reject(error('OAUTH_ERROR', 'Could not read redirect URL')));
    }
    process.stderr.write(`Authorize URL: ${url.href}\n`);
    if (options.manual) process.stderr.write('Paste the full redirect URL on stdin:\n');
    // Do not await this task here: the final redirect waits for our token exchange.
    Promise.resolve().then(async () => {
      if (hooks.onListening) await hooks.onListening(port, url.href);
      if (options['auto-follow']) {
        const response = await fetch(url.href, { signal: controller.signal, redirect: 'follow' });
        await response.arrayBuffer();
        if (!received) reject(error('OAUTH_ERROR', 'Automatic authorization did not reach the callback'));
      }
    }).catch(() => reject(controller.signal.aborted
      ? error('TIMEOUT', 'OAuth authorization timed out')
      : error('OAUTH_ERROR', 'OAuth callback failed')));
    if (controller.signal.aborted) abort();
    const code = await callback;
    const params = { grant_type: 'authorization_code', code, redirect_uri: redirectUri };
    if (!options['no-pkce']) params.code_verifier = verifier;
    const result = save(service, cfg, await exchange(cfg, params, controller.signal), false);
    if (browser) {
      browser.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'", 'Referrer-Policy': 'no-referrer' });
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
    controller.abort(); // Also release any outstanding auto-follow request.
    if (reader) { reader.close(); (hooks.stdin || process.stdin).pause(); }
    if (server) { server.close(); server.closeAllConnections(); }
  }
}

export async function run(args, hooks = {}) {
  try {
    const { command, service, options } = parse(args);
    const result = command === 'list' ? list() : command === 'status' ? status(service) : command === 'refresh' ? await refresh(service) : command === 'device' ? await deviceAuthorize(service, options, hooks) : await authorize(service, options, hooks);
    emit(ok(result));
    return 0;
  } catch (err) {
    return err instanceof OAuthError || ['EXPIRED', 'USAGE', 'CREDENTIAL_POLICY', 'STORE_SECURITY', 'OAUTH_ERROR'].includes(err.code) ? emitFail(err.code, err.message) : emitFail('OAUTH_ERROR', 'OAuth operation failed');
  }
}
