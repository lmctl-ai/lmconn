// Generic HTTP connector (the n8n "HTTP Request" node as a CLI):
//   lmconn http request <url> [--method M] [--header "K: V"]... [--data S | --data-file P]
//                       [--auth SERVICE] [--timeout MS]
// --auth SERVICE resolves store api_key, then $<SERVICE>_API_KEY, then OAuth (refreshing when expired), and
// sends it as `Authorization: Bearer`. The key never appears on stdout or stderr.

import { readFile } from 'node:fs/promises';
import { emit, ok, emitFail } from './result.js';
import { getCred, setCred, deleteCred } from './creds.js';

const USAGE = 'usage: lmconn http request <url> [--method GET|POST|...] [--header "K: V"]... ' +
  '[--data STRING | --data-file PATH] [--auth SERVICE] [--timeout MS]';

const usage = (message) => Object.assign(new Error(message), { code: 'USAGE' });

export const ops = [
  { name: 'http_request', access: 'write', description: 'Send one HTTP request and return status, headers summary and the body (JSON parsed when possible)', params: [
    { name: 'url', type: 'string', positional: true, description: 'Absolute http(s) URL' },
    { name: 'method', type: 'string', occurs: '?', default: 'GET', description: 'HTTP method (default GET, or POST when data is given)' },
    { name: 'header', type: 'array', items: 'string', occurs: '*', description: 'Request header as "Name: value" (repeatable)' },
    { name: 'data', type: 'string', occurs: '?', description: 'Request body (sets Content-Type application/json when it parses as JSON)' },
    { name: 'dataFile', type: 'string', occurs: '?', description: 'Read the request body from a file' },
    { name: 'auth', type: 'string', occurs: '?', description: 'Credential service whose API key or OAuth access token is sent as Authorization: Bearer' },
    { name: 'timeout', type: 'number', occurs: '?', default: 30000, description: 'Timeout in milliseconds' },
  ] },
];

// Env fallback for --auth: deepseek -> DEEPSEEK_API_KEY, ollama-cloud -> OLLAMA_CLOUD_API_KEY.
export function envNameFor(service) {
  return service.toUpperCase().replace(/[^A-Z0-9]/g, '_') + '_API_KEY';
}

const reconnect = service => Object.assign(new Error(`OAuth authorization expired or revoked; run \`lmconn oauth authorize ${service}\` again`), { code: 'RECONNECT' });
const refreshFailure = () => Object.assign(new Error('OAuth token refresh failed'), { code: 'OAUTH_REFRESH' });

// No dependency on cmd-oauth: the shared contract is the oauth_* credential fields.
export async function refreshOAuth(service, fetchImpl = globalThis.fetch, timeoutMs = 30000) {
  const read = field => getCred(service, `oauth_${field}`);
  const refreshToken = read('refresh_token');
  if (!refreshToken) throw reconnect(service);
  const tokenUrl = read('token_url');
  const clientId = read('client_id');
  const clientSecret = read('client_secret') ?? '';
  const style = read('auth_style') || 'header';
  if (!tokenUrl || !clientId || !['header', 'body'].includes(style)) throw refreshFailure();
  const form = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken });
  const headers = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' };
  if (style === 'header') headers.authorization = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;
  else { form.set('client_id', clientId); form.set('client_secret', clientSecret); }
  let response; let data;
  try {
    response = await fetchImpl(tokenUrl, { method: 'POST', headers, body: form.toString(),
      redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
    data = await response.json();
  } catch { throw refreshFailure(); }
  if (data?.error === 'invalid_grant') throw reconnect(service);
  if (!response.ok || data?.error || typeof data?.access_token !== 'string' || !data.access_token) throw refreshFailure();
  let expiresAt = null;
  if (data.expires_in !== undefined) {
    const seconds = Number(data.expires_in);
    const expiry = Date.now() + seconds * 1000;
    if (!Number.isFinite(seconds) || seconds < 0 || !Number.isFinite(new Date(expiry).getTime())) throw refreshFailure();
    expiresAt = new Date(expiry).toISOString();
  }
  setCred(service, 'oauth_access_token', data.access_token);
  if (typeof data.refresh_token === 'string' && data.refresh_token) setCred(service, 'oauth_refresh_token', data.refresh_token);
  if (expiresAt) setCred(service, 'oauth_expires_at', expiresAt);
  else deleteCred(service, 'oauth_expires_at'); // A new token without a lifetime must not retain the old expired timestamp.
  if (typeof data.token_type === 'string') setCred(service, 'oauth_token_type', data.token_type);
  if (typeof data.scope === 'string') setCred(service, 'oauth_scope', data.scope);
  return data.access_token;
}

export async function resolveAuth(service, fetchImpl = globalThis.fetch, timeoutMs = 30000) {
  const stored = getCred(service, 'api_key');
  if (stored) return stored;
  const fromEnv = process.env[envNameFor(service)];
  if (fromEnv) return fromEnv;
  const accessToken = getCred(service, 'oauth_access_token');
  if (!accessToken) return null;
  const expiry = getCred(service, 'oauth_expires_at');
  if (expiry && (!Number.isFinite(Date.parse(expiry)) || Date.parse(expiry) <= Date.now())) {
    if (!getCred(service, 'oauth_refresh_token')) throw reconnect(service);
    return refreshOAuth(service, fetchImpl, timeoutMs);
  }
  return accessToken;
}

export function parseArgs(args) {
  const [command, ...rest] = args;
  if (command !== 'request') throw usage(USAGE);
  const req = { url: null, method: null, headers: [], data: undefined, dataFile: undefined, auth: undefined, timeout: 30000 };
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    const value = () => {
      if (i + 1 >= rest.length) throw usage(`missing value for ${a}`);
      return rest[++i];
    };
    if (a === '--method') req.method = value().toUpperCase();
    else if (a === '--header') req.headers.push(value());
    else if (a === '--data') req.data = value();
    else if (a === '--data-file') req.dataFile = value();
    else if (a === '--auth') req.auth = value();
    else if (a === '--timeout') {
      req.timeout = Number(value());
      if (!Number.isSafeInteger(req.timeout) || req.timeout < 1) throw usage('--timeout must be a positive integer (ms)');
    } else if (a.startsWith('--')) throw usage(`unknown option: ${a}`);
    else if (req.url === null) req.url = a;
    else throw usage(`unexpected argument: ${a}`);
  }
  if (!req.url) throw usage(USAGE);
  let parsed;
  try { parsed = new URL(req.url); } catch { throw usage(`invalid url: ${req.url}`); }
  if (!/^https?:$/.test(parsed.protocol)) throw usage(`unsupported protocol: ${parsed.protocol}`);
  if (req.data !== undefined && req.dataFile !== undefined) throw usage('use only one of --data and --data-file');
  for (const h of req.headers) {
    if (!/^[^:\s]+\s*:/.test(h)) throw usage(`header must look like "Name: value": ${h}`);
  }
  return req;
}

function headerPairs(list) {
  return list.map((h) => {
    const idx = h.indexOf(':');
    return [h.slice(0, idx).trim(), h.slice(idx + 1).trim()];
  });
}

// Performs the request. `fetchImpl` is injectable for tests.
export async function request(req, fetchImpl = globalThis.fetch) {
  const headers = new Headers(headerPairs(req.headers));
  const secrets = [];
  const redact = value => secrets.reduce((text, secret) => text.split(secret).join('[REDACTED]'), String(value));
  let body = req.data;
  if (req.dataFile !== undefined) body = await readFile(req.dataFile, 'utf8');
  const method = req.method || (body !== undefined ? 'POST' : 'GET');
  if (body !== undefined && !headers.has('content-type')) {
    let isJson = false;
    try { JSON.parse(body); isJson = true; } catch { /* plain text */ }
    headers.set('content-type', isJson ? 'application/json' : 'text/plain; charset=utf-8');
  }
  if (req.auth !== undefined) {
    for (const field of ['api_key', 'oauth_access_token', 'oauth_refresh_token', 'oauth_client_secret']) {
      const value = getCred(req.auth, field);
      if (value) secrets.push(value);
    }
    const key = await resolveAuth(req.auth, fetchImpl, req.timeout);
    if (!key) {
      throw Object.assign(new Error(`no API key or OAuth token for service ${req.auth}: run \`lmconn cred set ${req.auth} api_key --env ${envNameFor(req.auth)}\` or \`lmconn oauth authorize ${req.auth}\``), { code: 'MISSING_KEY' });
    }
    secrets.push(key);
    const rotated = getCred(req.auth, 'oauth_refresh_token');
    if (rotated) secrets.push(rotated);
    headers.set('authorization', `Bearer ${key}`);
  }
  if (!headers.has('accept')) headers.set('accept', 'application/json, text/*;q=0.9, */*;q=0.8');
  const started = performance.now();
  let response;
  try {
    response = await fetchImpl(req.url, {
      method, headers, body: (method === 'GET' || method === 'HEAD') ? undefined : body,
      redirect: 'follow', signal: AbortSignal.timeout(req.timeout),
    });
  } catch (err) {
    const timedOut = err?.name === 'TimeoutError' || err?.name === 'AbortError';
    throw Object.assign(new Error(timedOut ? `request timed out after ${req.timeout} ms` : `request failed: ${redact(err?.cause?.message || err?.message || err)}`),
      { code: timedOut ? 'TIMEOUT' : 'NETWORK' });
  }
  const text = await response.text();
  const latencyMs = Math.round(performance.now() - started);
  const contentType = response.headers.get('content-type') || null;
  const result = { status: response.status, ok: response.status < 400, contentType, latencyMs, url: response.url || req.url };
  let bodyJson;
  if (text.length) {
    try { bodyJson = JSON.parse(text); } catch { /* not JSON */ }
  }
  if (bodyJson !== undefined) result.bodyJson = bodyJson; else result.bodyText = text;
  // An echo service may return the Authorization header; redact credential values there too.
  const sanitize = value => {
    if (typeof value === 'string') return redact(value);
    if (Array.isArray(value)) return value.map(sanitize);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [redact(k), sanitize(v)]));
    return value;
  };
  return sanitize(result);
}

export async function run(args, deps = {}) {
  try {
    const req = parseArgs(args);
    emit(ok(await request(req, deps.fetch)));
    return 0;
  } catch (err) {
    const known = ['USAGE', 'MISSING_KEY', 'TIMEOUT', 'NETWORK', 'RECONNECT', 'OAUTH_REFRESH'];
    if (known.includes(err.code)) return emitFail(err.code, err.message);
    if (err.code === 'ENOENT') return emitFail('USAGE', `cannot read --data-file: ${err.path}`);
    return emitFail('HTTP_ERROR', `http request failed: ${err.message}`);
  }
}
