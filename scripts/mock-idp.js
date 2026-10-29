// Strict mock OAuth2 authorization server (RFC 6749 + PKCE RFC 7636).
// Strict enough that n8n's own OAuth2 client can complete the flow against
// it; used by test/oauth.test.js, the adversarial suite, the runnable demo
// examples/oauth-mock-demo.lms, and scripts/verify-n8n-oauth.mjs.
//
// Node builtins only. Not shipped in the compiled binary.
//
//   import { createMockIdP } from '../scripts/mock-idp.js';
//   const idp = await createMockIdP({ port: 0 });
//   idp.registerClient({ clientId, clientSecret, redirectUris: [...], authStyle: 'header'|'body'|'both' });
//   // endpoints: idp.authUrl, idp.tokenUrl, idp.userinfoUrl  (origin = http://127.0.0.1:PORT)
//   // idp.log: every request, { method, path, params, authStyle: 'header'|'body'|null } (no secrets)
//   await idp.close();
import { createServer } from 'node:http';
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';

const base64url = (buf) => Buffer.from(buf).toString('base64url');
const s256 = (verifier) => base64url(createHash('sha256').update(verifier).digest());

export async function createMockIdP(options = {}) {
  const {
    port = 0,
    expiresIn = 3600,
    rotateRefreshTokens = false,
    formEncodedTokenResponse = false,
    requirePkce = false,
    allowPlainPkce = false,
    misbehave = null, // null | 'bad-state' | 'bad-json' | 'string-expires' — adversarial modes
  } = options;

  const clients = new Map();   // clientId -> { clientSecret, redirectUris, authStyle }
  const codes = new Map();     // code -> { clientId, redirectUri, challenge, challengeMethod, scope, expiresAt }
  const tokens = new Map();    // accessToken -> { clientId, scope, refreshToken }
  const refreshTokens = new Map(); // refreshToken -> { clientId, scope }
  const log = [];

  function fail(res, status, error, description) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error, ...(description && { error_description: description }) }));
  }
  function clientAuth(req, params) {
    const header = req.headers.authorization;
    if (header?.startsWith('Basic ')) {
      const [id, secret] = Buffer.from(header.slice(6), 'base64').toString('utf8').split(':');
      return { id: decodeURIComponent(id), secret: decodeURIComponent(secret ?? ''), style: 'header' };
    }
    if (params.client_id) return { id: params.client_id, secret: params.client_secret ?? '', style: 'body' };
    return { id: null, secret: null, style: null };
  }
  function checkClient(res, auth) {
    const client = auth.id && clients.get(auth.id);
    if (!client) { fail(res, 401, 'invalid_client', 'unknown client'); return null; }
    const okSecret = timingSafeEqual(Buffer.from(auth.secret.padEnd(64)), Buffer.from((client.clientSecret ?? '').padEnd(64)));
    if (!okSecret) { fail(res, 401, 'invalid_client', 'bad secret'); return null; }
    if (client.authStyle !== 'both' && auth.style !== client.authStyle) {
      fail(res, 401, 'invalid_client', `client must authenticate via ${client.authStyle}`); return null;
    }
    return client;
  }

  async function authorize(req, res, url) {
    const p = url.searchParams;
    const params = Object.fromEntries(p);
    log.push({ method: 'GET', path: '/authorize', params: { ...params, client_id: params.client_id }, authStyle: null });
    const client = clients.get(p.get('client_id') ?? '');
    const redirect = p.get('redirect_uri') ?? '';
    if (!client) return fail(res, 400, 'invalid_request', 'unknown client_id');
    if (!client.redirectUris.includes(redirect)) return fail(res, 400, 'invalid_request', 'redirect_uri mismatch');
    const bounce = (kv) => { res.writeHead(302, { Location: redirect + (redirect.includes('?') ? '&' : '?') + kv }); res.end(); };
    if (p.get('response_type') !== 'code') return bounce('error=unsupported_response_type&state=' + encodeURIComponent(p.get('state') ?? ''));
    const challenge = p.get('code_challenge');
    const method = p.get('code_challenge_method') ?? (challenge ? 'plain' : null);
    if (!challenge && requirePkce) return fail(res, 400, 'invalid_request', 'code_challenge required');
    if (challenge && method !== 'S256' && !(method === 'plain' && allowPlainPkce)) return fail(res, 400, 'invalid_request', 'unsupported code_challenge_method');
    const code = base64url(randomBytes(24));
    codes.set(code, { clientId: client.clientId ?? p.get('client_id'), redirectUri: redirect, challenge, challengeMethod: method, scope: p.get('scope') ?? '', expiresAt: Date.now() + 60000 });
    const state = misbehave === 'bad-state' ? 'tampered-state' : (p.get('state') ?? '');
    bounce(`code=${code}&state=${encodeURIComponent(state)}`);
  }

  async function token(req, res) {
    const params = Object.fromEntries(new URLSearchParams(await readBody(req)));
    const auth = clientAuth(req, params);
    log.push({ method: 'POST', path: '/token', params: { grant_type: params.grant_type, code: params.code ? '(redacted)' : undefined, refresh_token: params.refresh_token ? '(redacted)' : undefined }, authStyle: auth.style });
    const client = checkClient(res, auth);
    if (!client) return;
    const respond = (payload) => {
      const body = misbehave === 'bad-json' ? '{"access_token":' : formEncodedTokenResponse ? new URLSearchParams(payload).toString() : JSON.stringify(payload);
      res.writeHead(200, { 'Content-Type': formEncodedTokenResponse ? 'application/x-www-form-urlencoded' : 'application/json' });
      res.end(body);
    };
    if (params.grant_type === 'authorization_code') {
      const grant = codes.get(params.code ?? '');
      if (!grant || grant.expiresAt < Date.now()) return fail(res, 400, 'invalid_grant', 'unknown or expired code');
      codes.delete(params.code); // one-time use
      if (grant.clientId !== auth.id) return fail(res, 400, 'invalid_grant', 'code was issued to another client');
      if (params.redirect_uri !== grant.redirectUri) return fail(res, 400, 'invalid_grant', 'redirect_uri mismatch');
      if (grant.challenge) {
        const v = params.code_verifier;
        if (!v || v.length < 43 || v.length > 128) return fail(res, 400, 'invalid_grant', 'bad code_verifier');
        const okVerifier = grant.challengeMethod === 'S256' ? s256(v) === grant.challenge : v === grant.challenge;
        if (!okVerifier) return fail(res, 400, 'invalid_grant', 'code_verifier mismatch');
      }
      return issue(respond, auth.id, grant.scope);
    }
    if (params.grant_type === 'refresh_token') {
      const rt = refreshTokens.get(params.refresh_token ?? '');
      if (!rt || rt.clientId !== auth.id) return fail(res, 400, 'invalid_grant', 'unknown refresh_token');
      if (rotateRefreshTokens) refreshTokens.delete(params.refresh_token);
      return issue(respond, auth.id, rt.scope, rotateRefreshTokens ? null : params.refresh_token);
    }
    fail(res, 400, 'unsupported_grant_type', 'only authorization_code and refresh_token');
  }

  function issue(respond, clientId, scope, keepRefreshToken) {
    const access = base64url(randomBytes(24));
    const refresh = keepRefreshToken ?? base64url(randomBytes(24));
    tokens.set(access, { clientId, scope, refreshToken: refresh });
    refreshTokens.set(refresh, { clientId, scope });
    respond({
      access_token: access,
      refresh_token: refresh,
      token_type: 'Bearer',
      expires_in: misbehave === 'string-expires' ? String(expiresIn) : expiresIn,
      scope,
    });
  }

  function userinfo(req, res) {
    const header = req.headers.authorization ?? '';
    const token = header.startsWith('Bearer ') ? tokens.get(header.slice(7)) : null;
    log.push({ method: 'GET', path: '/api/userinfo', params: {}, authStyle: token ? 'bearer' : null });
    if (!token) {
      res.writeHead(401, { 'WWW-Authenticate': 'Bearer realm="mock-idp"' });
      return res.end(JSON.stringify({ error: 'invalid_token' }));
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ sub: 'mock-user-1', client_id: token.clientId, scope: token.scope }));
  }

  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/authorize' && req.method === 'GET') return authorize(req, res, url);
    if (url.pathname === '/token' && req.method === 'POST') return token(req, res);
    if (url.pathname === '/api/userinfo' && req.method === 'GET') return userinfo(req, res);
    fail(res, 404, 'invalid_request', 'unknown endpoint');
  });
  await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  return {
    origin,
    authUrl: `${origin}/authorize`,
    tokenUrl: `${origin}/token`,
    userinfoUrl: `${origin}/api/userinfo`,
    log,
    registerClient({ clientId, clientSecret = '', redirectUris, authStyle = 'both' }) {
      clients.set(clientId, { clientId, clientSecret, redirectUris, authStyle });
    },
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

// Standalone server for external clients (n8n): node scripts/mock-idp.js [--port 5556] [--once]
// --once exits 3 s after the first token grant (runnable end-to-end demos).
if (import.meta.url === `file://${process.argv[1]}`) {
  const flag = (name) => process.argv.includes(name);
  const port = Number(process.argv[process.argv.indexOf('--port') + 1] || 5556);
  const idp = await createMockIdP({ port });
  idp.registerClient({
    clientId: 'demo-client',
    clientSecret: 'demo-secret',
    redirectUris: [
      `http://127.0.0.1:${port === 0 ? 5556 : port}/callback`,
      'http://127.0.0.1:5558/callback',
      'http://localhost:5678/rest/oauth2-credential/callback',
      'http://127.0.0.1:5678/rest/oauth2-credential/callback',
    ],
    authStyle: 'both',
  });
  console.log(JSON.stringify({ authUrl: idp.authUrl, tokenUrl: idp.tokenUrl, userinfoUrl: idp.userinfoUrl, clientId: 'demo-client', clientSecret: 'demo-secret' }));
  if (flag('--once')) {
    const poll = setInterval(() => {
      if (idp.log.some((e) => e.path === '/token')) {
        clearInterval(poll);
        setTimeout(() => idp.close().then(() => process.exit(0)), 3000);
      }
    }, 100);
  }
}
