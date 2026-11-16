// `lmconn saml` — SAML 2.0 Identity Provider & Service Provider connector (lmsaml REST + XML metadata/assertion client).
//
// Operations:
//   lmconn saml ping      [--host H] [--port P] [--url URL]
//   lmconn saml metadata  [--host H] [--port P] [--url URL]
//   lmconn saml sp-metadata [--host H] [--port P] [--url URL]
//   lmconn saml users     [--host H] [--port P] [--url URL]
//   lmconn saml user-get  --user <name>
//   lmconn saml user-add  --user <name> [--email E] [--password PW] [--attributes JSON]
//   lmconn saml user-del  --user <name>
//   lmconn saml authn     --user <name> --password <pw>
//   lmconn saml assertion [--user <name>] [--audience <url>] [--acs-url <url>] [--request-id <id>]
//   lmconn saml verify    --response <b64_or_xml> [--audience <url>] [--acs-url <url>] [--request-id <id>]

import { parseArgs } from './args.js';
import { emit, ok, emitFail } from './result.js';
import { request } from './http.js';
import { getCredential } from './creds.js';

function resolveConn(flags) {
  let host = flags.host || '127.0.0.1';
  let port = Number(flags.port || 8080);
  let baseUrl = flags.url || '';
  let user = flags.adminUser || flags['admin-user'] || '';
  let password = flags.adminPassword || flags['admin-password'] || '';

  if (flags.cred) {
    const c = getCredential(String(flags.cred));
    if (!c) {
      const err = new Error(`credential not found: ${flags.cred}`);
      err.code = 'CRED_NOT_FOUND';
      throw err;
    }
    const s = c.secret;
    if (s && typeof s === 'object') {
      if (s.url && !flags.url) baseUrl = String(s.url);
      if (s.host && !flags.host) host = String(s.host);
      if (s.port && !flags.port) port = Number(s.port);
      if (s.user && !user) user = String(s.user);
      if (s.password && !password) password = String(s.password);
    }
  }

  if (!baseUrl) {
    baseUrl = `http://${host}:${port}`;
  }
  baseUrl = baseUrl.replace(/\/+$/, '');
  return { host, port, baseUrl, user, password };
}

function authHeaders(conn) {
  const headers = { Accept: 'application/json' };
  if (conn.user && conn.password) {
    const b64 = Buffer.from(`${conn.user}:${conn.password}`).toString('base64');
    headers.Authorization = `Basic ${b64}`;
  } else if (conn.password) {
    headers.Authorization = `Bearer ${conn.password}`;
  }
  return headers;
}

export async function run(argv) {
  const { positionals, flags } = parseArgs(argv, {
    booleans: ['help'],
  });
  const sub = positionals[0];
  if (!sub || flags.help) {
    return emitFail('USAGE', 'usage: lmconn saml <ping|metadata|sp-metadata|users|user-get|user-add|user-del|authn|assertion|verify> [--host H] [--port P] [--url URL]');
  }

  let conn;
  try {
    conn = resolveConn(flags);
  } catch (err) {
    return emitFail(err.code || 'SAML_CONFIG_ERROR', err.message);
  }

  try {
    const headers = authHeaders(conn);
    switch (sub) {
      case 'ping': {
        const res = await request({ method: 'GET', url: `${conn.baseUrl}/ping`, headers });
        if (!res.ok) return emitFail('SAML_ERROR', `REST ping HTTP ${res.status}`, { status: res.status });
        emit(ok({ result: res.json?.result || 'PONG', service: res.json?.service || 'lmsaml', status: res.status }));
        return 0;
      }
      case 'metadata': {
        const res = await request({
          method: 'GET',
          url: `${conn.baseUrl}/idp/metadata`,
          headers: { ...headers, Accept: 'application/samlmetadata+xml, application/xml, text/xml' },
        });
        if (!res.ok) return emitFail('SAML_ERROR', `IdP metadata HTTP ${res.status}`, { status: res.status });
        emit(ok({ xml: res.body, contentType: res.headers['content-type'] || '' }));
        return 0;
      }
      case 'sp-metadata': {
        const res = await request({
          method: 'GET',
          url: `${conn.baseUrl}/sp/metadata`,
          headers: { ...headers, Accept: 'application/samlmetadata+xml, application/xml, text/xml' },
        });
        if (!res.ok) return emitFail('SAML_ERROR', `SP metadata HTTP ${res.status}`, { status: res.status });
        emit(ok({ xml: res.body, contentType: res.headers['content-type'] || '' }));
        return 0;
      }
      case 'users': {
        const res = await request({ method: 'GET', url: `${conn.baseUrl}/users`, headers });
        if (!res.ok) return emitFail('SAML_ERROR', `users HTTP ${res.status}`, { status: res.status });
        emit(ok({ users: res.json?.users || [] }));
        return 0;
      }
      case 'user-get': {
        const user = flags.user ?? positionals[1];
        if (!user) return emitFail('USAGE', 'saml user-get requires --user <name>');
        const res = await request({ method: 'GET', url: `${conn.baseUrl}/users/${encodeURIComponent(String(user))}`, headers });
        if (res.status === 404) {
          emit(ok({ user: String(user), found: false, entry: null }));
          return 0;
        }
        if (!res.ok) return emitFail('SAML_ERROR', `user-get HTTP ${res.status}`, { status: res.status });
        emit(ok({ user: String(user), found: true, entry: res.json }));
        return 0;
      }
      case 'user-add': {
        const user = flags.user ?? positionals[1];
        if (!user) return emitFail('USAGE', 'saml user-add requires --user <name>');
        let bodyObj = {};
        if (flags.attributes) {
          bodyObj = typeof flags.attributes === 'string' ? JSON.parse(flags.attributes) : flags.attributes;
        }
        if (flags.email) bodyObj.email = String(flags.email);
        if (flags.password) bodyObj.password = String(flags.password);
        if (flags['common-name']) bodyObj.common_name = String(flags['common-name']);
        const res = await request({
          method: 'PUT',
          url: `${conn.baseUrl}/users/${encodeURIComponent(String(user))}`,
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify(bodyObj),
        });
        if (!res.ok) return emitFail('SAML_ERROR', `user-add HTTP ${res.status}`, { status: res.status, body: res.json });
        emit(ok({ user: String(user), result: res.json?.result || 'OK', entry: res.json?.user || null }));
        return 0;
      }
      case 'user-del': {
        const user = flags.user ?? positionals[1];
        if (!user) return emitFail('USAGE', 'saml user-del requires --user <name>');
        const res = await request({
          method: 'DELETE',
          url: `${conn.baseUrl}/users/${encodeURIComponent(String(user))}`,
          headers,
        });
        const deleted = res.ok ? 1 : 0;
        emit(ok({ user: String(user), deleted }));
        return 0;
      }
      case 'authn': {
        const user = flags.user ?? positionals[1];
        const password = flags.password ?? positionals[2] ?? '';
        if (!user) return emitFail('USAGE', 'saml authn requires --user <name> --password <pw>');
        const res = await request({
          method: 'POST',
          url: `${conn.baseUrl}/authn`,
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: String(user), password: String(password) }),
        });
        if (!res.ok) return emitFail('SAML_AUTH_FAILED', res.json?.error || `HTTP ${res.status}`, { status: res.status });
        emit(ok({ authenticated: true, user: res.json?.user || { name: String(user) } }));
        return 0;
      }
      case 'assertion': {
        const user = flags.user ?? positionals[1] ?? 'admin';
        const audience = flags.audience || '';
        const acsUrl = flags['acs-url'] || flags.acsUrl || '';
        const requestId = flags['request-id'] || flags.requestId || '';
        const res = await request({
          method: 'POST',
          url: `${conn.baseUrl}/assertion`,
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            user: String(user),
            audience: String(audience),
            acs_url: String(acsUrl),
            request_id: String(requestId),
          }),
        });
        if (!res.ok) return emitFail('SAML_ERROR', res.json?.error || `HTTP ${res.status}`, { status: res.status });
        emit(ok(res.json));
        return 0;
      }
      case 'verify': {
        const responsePayload = flags.response ?? positionals[1];
        if (!responsePayload) return emitFail('USAGE', 'saml verify requires --response <b64_or_xml>');
        const audience = flags.audience || '';
        const acsUrl = flags['acs-url'] || flags.acsUrl || '';
        const requestId = flags['request-id'] || flags.requestId || '';
        const res = await request({
          method: 'POST',
          url: `${conn.baseUrl}/verify`,
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            saml_response_b64: String(responsePayload),
            audience: String(audience),
            acs_url: String(acsUrl),
            request_id: String(requestId),
          }),
        });
        if (!res.ok) return emitFail('SAML_VERIFY_FAILED', res.json?.error || `HTTP ${res.status}`, { status: res.status });
        emit(ok(res.json));
        return 0;
      }
      default:
        return emitFail('USAGE', `unknown saml subcommand: ${sub}`);
    }
  } catch (err) {
    return emitFail(err.code || 'SAML_ERROR', err.message || String(err));
  }
}

const CONN_PARAMS = {
  host:    { type: 'string', description: 'SAML server host (default 127.0.0.1)' },
  port:    { type: 'number', description: 'SAML server port (default 8080)' },
  url:     { type: 'string', description: 'Base URL override' },
  cred:    { type: 'string', description: 'Credential store entry name' },
};

export const ops = [
  { name: 'ping', access: 'read', description: 'Ping a SAML 2.0 server (lmsaml)', params: { ...CONN_PARAMS } },
  { name: 'metadata', access: 'read', description: 'Fetch SAML 2.0 IdP EntityDescriptor XML metadata', params: { ...CONN_PARAMS } },
  { name: 'sp_metadata', subcommand: 'sp-metadata', access: 'read', description: 'Fetch SAML 2.0 SP EntityDescriptor XML metadata', params: { ...CONN_PARAMS } },
  { name: 'users', access: 'read', description: 'List SAML IdP users', params: { ...CONN_PARAMS } },
  { name: 'user_get', subcommand: 'user-get', access: 'read', description: 'Get a SAML IdP user by username', params: { ...CONN_PARAMS, user: { type: 'string', required: true } } },
  { name: 'user_add', subcommand: 'user-add', access: 'write', description: 'Create or update a SAML IdP user', params: { ...CONN_PARAMS, user: { type: 'string', required: true }, email: { type: 'string' }, password: { type: 'string' }, attributes: { type: 'string' } } },
  { name: 'user_del', subcommand: 'user-del', access: 'write', description: 'Delete a SAML IdP user', params: { ...CONN_PARAMS, user: { type: 'string', required: true } } },
  { name: 'authn', access: 'read', description: 'Authenticate a SAML IdP user', params: { ...CONN_PARAMS, user: { type: 'string', required: true }, password: { type: 'string', required: true } } },
  { name: 'assertion', access: 'read', description: 'Issue a cryptographically signed SAML 2.0 Response & Assertion', params: { ...CONN_PARAMS, user: { type: 'string' }, audience: { type: 'string' }, 'acs-url': { type: 'string' }, 'request-id': { type: 'string' } } },
  { name: 'verify', access: 'read', description: 'Cryptographically verify a signed SAML 2.0 Response & Assertion', params: { ...CONN_PARAMS, response: { type: 'string', required: true }, audience: { type: 'string' }, 'acs-url': { type: 'string' }, 'request-id': { type: 'string' } } },
];
