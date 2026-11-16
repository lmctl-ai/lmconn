// `lmconn saml` — SAML 2.0 Identity Provider & Service Provider connector (lmsaml REST + XML metadata/assertion client).
// Zero external dependencies.
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

import { emit, ok, emitFail } from './result.js';

const CONN_PARAMS = [
  { name: 'host', type: 'string', occurs: '?', default: '127.0.0.1', description: 'SAML server host' },
  { name: 'port', type: 'number', occurs: '?', default: 8080, description: 'SAML server port' },
  { name: 'url', type: 'string', occurs: '?', description: 'Base URL override' },
  { name: 'timeout', type: 'number', occurs: '?', default: 5000, description: 'Timeout in milliseconds' },
];

export const ops = [
  { name: 'saml ping', access: 'read', description: 'Ping a SAML 2.0 server (lmsaml)', params: [...CONN_PARAMS] },
  { name: 'saml metadata', access: 'read', description: 'Fetch SAML 2.0 IdP EntityDescriptor XML metadata', params: [...CONN_PARAMS] },
  { name: 'saml sp-metadata', access: 'read', description: 'Fetch SAML 2.0 SP EntityDescriptor XML metadata', params: [...CONN_PARAMS] },
  { name: 'saml users', access: 'read', description: 'List SAML IdP users', params: [...CONN_PARAMS] },
  { name: 'saml user-get', access: 'read', description: 'Get a SAML IdP user by username', params: [
    { name: 'user', type: 'string', occurs: '1', description: 'Username' },
    ...CONN_PARAMS,
  ] },
  { name: 'saml user-add', access: 'write', description: 'Create or update a SAML IdP user', params: [
    { name: 'user', type: 'string', occurs: '1', description: 'Username' },
    { name: 'email', type: 'string', occurs: '?', description: 'User email' },
    { name: 'password', type: 'string', occurs: '?', description: 'User password' },
    { name: 'attributes', type: 'string', occurs: '?', description: 'Additional user attributes JSON' },
    ...CONN_PARAMS,
  ] },
  { name: 'saml user-del', access: 'write', description: 'Delete a SAML IdP user', params: [
    { name: 'user', type: 'string', occurs: '1', description: 'Username' },
    ...CONN_PARAMS,
  ] },
  { name: 'saml authn', access: 'read', description: 'Authenticate a SAML IdP user', params: [
    { name: 'user', type: 'string', occurs: '1', description: 'Username' },
    { name: 'password', type: 'string', occurs: '1', description: 'Password' },
    ...CONN_PARAMS,
  ] },
  { name: 'saml assertion', access: 'read', description: 'Issue a cryptographically signed SAML 2.0 Response & Assertion', params: [
    { name: 'user', type: 'string', occurs: '?', default: 'admin', description: 'Username' },
    { name: 'audience', type: 'string', occurs: '?', description: 'SP EntityID / Audience URL' },
    { name: 'acs-url', type: 'string', occurs: '?', description: 'Assertion Consumer Service URL' },
    { name: 'request-id', type: 'string', occurs: '?', description: 'AuthnRequest ID' },
    ...CONN_PARAMS,
  ] },
  { name: 'saml verify', access: 'read', description: 'Cryptographically verify a signed SAML 2.0 Response & Assertion', params: [
    { name: 'response', type: 'string', occurs: '1', description: 'Base64 or XML SAML 2.0 Response' },
    { name: 'audience', type: 'string', occurs: '?', description: 'Expected SP EntityID / Audience' },
    { name: 'acs-url', type: 'string', occurs: '?', description: 'Expected ACS URL' },
    { name: 'request-id', type: 'string', occurs: '?', description: 'Expected InResponseTo ID' },
    ...CONN_PARAMS,
  ] },
];

function parseCliArgs(args) {
  const flags = {};
  const positionals = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--help' || a === '-h') {
      flags.help = true;
    } else if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq >= 0) {
        flags[a.slice(2, eq)] = a.slice(eq + 1);
      } else if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        flags[a.slice(2)] = args[++i];
      } else {
        flags[a.slice(2)] = true;
      }
    } else {
      positionals.push(a);
    }
  }
  return { flags, positionals };
}

async function httpReq(url, { method = 'GET', headers = {}, body, timeout = 5000 } = {}) {
  const res = await fetch(url, {
    method,
    headers,
    body,
    signal: AbortSignal.timeout(timeout),
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {}
  return { ok: res.ok, status: res.status, headers: res.headers, body: text, json };
}

export async function run(argv) {
  const { flags, positionals } = parseCliArgs(argv);
  const sub = positionals[0];
  if (!sub || flags.help) {
    return emitFail('USAGE', 'usage: lmconn saml <ping|metadata|sp-metadata|users|user-get|user-add|user-del|authn|assertion|verify> [--host H] [--port P] [--url URL]');
  }

  const host = flags.host || process.env.SAML_HOST || '127.0.0.1';
  const port = Number(flags.port || process.env.SAML_PORT || 8080);
  const timeout = Number(flags.timeout || 5000);
  const baseUrl = String(flags.url || `http://${host}:${port}`).replace(/\/+$/, '');
  const headers = { Accept: 'application/json' };
  if (flags['admin-user'] && flags['admin-password']) {
    const b64 = Buffer.from(`${flags['admin-user']}:${flags['admin-password']}`).toString('base64');
    headers.Authorization = `Basic ${b64}`;
  } else if (flags['admin-password']) {
    headers.Authorization = `Bearer ${flags['admin-password']}`;
  }

  try {
    switch (sub) {
      case 'ping': {
        const res = await httpReq(`${baseUrl}/ping`, { headers, timeout });
        if (!res.ok) return emitFail('SAML_ERROR', `REST ping HTTP ${res.status}`, { status: res.status });
        emit(ok({ result: res.json?.result || 'PONG', service: res.json?.service || 'lmsaml', status: res.status }));
        return 0;
      }
      case 'metadata': {
        const res = await httpReq(`${baseUrl}/idp/metadata`, {
          headers: { ...headers, Accept: 'application/samlmetadata+xml, application/xml, text/xml' },
          timeout,
        });
        if (!res.ok) return emitFail('SAML_ERROR', `IdP metadata HTTP ${res.status}`, { status: res.status });
        emit(ok({ xml: res.body, contentType: res.headers.get('content-type') || '' }));
        return 0;
      }
      case 'sp-metadata': {
        const res = await httpReq(`${baseUrl}/sp/metadata`, {
          headers: { ...headers, Accept: 'application/samlmetadata+xml, application/xml, text/xml' },
          timeout,
        });
        if (!res.ok) return emitFail('SAML_ERROR', `SP metadata HTTP ${res.status}`, { status: res.status });
        emit(ok({ xml: res.body, contentType: res.headers.get('content-type') || '' }));
        return 0;
      }
      case 'users': {
        const res = await httpReq(`${baseUrl}/users`, { headers, timeout });
        if (!res.ok) return emitFail('SAML_ERROR', `users HTTP ${res.status}`, { status: res.status });
        emit(ok({ users: res.json?.users || [] }));
        return 0;
      }
      case 'user-get': {
        const user = flags.user ?? positionals[1];
        if (!user) return emitFail('USAGE', 'saml user-get requires --user <name>');
        const res = await httpReq(`${baseUrl}/users/${encodeURIComponent(String(user))}`, { headers, timeout });
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
        const res = await httpReq(`${baseUrl}/users/${encodeURIComponent(String(user))}`, {
          method: 'PUT',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify(bodyObj),
          timeout,
        });
        if (!res.ok) return emitFail('SAML_ERROR', `user-add HTTP ${res.status}`, { status: res.status, body: res.json });
        emit(ok({ user: String(user), result: res.json?.result || 'OK', entry: res.json?.user || null }));
        return 0;
      }
      case 'user-del': {
        const user = flags.user ?? positionals[1];
        if (!user) return emitFail('USAGE', 'saml user-del requires --user <name>');
        const res = await httpReq(`${baseUrl}/users/${encodeURIComponent(String(user))}`, {
          method: 'DELETE',
          headers,
          timeout,
        });
        const deleted = res.ok ? 1 : 0;
        emit(ok({ user: String(user), deleted }));
        return 0;
      }
      case 'authn': {
        const user = flags.user ?? positionals[1];
        const password = flags.password ?? positionals[2] ?? '';
        if (!user) return emitFail('USAGE', 'saml authn requires --user <name> --password <pw>');
        const res = await httpReq(`${baseUrl}/authn`, {
          method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: String(user), password: String(password) }),
          timeout,
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
        const res = await httpReq(`${baseUrl}/assertion`, {
          method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            user: String(user),
            audience: String(audience),
            acs_url: String(acsUrl),
            request_id: String(requestId),
          }),
          timeout,
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
        const res = await httpReq(`${baseUrl}/verify`, {
          method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            saml_response_b64: String(responsePayload),
            audience: String(audience),
            acs_url: String(acsUrl),
            request_id: String(requestId),
          }),
          timeout,
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
