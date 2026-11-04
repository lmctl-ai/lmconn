// Shared OAuth grammar and secrecy rules. No credential value belongs in an error.
export function securityError(message = 'Credential policy refused this operation', code = 'CREDENTIAL_POLICY') {
  return Object.assign(new Error(message), { code });
}
export function unsafeText(value) {
  for (const c of String(value)) {
    const n = c.codePointAt(0);
    if (n < 32 || (n >= 127 && n <= 159) || n === 0x200e || n === 0x200f ||
        (n >= 0x202a && n <= 0x202e) || (n >= 0x2066 && n <= 0x2069)) return true;
  }
  return false;
}
export function endpoint(value, label = 'OAuth endpoint', originOnly = false) {
  let url;
  try { if (typeof value !== 'string' || value !== value.trim() || unsafeText(value) || value.includes('\\')) throw Error(); url = new URL(value); }
  catch { throw securityError(label + ' must be a safe HTTPS URL (literal loopback HTTP is allowed)', 'USAGE'); }
  const authority = value.slice(value.indexOf('://') + 3).split('/')[0].split('?')[0].split('#')[0];
  const rawHost = authority.startsWith('[') ? authority.slice(0, authority.indexOf(']') + 1) : authority.split(':')[0];
  const literalLoopback = ['127.0.0.1', '[::1]'].includes(url.hostname) &&
    rawHost === url.hostname;
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && literalLoopback)) || url.username || url.password ||
      value.includes('#') || (originOnly && (url.pathname !== '/' || url.search))) {
    throw securityError(label + ' must be HTTPS or literal loopback HTTP without userinfo or fragment', 'USAGE');
  }
  return url;
}
export function origins(values) {
  if (!Array.isArray(values) || values.length === 0) throw securityError('At least one allowed origin is required');
  return [...new Set(values.map(v => endpoint(v, 'Allowed origin', true).origin))].sort();
}
export function secretVariants(secrets) {
  const result = new Set();
  for (const secret of secrets) if (typeof secret === 'string' && secret) {
    const encoded = encodeURIComponent(Buffer.from(secret).toString('utf8'));
    result.add(secret); result.add(encoded);
    result.add(encoded.split('%').map((part, i) => i ? part.slice(0, 2).toLowerCase() + part.slice(2) : part).join('%'));
    result.add(new URLSearchParams({ v: secret }).toString().slice(2));
    result.add(Buffer.from(secret).toString('base64')); result.add(Buffer.from(secret).toString('base64url'));
  }
  return [...result].sort((a, b) => b.length - a.length);
}
export function redact(value, secrets) {
  const variants = secretVariants(secrets);
  const text = s => variants.reduce((v, secret) => v.split(secret).join('[REDACTED]'), s);
  function visit(v) {
    if (typeof v === 'string') return text(v);
    if (Array.isArray(v)) return v.map(visit);
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [text(k), visit(x)]));
    return v;
  }
  return visit(value);
}
export function safeMetadata(value, secrets) {
  const result = redact(value, secrets);
  function display(v) {
    if (typeof v === 'string') return [...v].map(c => unsafeText(c) ? '[U+' + c.codePointAt(0).toString(16).toUpperCase() + ']' : c).join('');
    if (Array.isArray(v)) return v.map(display);
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [display(k), display(x)]));
    return v;
  }
  return display(result);
}
export function scopeText(value, requested = '', secrets = []) {
  if (typeof value !== 'string' || unsafeText(value) || redact(value, secrets) !== value) throw securityError('Invalid OAuth scope', 'OAUTH_ERROR');
  for (const c of value) { const n = c.codePointAt(0); if (n < 32 || n > 126 || n === 34 || n === 92) throw securityError('Invalid OAuth scope', 'OAUTH_ERROR'); }
  const words = value.split(' ').filter(Boolean), allowed = String(requested).split(' ').filter(Boolean);
  if (allowed.length && words.some(word => !allowed.includes(word))) throw securityError('OAuth scope exceeds the requested scope', 'OAUTH_ERROR');
  return words.join(' ');
}
export function validSecret(value) {
  if (typeof value !== 'string' || !value || unsafeText(value)) return false;
  for (const c of value) if (c.codePointAt(0) >= 0xd800 && c.codePointAt(0) <= 0xdfff) return false;
  return true;
}
export function tokenResult(token, cfg, now = Date.now()) {
  if (!token || Array.isArray(token) || !validSecret(token.access_token) || token.error ||
      (token.refresh_token !== undefined && !validSecret(token.refresh_token)) ||
      (token.token_type !== undefined && (typeof token.token_type !== 'string' || unsafeText(token.token_type)))) {
    throw securityError('Invalid OAuth token response', 'OAUTH_ERROR');
  }
  if (token.scope !== undefined) token.scope = scopeText(token.scope, cfg.scope || '', [token.access_token, token.refresh_token, cfg['client-secret'], cfg.previousRefresh]);
  let expiresAt = null;
  if (token.expires_in !== undefined) {
    const seconds = Number(token.expires_in), date = new Date(now + seconds * 1000);
    if (!Number.isFinite(seconds) || seconds < 0 || !Number.isFinite(date.getTime())) throw securityError('Invalid OAuth expiry', 'OAUTH_ERROR');
    expiresAt = date.toISOString();
  }
  return { token, expiresAt };
}
function hex(c) { const n = c?.charCodeAt(0); return n >= 48 && n <= 57 || n >= 65 && n <= 70 || n >= 97 && n <= 102; }
export function callbackParameters(raw, redirect, state) {
  if (typeof raw !== 'string' || unsafeText(raw) || raw.includes('#') || raw.includes(' ') || raw.includes('\\')) throw Error('Invalid callback');
  for (let i = 0; i < raw.length; i++) if (raw[i] === '%') { if (!hex(raw[i + 1]) || !hex(raw[i + 2])) throw Error('Invalid callback encoding'); i += 2; }
  const url = new URL(raw), expected = new URL(redirect);
  if (url.origin !== expected.origin || url.pathname !== '/callback' || url.username || url.password) throw Error('Invalid callback origin');
  const params = new Map();
  for (const pair of url.search.slice(1).split('&')) {
    const at = pair.indexOf('='); if (at < 1) throw Error('Invalid callback parameter');
    const key = decodeURIComponent(pair.slice(0, at).replaceAll('+', ' ')), value = decodeURIComponent(pair.slice(at + 1).replaceAll('+', ' '));
    if (!['code', 'state', 'error', 'error_description', 'error_uri'].includes(key) || params.has(key) || unsafeText(value)) throw Error('Invalid callback parameter');
    params.set(key, value);
  }
  if (params.get('state') !== state || params.has('code') === params.has('error')) throw Error('Invalid callback state');
  if (params.has('code')) {
    const code = params.get('code'); if (!code || params.has('error_description') || params.has('error_uri')) throw Error('Invalid callback code');
    for (const c of code) if (c.codePointAt(0) > 126) throw Error('Invalid callback code');
  } else if (!params.get('error')) throw Error('Invalid callback error');
  return { code: params.get('code'), denied: params.has('error') };
}
