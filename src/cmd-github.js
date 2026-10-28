// Read-only GitHub connector over https://api.github.com:
//   lmconn github user                  the authenticated user (needs a token)
//   lmconn github repos <org> [--limit N]  repository names of an organisation (or user)
// Token: getCred('github','api_key'), then $GITHUB_TOKEN / $GH_TOKEN, then `gh auth token`,
// else anonymous (rate limited). The token never appears on stdout or stderr.

import { execFileSync } from 'node:child_process';
import { emit, ok, emitFail } from './result.js';
import { getCred } from './creds.js';

export const API = 'https://api.github.com';
const USAGE = 'usage: lmconn github user | lmconn github repos <org> [--limit N]';
const usage = (message) => Object.assign(new Error(message), { code: 'USAGE' });

export const ops = [
  { name: 'github_user', access: 'read', description: 'Return the authenticated GitHub user (login, name, id, publicRepos)', params: [] },
  { name: 'github_repos', access: 'read', description: 'List repository names of an organisation or user', params: [
    { name: 'org', type: 'string', positional: true, description: 'Organisation or user login' },
    { name: 'limit', type: 'number', occurs: '?', default: 30, description: 'Maximum number of names (1..1000)' },
  ] },
];

export function ghAuthToken(exec = execFileSync) {
  try {
    const out = exec('gh', ['auth', 'token'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 });
    const token = String(out).trim();
    return token || null;
  } catch { return null; }
}

// Returns { token, source } with source 'store' | 'env:NAME' | 'gh' | 'anonymous'.
export function resolveToken(exec) {
  const stored = getCred('github', 'api_key');
  if (stored) return { token: stored, source: 'store' };
  for (const name of ['GITHUB_TOKEN', 'GH_TOKEN']) {
    if (process.env[name]) return { token: process.env[name], source: `env:${name}` };
  }
  const fromGh = ghAuthToken(exec);
  if (fromGh) return { token: fromGh, source: 'gh' };
  return { token: null, source: 'anonymous' };
}

async function api(path, auth, fetchImpl) {
  const headers = { accept: 'application/vnd.github+json', 'user-agent': 'lmconn', 'x-github-api-version': '2022-11-28' };
  if (auth.token) headers.authorization = `Bearer ${auth.token}`;
  let response;
  try {
    response = await fetchImpl(API + path, { headers, signal: AbortSignal.timeout(30000) });
  } catch (err) {
    throw Object.assign(new Error(`GitHub request failed: ${err?.cause?.message || err?.message || err}`), { code: 'NETWORK' });
  }
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { /* keep null */ }
  if (!response.ok) {
    const detail = data?.message ? `: ${data.message}` : '';
    const hint = response.status === 401 || response.status === 403
      ? ` (auth: ${auth.source}; store a token with \`lmconn cred set github api_key --stdin\`)` : '';
    throw Object.assign(new Error(`GitHub ${path} -> HTTP ${response.status}${detail}${hint}`), { code: 'GITHUB_HTTP', status: response.status });
  }
  return { data, response };
}

export async function user(auth, fetchImpl) {
  if (!auth.token) throw Object.assign(new Error('github user needs a token: store one with `lmconn cred set github api_key --stdin`, export GITHUB_TOKEN, or log in with gh'), { code: 'MISSING_KEY' });
  const { data } = await api('/user', auth, fetchImpl);
  return { login: data.login, name: data.name ?? null, id: data.id, publicRepos: data.public_repos ?? null, auth: auth.source };
}

export async function repos(org, limit, auth, fetchImpl) {
  const names = [];
  let path = `/orgs/${encodeURIComponent(org)}/repos?per_page=${Math.min(limit, 100)}&sort=full_name`;
  let userFallback = false;
  for (let page = 1; names.length < limit && path; page++) {
    let result;
    try {
      result = await api(path, auth, fetchImpl);
    } catch (err) {
      // Not an organisation: fall back to the user endpoint once.
      if (err.status === 404 && !userFallback && page === 1) {
        userFallback = true;
        path = `/users/${encodeURIComponent(org)}/repos?per_page=${Math.min(limit, 100)}&sort=full_name`;
        page = 0;
        continue;
      }
      throw err;
    }
    if (!Array.isArray(result.data)) throw Object.assign(new Error('GitHub returned a non-list for repositories'), { code: 'INVALID_RESPONSE' });
    for (const r of result.data) if (names.length < limit) names.push(r.name);
    const link = result.response.headers.get('link') || '';
    const next = /<([^>]+)>;\s*rel="next"/.exec(link);
    path = next && result.data.length ? next[1].replace(API, '') : null;
    if (!result.data.length) break;
  }
  return { org, count: names.length, names, auth: auth.source };
}

export function parseArgs(args) {
  const [command, ...rest] = args;
  if (command === 'user') {
    if (rest.length) throw usage('usage: lmconn github user');
    return { command };
  }
  if (command === 'repos') {
    let org = null; let limit = 30;
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i];
      if (a === '--limit') {
        if (i + 1 >= rest.length) throw usage('missing value for --limit');
        limit = Number(rest[++i]);
        if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw usage('--limit must be an integer 1..1000');
      } else if (a.startsWith('--')) throw usage(`unknown option: ${a}`);
      else if (org === null) org = a;
      else throw usage(`unexpected argument: ${a}`);
    }
    if (!org) throw usage('usage: lmconn github repos <org> [--limit N]');
    return { command, org, limit };
  }
  throw usage(USAGE);
}

// deps: { fetch, exec } are injectable for tests (no network, no gh).
export async function run(args, deps = {}) {
  const fetchImpl = deps.fetch || globalThis.fetch;
  try {
    const call = parseArgs(args);
    const auth = resolveToken(deps.exec);
    if (call.command === 'user') emit(ok(await user(auth, fetchImpl)));
    else emit(ok(await repos(call.org, call.limit, auth, fetchImpl)));
    return 0;
  } catch (err) {
    const known = ['USAGE', 'MISSING_KEY', 'NETWORK', 'GITHUB_HTTP', 'INVALID_RESPONSE'];
    return emitFail(known.includes(err.code) ? err.code : 'GITHUB_ERROR', known.includes(err.code) ? err.message : `github command failed: ${err.message}`);
  }
}
