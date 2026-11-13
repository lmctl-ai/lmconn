// npm connector that publishes with a protected credential (SPEC-publish-bridge.md section 8):
//   lmconn npm pack DIR --out FILE
//   lmconn npm publish FILE --credential HANDLE --expect-integrity sha512-... [--tag T] [--access public|restricted]
//   lmconn npm whoami --credential HANDLE
// The token reaches npm only as the environment variable LMCONN_NPM_TOKEN, referenced from a userconfig of
// ours; child output is never forwarded. Outcomes: published_confirmed | conflict | not_published | pending_verification.

import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { emit, ok, emitFail } from './result.js';
import { getCred } from './creds.js';
import { authorizeOrigin } from './credential-policy.js';
import { redact } from './oauth-security.js';

const USAGE = 'usage: lmconn npm pack DIR --out FILE | lmconn npm publish FILE --credential HANDLE --expect-integrity sha512-... ' +
  '[--tag T] [--access public|restricted] | lmconn npm whoami --credential HANDLE';
const usage = (message) => Object.assign(new Error(message), { code: 'USAGE' });
const refuse = (message) => Object.assign(new Error(message), { code: 'NPM_REFUSED' });

export const LIMITS = { compressed: 50 * 1024 * 1024, expanded: 200 * 1024 * 1024, entries: 10000, ratio: 200, manifest: 1024 * 1024, output: 65536 };
const REGISTRY = 'https://registry.npmjs.org';
const registry = () => (process.env.LMCONN_NPM_TEST_REGISTRY || REGISTRY).replace(/\/+$/, '');

export const ops = [
  { name: 'npm_pack', access: 'write', description: 'Pack a package directory with npm (scripts off, no credential) and print its sha512', params: [
    { name: 'dir', type: 'string', positional: true, description: 'Package directory' },
    { name: 'out', type: 'string', occurs: '1', description: 'Output tarball path' },
  ] },
  { name: 'npm_publish', access: 'write', description: 'Publish a tarball with a protected credential; prints a receipt only', params: [
    { name: 'file', type: 'string', positional: true, description: 'Tarball produced by npm pack' },
    { name: 'credential', type: 'string', occurs: '1', description: 'Protected credential handle bound to https://registry.npmjs.org' },
    { name: 'expectIntegrity', type: 'string', occurs: '1', description: 'Expected sha512-<base64> of the tarball' },
    { name: 'tag', type: 'string', occurs: '?', description: 'dist-tag (required for a prerelease version)' },
    { name: 'access', type: 'string', occurs: '?', description: 'public or restricted' },
  ] },
  { name: 'npm_whoami', access: 'read', description: 'Return the npm user name for a protected credential', params: [
    { name: 'credential', type: 'string', occurs: '1', description: 'Protected credential handle' },
  ] },
];

// ---- strict JSON (duplicate member names are an error) ----
export function parseStrictJson(text) {
  let i = 0;
  const ws = () => { while (' \t\n\r'.includes(text[i]) && i < text.length) i++; };
  const value = () => {
    ws();
    const c = text[i];
    if (c === '{') {
      i++; const obj = {}; const seen = new Set(); ws();
      if (text[i] === '}') { i++; return obj; }
      for (;;) {
        ws(); if (text[i] !== '"') throw Error('bad json');
        const key = str(); if (seen.has(key)) throw refuse(`manifest has a duplicate member: ${key}`);
        seen.add(key); ws(); if (text[i++] !== ':') throw Error('bad json');
        Object.defineProperty(obj, key, { value: value(), enumerable: true, writable: true, configurable: true }); ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i++] === '}') return obj;
        throw Error('bad json');
      }
    }
    if (c === '[') {
      i++; const arr = []; ws();
      if (text[i] === ']') { i++; return arr; }
      for (;;) { arr.push(value()); ws(); if (text[i] === ',') { i++; continue; } if (text[i++] === ']') return arr; throw Error('bad json'); }
    }
    if (c === '"') return str();
    const m = /^(?:true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i, i + 64));
    if (!m) throw Error('bad json');
    i += m[0].length; return JSON.parse(m[0]);
  };
  const str = () => {
    const start = i++;
    while (i < text.length && text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
    if (i >= text.length) throw Error('bad json');
    i++; return JSON.parse(text.slice(start, i));
  };
  const v = value(); ws();
  if (i !== text.length) throw Error('bad json');
  return v;
}

// ---- strict tar reader: every entry under package/, files and directories only ----
const field = (b, o, n) => { const s = b.subarray(o, o + n); const z = s.indexOf(0); return s.subarray(0, z < 0 ? n : z).toString('utf8'); };
const octal = (b, o, n) => { const t = field(b, o, n).trim(); if (!/^[0-7]*$/.test(t)) throw refuse('malformed tar size'); return t ? parseInt(t, 8) : 0; };

export function normalizeEntry(name) {
  if (typeof name !== 'string' || !name || name.includes('\0') || name.includes('\\') || name.startsWith('/')) throw refuse('unsafe tar path');
  const parts = name.split('/').filter(p => p !== '');
  if (parts.some(p => p === '..' || p === '.')) throw refuse('unsafe tar path');
  if (parts[0] !== 'package') throw refuse(`tar entry outside package/: ${name}`);
  return parts.join('/');
}

function paxPath(data) {
  let path = null; let at = 0;
  while (at < data.length) {
    const sp = data.indexOf(0x20, at); if (sp < 0) throw refuse('malformed pax header');
    const len = Number(data.subarray(at, sp).toString()); if (!Number.isSafeInteger(len) || len < 1 || at + len > data.length) throw refuse('malformed pax header');
    const rec = data.subarray(sp + 1, at + len - 1).toString('utf8'); const eq = rec.indexOf('=');
    const key = rec.slice(0, eq), val = rec.slice(eq + 1);
    if (key === 'path') path = val;
    else if (['linkpath', 'size', 'uid', 'gid', 'mtime', 'atime', 'ctime', 'uname', 'gname', 'comment'].includes(key) || key.startsWith('SCHILY.') || key.startsWith('LIBARCHIVE.')) { if (key === 'size' || key === 'linkpath') throw refuse('unsupported pax header'); }
    else throw refuse('unsupported pax header');
    at += len;
  }
  return path;
}

export function readPackage(gz) {
  if (gz.length > LIMITS.compressed) throw refuse('tarball too large');
  let raw;
  try { raw = zlib.gunzipSync(gz, { maxOutputLength: LIMITS.expanded }); } catch { throw refuse('not a gzip tarball or it expands beyond the limit'); }
  if (raw.length / Math.max(gz.length, 1) > LIMITS.ratio && raw.length > 1024 * 1024) throw refuse('tarball compression ratio too high');
  const seen = new Set(); const files = new Map(); let at = 0; let longName = null; let paxName = null; let total = 0; let count = 0;
  while (at + 512 <= raw.length) {
    const h = raw.subarray(at, at + 512);
    if (h.every(b => b === 0)) break;
    let sum = 0; for (let k = 0; k < 512; k++) sum += (k >= 148 && k < 156) ? 32 : h[k];
    if (octal(h, 148, 8) !== sum) throw refuse('bad tar checksum');
    const size = octal(h, 124, 12), type = String.fromCharCode(h[156] || 48);
    const body = raw.subarray(at + 512, at + 512 + size);
    if (body.length !== size) throw refuse('truncated tar');
    at += 512 + Math.ceil(size / 512) * 512;
    if (type === 'x') { if (paxName !== null) throw refuse('stacked pax headers'); paxName = paxPath(body) ?? false; continue; }
    if (type === 'L') { if (longName !== null) throw refuse('stacked long names'); longName = field(body, 0, body.length); continue; }
    if (!['0', '5'].includes(type)) throw refuse('tar entry is not a plain file or directory');
    if (++count > LIMITS.entries) throw refuse('too many tar entries');
    const prefix = field(h, 345, 155);
    let name = paxName || longName || (prefix ? `${prefix}/${field(h, 0, 100)}` : field(h, 0, 100));
    paxName = null; longName = null;
    if (type === '5') { const dir = normalizeEntry(name.replace(/\/+$/, '')); if (seen.has(dir)) throw refuse('duplicate tar path'); seen.add(dir); continue; }
    const norm = normalizeEntry(name);
    if (norm === 'package' || seen.has(norm)) throw refuse('duplicate tar path');
    seen.add(norm); total += size;
    if (total > LIMITS.expanded) throw refuse('tarball expands beyond the limit');
    if (norm === 'package/package.json') { if (size > LIMITS.manifest) throw refuse('manifest too large'); files.set(norm, Buffer.from(body)); }
  }
  if (paxName !== null || longName !== null) throw refuse('dangling tar extension header');
  const manifestBytes = files.get('package/package.json');
  if (!manifestBytes) throw refuse('package/package.json missing');
  let manifest;
  try { manifest = parseStrictJson(manifestBytes.toString('utf8')); } catch (err) { throw err.code ? err : refuse('manifest is not valid JSON'); }
  return { manifest, entries: count };
}

const PRERELEASE = /^\d+\.\d+\.\d+-/;
export function checkManifest(manifest, tag) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) throw refuse('manifest must be an object');
  const { name, version } = manifest;
  if (typeof name !== 'string' || !/^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/.test(name) || name.length > 214) throw refuse('manifest name is invalid');
  if (typeof version !== 'string' || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version)) throw refuse('manifest version is invalid');
  if ('tag' in manifest) throw refuse('a top-level "tag" in the manifest is refused');
  const pc = manifest.publishConfig;
  if (pc !== undefined) {
    if (!pc || typeof pc !== 'object' || Array.isArray(pc)) throw refuse('publishConfig must be an object');
    for (const k of Object.keys(pc)) if (!['access', 'tag', 'provenance'].includes(k)) throw refuse(`publishConfig.${k} is refused`);
    if (pc.tag !== undefined && pc.tag !== tag) throw refuse('publishConfig.tag must equal --tag');
  }
  if (PRERELEASE.test(version) && !tag) throw refuse('a prerelease version needs an explicit --tag');
  return { name, version };
}

// ---- running npm in isolation ----
function runRoot() {
  const root = process.env.LMCONN_RUN_DIR || path.join(os.homedir(), '.lmconn', 'run');
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const st = fs.lstatSync(root);
  if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== process.getuid() || (st.mode & 0o077)) {
    if (st.isDirectory() && !st.isSymbolicLink() && st.uid === process.getuid()) fs.chmodSync(root, 0o700);
    else throw refuse('run directory is not private');
  }
  return root;
}

function scratch() {
  const dir = path.join(runRoot(), randomBytes(12).toString('hex'));
  fs.mkdirSync(dir, { mode: 0o700 });
  return dir;
}

function writeConfig(dir, withToken) {
  const reg = registry(); const host = reg.replace(/^https?:/, '');
  const lines = [`registry=${reg}/`, `@lmctl-ai:registry=${reg}/`, 'strict-ssl=true', 'proxy=', 'https-proxy=', 'noproxy=',
    `cache=${dir}/cache`, `logs-dir=${dir}/logs`, 'update-notifier=false', 'audit=false', 'fund=false', 'ignore-scripts=true', 'fetch-retries=0'];
  if (withToken) lines.push(`${host}/:_authToken=\${LMCONN_NPM_TOKEN}`);
  const user = path.join(dir, 'userconfig'), glob = path.join(dir, 'globalconfig');
  fs.writeFileSync(user, lines.join('\n') + '\n', { mode: 0o600 });
  fs.writeFileSync(glob, '', { mode: 0o600 });
  return { user, glob };
}

export function runNpm(args, { cwd, token, timeoutMs = 120000, dir }) {
  const { user, glob } = writeConfig(dir, !!token);
  const env = { PATH: process.env.PATH || '/usr/bin:/bin', HOME: dir, NO_COLOR: '1' };
  if (token) env.LMCONN_NPM_TOKEN = token;
  const bin = process.env.LMCONN_NPM_BIN || 'npm';
  const full = [...args, '--userconfig', user, '--globalconfig', glob, '--registry', `${registry()}/`, '--ignore-scripts', '--no-update-notifier', '--no-audit', '--no-fund', '--workspaces=false'];
  return new Promise((resolve) => {
    const child = spawn(bin, full, { cwd, env, shell: false, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '', timedOut = false, over = false;
    const cap = (s, d) => (s.length + d.length > LIMITS.output ? (over = true, s) : s + d);
    child.stdout.on('data', d => { out = cap(out, d.toString()); });
    child.stderr.on('data', d => { err = cap(err, d.toString()); });
    const kill = () => { try { process.kill(-child.pid, 'SIGKILL'); } catch { /* gone */ } };
    const timer = setTimeout(() => { timedOut = true; kill(); }, timeoutMs);
    child.on('error', () => { clearTimeout(timer); resolve({ code: 127, out, err, timedOut, over }); });
    child.on('close', (code) => { clearTimeout(timer); kill(); resolve({ code, out, err, timedOut, over }); });
  });
}

const sha512 = (buf) => 'sha512-' + createHash('sha512').update(buf).digest('base64');
const cleanup = (dir) => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } };

function tokenFor(handle) {
  authorizeOrigin(handle, registry());
  const token = getCred(handle, 'api_key') || getCred(handle, 'oauth_access_token');
  if (!token) throw Object.assign(new Error(`no token stored for ${handle}`), { code: 'MISSING_KEY' });
  return token;
}

const safeText = (text, secrets) => redact(String(text).slice(0, 300), secrets);

// ---- operations ----
export async function pack(dirArg, out) {
  const src = fs.realpathSync(dirArg);
  if (!fs.statSync(src).isDirectory() || !fs.existsSync(path.join(src, 'package.json'))) throw usage('DIR must contain package.json');
  const dir = scratch();
  try {
    const work = path.join(dir, 'src'); fs.mkdirSync(work, { mode: 0o700 });
    fs.cpSync(src, work, { recursive: true, filter: (p) => !['.git', 'node_modules'].includes(path.basename(p)) });
    const dest = path.join(dir, 'out'); fs.mkdirSync(dest, { mode: 0o700 });
    const r = await runNpm(['pack', '--pack-destination', dest, '--json'], { cwd: work, dir });
    if (r.code !== 0) throw Object.assign(new Error('npm pack failed'), { code: 'NPM_FAILED' });
    const names = fs.readdirSync(dest).filter(n => n.endsWith('.tgz'));
    if (names.length !== 1) throw Object.assign(new Error('npm pack produced no single tarball'), { code: 'NPM_FAILED' });
    const bytes = fs.readFileSync(path.join(dest, names[0]));
    const { manifest, entries } = readPackage(bytes);
    fs.writeFileSync(out, bytes, { mode: 0o600 });
    return { file: out, name: manifest.name, version: manifest.version, entries, integrity: sha512(bytes), bytes: bytes.length };
  } finally { cleanup(dir); }
}

async function remoteIntegrity(spec, { token, dir }) {
  const r = await runNpm(['view', spec, 'dist.integrity', '--json'], { cwd: dir, token, dir, timeoutMs: 30000 });
  if (r.code === 0) { try { const v = JSON.parse(r.out); return typeof v === 'string' ? v : null; } catch { return null; } }
  return /E404|404 Not Found/i.test(r.err + r.out) ? 'absent' : null;
}

export async function publish({ file, credential, expectIntegrity, tag, access }) {
  if (!/^sha512-[A-Za-z0-9+/]{86}==$/.test(expectIntegrity || '')) throw usage('--expect-integrity must be sha512-<base64>');
  if (tag !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(tag)) throw usage('--tag is invalid');
  if (access !== undefined && !['public', 'restricted'].includes(access)) throw usage('--access must be public or restricted');
  const dir = scratch();
  try {
    const copy = path.join(dir, 'package.tgz');
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > LIMITS.compressed) throw refuse('tarball missing or too large');
    fs.copyFileSync(file, copy, fs.constants.COPYFILE_EXCL); fs.chmodSync(copy, 0o600);
    const bytes = fs.readFileSync(copy);
    const local = sha512(bytes);
    if (local !== expectIntegrity) throw refuse('tarball does not match --expect-integrity');
    const { name, version } = checkManifest(readPackage(bytes).manifest, tag);
    const token = tokenFor(credential);  // origin is authorized before the secret is read
    const secrets = [token];
    const args = ['publish', copy];
    if (tag) args.push('--tag', tag);
    if (access) args.push('--access', access);
    const r = await runNpm(args, { cwd: dir, token, dir, timeoutMs: Number(process.env.LMCONN_NPM_TIMEOUT_MS) || 180000 });
    const receipt = { package: name, version, integrity: local };
    const spec = `${name}@${version}`;
    const check = async () => remoteIntegrity(spec, { token, dir });
    const text = r.err + r.out;
    let seen = await check();
    if (seen === local) return { outcome: 'published_confirmed', ...receipt, registryIntegrity: seen };
    if (seen && seen !== 'absent') return { outcome: 'conflict', ...receipt, registryIntegrity: seen };
    // Failures known to precede submission or a definitive rejection.
    if (r.code !== 0 && !r.timedOut && !r.over && /\b(ENEEDAUTH|E401|E403|E400|E422|EUSAGE|EINVALIDTAGNAME|EBADENGINE)\b/.test(text) && seen === 'absent') {
      return { outcome: 'not_published', ...receipt, reason: safeText(text.match(/\b(ENEEDAUTH|E401|E403|E400|E422|EUSAGE|EINVALIDTAGNAME|EBADENGINE)\b/)[1], secrets) };
    }
    // The PUT may have been sent: reconcile for a window, then stay pending.
    const until = Date.now() + (Number(process.env.LMCONN_NPM_RECONCILE_MS) || 60000);
    while (Date.now() < until) {
      await new Promise(res => setTimeout(res, Math.min(5000, Math.max(50, until - Date.now()))));
      seen = await check();
      if (seen === local) return { outcome: 'published_confirmed', ...receipt, registryIntegrity: seen };
      if (seen && seen !== 'absent') return { outcome: 'conflict', ...receipt, registryIntegrity: seen };
    }
    return { outcome: 'pending_verification', ...receipt };
  } finally { cleanup(dir); }
}

export async function whoami(credential) {
  const dir = scratch();
  try {
    const token = tokenFor(credential);
    const r = await runNpm(['whoami'], { cwd: dir, token, dir, timeoutMs: 30000 });
    if (r.code !== 0) throw Object.assign(new Error('npm rejected the credential'), { code: 'NPM_FAILED' });
    return { username: safeText(r.out.trim(), [token]) };
  } finally { cleanup(dir); }
}

export function parseArgs(args) {
  const [command, ...rest] = args;
  if (!['pack', 'publish', 'whoami'].includes(command)) throw usage(USAGE);
  const req = { command, positional: null, flags: {} };
  const known = { pack: ['out'], publish: ['credential', 'expect-integrity', 'tag', 'access'], whoami: ['credential'] }[command];
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a.startsWith('--')) {
      const name = a.slice(2);
      if (!known.includes(name)) throw usage(`unknown option: ${a}`);
      if (i + 1 >= rest.length) throw usage(`missing value for ${a}`);
      if (name in req.flags) throw usage(`${a} given twice`);
      req.flags[name] = rest[++i];
    } else if (req.positional === null && command !== 'whoami') req.positional = a;
    else throw usage(`unexpected argument: ${a}`);
  }
  if (command !== 'whoami' && !req.positional) throw usage(USAGE);
  if (command === 'pack' && !req.flags.out) throw usage('--out is required');
  if (command === 'publish' && (!req.flags.credential || !req.flags['expect-integrity'])) throw usage('--credential and --expect-integrity are required');
  if (command === 'whoami' && !req.flags.credential) throw usage('--credential is required');
  return req;
}

export async function run(args) {
  try {
    const req = parseArgs(args);
    let result;
    if (req.command === 'pack') result = await pack(req.positional, path.resolve(req.flags.out));
    else if (req.command === 'publish') result = await publish({ file: req.positional, credential: req.flags.credential, expectIntegrity: req.flags['expect-integrity'], tag: req.flags.tag, access: req.flags.access });
    else result = await whoami(req.flags.credential);
    emit(ok(result));
    return 0;
  } catch (err) {
    if (['USAGE', 'MISSING_KEY', 'CREDENTIAL_POLICY', 'STORE_SECURITY', 'NPM_REFUSED', 'NPM_FAILED'].includes(err.code)) return emitFail(err.code, err.message);
    if (err.code === 'ENOENT') return emitFail('USAGE', 'file or directory not found');
    return emitFail('NPM_ERROR', 'npm operation failed');
  }
}
