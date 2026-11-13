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

const USAGE = 'usage: lmconn npm trust-list PACKAGE --credential HANDLE | lmconn npm trust-github PACKAGE --credential HANDLE --repo OWNER/REPO --file WORKFLOW.yml [--env E] [--auth-url-file ABS] | lmconn npm pack DIR --out FILE | lmconn npm publish FILE --credential HANDLE --expect-integrity sha512-... ' +
  '[--tag T] [--access public|restricted] | lmconn npm whoami --credential HANDLE';
const usage = (message) => Object.assign(new Error(message), { code: 'USAGE' });
const refuse = (message) => Object.assign(new Error(message), { code: 'NPM_REFUSED' });

export const LIMITS = { compressed: 50 * 1024 * 1024, expanded: 200 * 1024 * 1024, entries: 10000, ratio: 200, manifest: 1024 * 1024, output: 65536 };
const REGISTRY = 'https://registry.npmjs.org';
// Test overrides are honoured only with LMCONN_NPM_TEST=1 and only for a literal loopback registry; otherwise the
// registry is the constant and npm is the one installed beside the node running lmconn (never found through the caller's PATH).
const testMode = () => process.env.LMCONN_NPM_TEST === '1';
const registry = () => {
  const t = process.env.LMCONN_NPM_TEST_REGISTRY;
  if (testMode() && t && /^http:\/\/127\.0\.0\.1:\d+$/.test(t)) return t;
  return REGISTRY;
};
const nodeDir = () => path.dirname(process.execPath);
function npmBin() {
  if (testMode() && process.env.LMCONN_NPM_BIN) return process.env.LMCONN_NPM_BIN;
  const pinned = path.join(os.homedir(), '.lmconn', 'npm', 'bin', 'npm');
  if (fs.existsSync(pinned)) { const st = fs.statSync(pinned); if (st.uid === process.getuid() && !(st.mode & 0o022)) return pinned; }
  return path.join(nodeDir(), 'npm');
}

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
    const len = Number(data.subarray(at, sp).toString()); if (!Number.isSafeInteger(len) || len <= sp - at + 1 || at + len > data.length || data[at + len - 1] !== 0x0a) throw refuse('malformed pax header');
    const rec = data.subarray(sp + 1, at + len - 1).toString('utf8'); const eq = rec.indexOf('='); if (eq < 1) throw refuse('malformed pax header');
    const key = rec.slice(0, eq), val = rec.slice(eq + 1);
    if (key === 'path') { if (!val) throw refuse('empty pax path'); path = val; }
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
  const seen = new Set(); const dirs = new Set(); const filesSeen = new Set(); let ended = false; const files = new Map(); let at = 0; let longName = null; let paxName = null; let total = 0; let count = 0;
  while (at + 512 <= raw.length) {
    const h = raw.subarray(at, at + 512);
    if (h.every(b => b === 0)) {
      // node-tar ends only at two zero blocks; nothing but zeros may follow, or a hidden entry could be read by npm.
      if (at + 1024 > raw.length || !raw.subarray(at).every(b => b === 0)) throw refuse('malformed tar end marker');
      ended = true; break;
    }
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
    const ustar = h.subarray(257, 265).equals(Buffer.from('ustar\x0000', 'latin1'));
    const prefix = field(h, 345, 155);
    if (prefix && !ustar) throw refuse('tar prefix field without ustar magic');
    let name = paxName || longName || (prefix ? `${prefix}/${field(h, 0, 100)}` : field(h, 0, 100));
    paxName = null; longName = null;
    if (type === '5') { const dir = normalizeEntry(name.replace(/\/+$/, '')); if (seen.has(dir)) throw refuse('duplicate tar path'); seen.add(dir); dirs.add(dir); continue; }
    if (name.endsWith('/')) throw refuse('a file entry name ends with a slash');
    const norm = normalizeEntry(name);
    if (norm === 'package' || seen.has(norm)) throw refuse('duplicate tar path');
    seen.add(norm); filesSeen.add(norm); total += size;
    if (total > LIMITS.expanded) throw refuse('tarball expands beyond the limit');
    if (norm === 'package/package.json') { if (size > LIMITS.manifest) throw refuse('manifest too large'); files.set(norm, Buffer.from(body)); }
  }
  if (paxName !== null || longName !== null) throw refuse('dangling tar extension header');
  if (!ended) throw refuse('tar has no end marker');
  for (const f of filesSeen) {
    if (dirs.has(f)) throw refuse('a path is both a file and a directory');
    for (let i = f.lastIndexOf('/'); i > 0; i = f.lastIndexOf('/', i - 1)) if (filesSeen.has(f.slice(0, i))) throw refuse('a path is both a file and a directory');
  }
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
  if (PRERELEASE.test(version) && (!tag || tag === 'latest')) throw refuse('a prerelease version needs an explicit --tag other than latest');
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

const active = { dirs: new Set(), pids: new Set() };
function scratch() {
  const dir = path.join(runRoot(), randomBytes(12).toString('hex'));
  fs.mkdirSync(dir, { mode: 0o700 });
  fs.writeFileSync(path.join(dir, 'package.json'), '{"private":true}\n', { mode: 0o600 });  // stops npm's walk up to an ancestor project
  active.dirs.add(dir);
  return dir;
}

function writeConfig(dir, withToken, opener) {
  const reg = registry(); const host = reg.replace(/^https?:/, '');
  const lines = [`registry=${reg}/`, `@lmctl-ai:registry=${reg}/`, 'strict-ssl=true',
    `cache=${dir}/cache`, `logs-dir=${dir}/logs`, 'update-notifier=false', 'audit=false', 'fund=false', 'ignore-scripts=true', 'fetch-retries=0'];
  if (withToken) lines.push(`${host}/:_authToken=\${LMCONN_NPM_TOKEN}`);
  if (opener) {  // npm 'opens the browser' with this script, which only hands the approval link to the human through a file
    const bin = path.join(dir, 'bin'); fs.mkdirSync(bin, { mode: 0o700 });
    const script = path.join(bin, 'xdg-open');  // npm opens links with xdg-open on Linux; this one only passes the link on
    fs.writeFileSync(script, '#!/bin/sh\ncase "$1" in https://www.npmjs.com/auth/cli/[0-9A-Za-z-]*) if [ -n "$LMCONN_AUTH_URL_FILE" ]; then (set -C; printf \'%s\\n\' "$1" > "$LMCONN_AUTH_URL_FILE") 2>/dev/null; fi;; esac\nexit 0\n', { mode: 0o700 });
  }
  const user = path.join(dir, 'userconfig'), glob = path.join(dir, 'globalconfig');
  fs.writeFileSync(user, lines.join('\n') + '\n', { mode: 0o600 });
  fs.writeFileSync(glob, '', { mode: 0o600 });
  return { user, glob };
}

export function runNpm(args, { cwd, token, timeoutMs = 120000, dir, prefix = dir, onData, envConfig = false, tty = false, authUrlFile }) {
  const { user, glob } = writeConfig(dir, !!token, tty);
  const env = { PATH: `${tty ? dir + '/bin:' : ''}${nodeDir()}:/usr/bin:/bin`, HOME: dir, NO_COLOR: '1' };
  if (token) env.LMCONN_NPM_TOKEN = token;
  // `npm trust` does not accept these as flags (their values are read as positionals), so for it our own config files go in by env.
  if (tty && authUrlFile) env.LMCONN_AUTH_URL_FILE = authUrlFile;
  if (envConfig) Object.assign(env, { NPM_CONFIG_USERCONFIG: user, NPM_CONFIG_GLOBALCONFIG: glob, NPM_CONFIG_PREFIX: prefix });
  const bin = npmBin();
  const full = [...args, ...(envConfig ? [] : ['--userconfig', user, '--globalconfig', glob]), '--registry', `${registry()}/`, '--ignore-scripts', '--no-update-notifier', '--no-audit', '--no-fund', '--workspaces=false', ...(envConfig ? [] : ['--prefix', prefix])];
  return new Promise((resolve) => {
    // npm waits for a web-auth approval only on a terminal; python's pty module gives it one (argv passed as-is, no shell).
    const child = tty ? spawn('/usr/bin/python3', ['-I', '-c', 'import os,pty,sys;st=pty.spawn(sys.argv[1:]);c=os.waitstatus_to_exitcode(st);sys.exit(c if c>=0 else 128-c)', bin, ...full], { cwd, env, shell: false, detached: true, stdio: ['pipe', 'pipe', 'pipe'] })
      : spawn(bin, full, { cwd, env, shell: false, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '', timedOut = false, over = false;
    const cap = (s, d) => (s.length + d.length > LIMITS.output ? (over = true, kill(), s) : s + d);
    let entered = false;  // the terminal prompt 'Press ENTER to open in the browser' is answered once so npm prints the approval link and waits
    const answer = (t) => { if (tty && !entered && /Press ENTER/i.test(t)) { entered = true; try { child.stdin.write('\n'); } catch { /* gone */ } } };
    child.stdout.on('data', d => { out = cap(out, d.toString()); onData?.(d.toString()); answer(d.toString()); });
    child.stderr.on('data', d => { err = cap(err, d.toString()); onData?.(d.toString()); });
    const kill = () => { try { process.kill(-child.pid, 'SIGKILL'); } catch { /* gone */ } };
    active.pids.add(child.pid);
    const timer = setTimeout(() => { timedOut = true; kill(); }, timeoutMs);
    child.on('error', () => { clearTimeout(timer); resolve({ code: 127, out, err, timedOut, over }); });
    child.on('close', (code) => { clearTimeout(timer); kill(); active.pids.delete(child.pid); resolve({ code, out, err, timedOut, over }); });
  });
}

const sha512 = (buf) => 'sha512-' + createHash('sha512').update(buf).digest('base64');
const cleanup = (dir) => { active.dirs.delete(dir); try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } };

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
    const r = await runNpm(['pack', '--pack-destination', dest, '--json'], { cwd: work, dir, prefix: work });
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

export async function publish({ file, credential, expectIntegrity, tag, access, authUrlFile }) {
  const onData = authHook(authUrlFile);  // validated before anything else
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
    const r = await runNpm(args, { cwd: dir, token, dir, tty: true, onData, authUrlFile, timeoutMs: Number(process.env.LMCONN_NPM_TIMEOUT_MS) || 600000 });
    r.err = (r.err + '\n' + r.out).replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '').replace(/\r/g, '');
    const receipt = { package: name, version, integrity: local };
    const spec = `${name}@${version}`;
    const check = async () => { try { return await remoteIntegrity(spec, { token, dir }); } catch { return null; } };
    const text = r.err + r.out;
    let seen = await check();
    if (seen === local) return { outcome: 'published_confirmed', ...receipt, registryIntegrity: seen, submitted: r.code === 0 };
    if (seen && seen !== 'absent') return { outcome: 'conflict', ...receipt, registryIntegrity: seen };
    // Failures known to precede submission or a definitive rejection.
    const code = /^npm error code (ENEEDAUTH|E401|E403|EOTP|EUSAGE|EINVALIDTAGNAME|EBADENGINE)\s*$/m.exec(r.err)?.[1];
    if (r.code !== 0 && !r.timedOut && !r.over && code && seen === 'absent') return { outcome: 'not_published', ...receipt, reason: code };
    // The PUT may have been sent: reconcile for a window, then stay pending.
    const until = Date.now() + (Number(process.env.LMCONN_NPM_RECONCILE_MS) || 60000);
    while (Date.now() < until) {
      await new Promise(res => setTimeout(res, Math.min(5000, Math.max(50, until - Date.now()))));
      seen = await check();
      if (seen === local) return { outcome: 'published_confirmed', ...receipt, registryIntegrity: seen };
      if (seen && seen !== 'absent') return { outcome: 'conflict', ...receipt, registryIntegrity: seen };
    }
    return { outcome: 'pending_verification', ...receipt, detail: errSummary(r, token) };
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

const PKG_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;
const TRUST_OWNERS = ['lmctl-ai'];  // trusted publishers may only be granted to these GitHub owners
const AUTH_URL = /https:\/\/www\.npmjs\.com\/auth\/cli\/[0-9A-Za-z-]+/;

// npm's own error lines only (never the token); short, redacted
const errSummary = (r, token) => r.timedOut ? 'timeout' : safeText((r.err + '\n' + r.out).replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '').replace(/[\u2800-\u28ff]/g, '').replace(/\r/g, '').split('\n').map(l => l.trim()).filter(l => /^npm error/.test(l)).map(l => l.slice(10).trim()).filter(Boolean).slice(0, 4).join(' | ') || 'error', [token]);

// A web-auth URL printed by npm is a one-time approval link for the human (not a secret); hand it over through a file the caller named.
function authHook(authUrlFile) {
  if (authUrlFile === undefined) return undefined;
  if (!path.isAbsolute(authUrlFile) || authUrlFile.includes('\0')) throw usage('--auth-url-file must be an absolute path');
  let announced = false; let seen = '';
  return (text) => {
    if (announced) return;
    seen = (seen + text.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '').replace(/\r/g, '')).slice(-4096);  // the link can arrive split across chunks
    const m = AUTH_URL.exec(seen);
    if (!m) return;
    announced = true;
    try {  // never follow a symlink, never block on a FIFO, only a regular file is ever written
      const fd = fs.openSync(authUrlFile, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK, 0o600);
      try { if (!fs.fstatSync(fd).isFile()) return; fs.writeSync(fd, m[0] + '\n'); } finally { fs.closeSync(fd); }
    } catch { /* the caller sees a timeout instead of a crash */ }
  };
}

export async function trustList(pkg, credential, authUrlFile) {
  if (!PKG_NAME.test(pkg) || pkg.length > 214) throw usage('package name is invalid');
  const onData = authHook(authUrlFile);  // validated before the credential is touched
  const dir = scratch();
  try {
    const token = tokenFor(credential);
    const r = await runNpm(['trust', 'list', pkg, '--json'], { cwd: dir, token, dir, timeoutMs: Number(process.env.LMCONN_NPM_TIMEOUT_MS) || 600000, envConfig: true, tty: true, authUrlFile, onData });
    if (r.code !== 0) throw Object.assign(new Error(`npm trust list failed: ${errSummary(r, token)}`), { code: 'NPM_FAILED' });
    // On a terminal the output has colour codes, spinners and warnings around the JSON; keep the JSON (or the last clean lines).
    const text = r.out.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '').replace(/[\u2800-\u28ff]/g, '').replace(/\r/g, '');
    const lines = text.split('\n').filter(l => l.trim() && !/^npm (warn|notice)/.test(l));
    const at = lines.findIndex(l => /^[[{]/.test(l));
    let parsed = null; try { parsed = JSON.parse((at < 0 ? lines : lines.slice(at)).join('\n')); } catch { /* keep text */ }
    return { package: pkg, trust: parsed ?? safeText(lines.slice(-6).join(' | '), [token]) };
  } finally { cleanup(dir); }
}

export async function trustGithub({ pkg, credential, repo, file, env, authUrlFile }) {
  if (!PKG_NAME.test(pkg) || pkg.length > 214) throw usage('package name is invalid');
  if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(repo)) throw usage('--repo must look like owner/repo');
  if (!TRUST_OWNERS.includes(repo.split('/')[0]) && !(testMode() && repo.startsWith('lmctl-test/'))) throw usage('--repo owner is not allowed for trusted publishing');
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.ya?ml$/.test(file)) throw usage('--file must be a workflow file name ending in .yml or .yaml');
  if (env !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(env)) throw usage('--env is invalid');
  const dir = scratch();
  try {
    const onData = authHook(authUrlFile);  // validated before the credential is touched
    const token = tokenFor(credential);
    const args = ['trust', 'github', pkg, '--repo', repo, '--file', file, '--allow-publish', '--yes'];
    if (env) args.push('--env', env);
    const r = await runNpm(args, { cwd: dir, token, dir, timeoutMs: Number(process.env.LMCONN_NPM_TIMEOUT_MS) || 600000, onData, envConfig: true, tty: true, authUrlFile });
    if (r.code !== 0) return { outcome: 'failed', package: pkg, reason: errSummary(r, token) };
    return { outcome: 'configured', package: pkg, repo, file, ...(env ? { env } : {}) };
  } finally { cleanup(dir); }
}

export function parseArgs(args) {
  const [command, ...rest] = args;
  if (!['pack', 'publish', 'whoami', 'trust-list', 'trust-github'].includes(command)) throw usage(USAGE);
  const req = { command, positional: null, flags: {} };
  const known = { pack: ['out'], publish: ['credential', 'expect-integrity', 'tag', 'access', 'auth-url-file'], whoami: ['credential'], 'trust-list': ['credential', 'auth-url-file'], 'trust-github': ['credential', 'repo', 'file', 'env', 'auth-url-file'] }[command];
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a.startsWith('--')) {
      const name = a.slice(2);
      if (!known.includes(name)) throw usage(`unknown option: ${a}`);
      if (i + 1 >= rest.length) throw usage(`missing value for ${a}`);
      if (name in req.flags) throw usage(`${a} given twice`);
      req.flags[name] = rest[++i];
    } else if (req.positional === null && command !== 'whoami') req.positional = a;  // pack DIR, publish FILE, trust-* PACKAGE
    else throw usage(`unexpected argument: ${a}`);
  }
  if (!['whoami'].includes(command) && !req.positional) throw usage(USAGE);
  if (command === 'pack' && !req.flags.out) throw usage('--out is required');
  if (command === 'publish' && (!req.flags.credential || !req.flags['expect-integrity'])) throw usage('--credential and --expect-integrity are required');
  if (['whoami', 'trust-list', 'trust-github'].includes(command) && !req.flags.credential) throw usage('--credential is required');
  if (command === 'trust-github' && (!req.flags.repo || !req.flags.file)) throw usage('--repo and --file are required');
  return req;
}

function installSignals() {
  for (const sig of ['SIGINT', 'SIGTERM']) process.once(sig, () => {
    for (const pid of active.pids) { try { process.kill(-pid, 'SIGKILL'); } catch { /* gone */ } }
    for (const d of active.dirs) cleanup(d);
    process.exit(130);
  });
}

export async function run(args) {
  installSignals();
  try {
    const req = parseArgs(args);
    let result;
    if (req.command === 'pack') result = await pack(req.positional, path.resolve(req.flags.out));
    else if (req.command === 'publish') result = await publish({ file: req.positional, credential: req.flags.credential, expectIntegrity: req.flags['expect-integrity'], tag: req.flags.tag, access: req.flags.access, authUrlFile: req.flags['auth-url-file'] });
    else if (req.command === 'trust-list') result = await trustList(req.positional, req.flags.credential, req.flags['auth-url-file']);
    else if (req.command === 'trust-github') result = await trustGithub({ pkg: req.positional, credential: req.flags.credential, repo: req.flags.repo, file: req.flags.file, env: req.flags.env, authUrlFile: req.flags['auth-url-file'] });
    else result = await whoami(req.flags.credential);
    emit(ok(result));
    return 0;
  } catch (err) {
    if (['USAGE', 'MISSING_KEY', 'CREDENTIAL_POLICY', 'STORE_SECURITY', 'NPM_REFUSED', 'NPM_FAILED'].includes(err.code)) return emitFail(err.code, err.message);
    if (err.code === 'ENOENT') return emitFail('USAGE', 'file or directory not found');
    return emitFail('NPM_ERROR', 'npm operation failed');
  }
}
