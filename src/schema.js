// cli.schema.v1 generator and the bridge from schema-module calls to argv.
//
// Each command area publishes `ops`, a list of operation fragments. This module
// collects them (a missing or broken area is skipped), normalises names to the
// lmts rules (operation ^[a-z][a-z0-9_]*$, param ^[A-Za-z_]\w*$) and returns the
// document that `lmconn --cli-schema --json` prints and lmscript imports.
//
// lmscript calls an imported operation as
//   lmconn <op> --input-json '{"op":"<op>","params":{...}}' [--readonly] [--confirm]
// argvFromSchemaCall() turns that back into the ordinary CLI form
//   lmconn <area> <sub> <positional...> --flag value ...
// Convention: op name = <area>_<sub>, where <sub> is the CLI subcommand; a param
// published as camelCase maps to the kebab-case flag (dataFile -> --data-file).

import { readFileSync } from 'node:fs';
// JSON import attribute so the version survives bun --compile (no ../package.json in a binary).
import pkg from '../package.json' with { type: 'json' };

export const AREAS = ['cred', 'llm', 'http', 'github'];

// Allowed param keys per @lmctl-ai/lmts/publish (anything else is a validation error).
const PARAM_KEYS = ['name', 'type', 'occurs', 'default', 'enum', 'positional', 'items', 'description', 'aliases', 'cliOnly', 'docOnly', 'derived'];

export const GLOBALS = [
  { name: 'readonly', type: 'boolean', occurs: '?', aliases: ['read-only'], description: 'Refuse to run write operations' },
  { name: 'json', type: 'boolean', occurs: '?', description: 'Output as JSON (the envelope is always JSON)' },
  { name: 'help', type: 'boolean', occurs: '?', aliases: ['h'], description: 'Show help' },
  { name: 'input-json', type: 'string', occurs: '?', aliases: ['inputJson'], description: 'JSON document input' },
  { name: 'input-file', type: 'string', occurs: '?', aliases: ['inputFile'], description: 'Path to file containing JSON document input' },
];

export function packageVersion() {
  return pkg.version || '0.0.0';
}

export const camelCase = (s) => s.replace(/[-_\s]+([a-zA-Z0-9])/g, (_, c) => c.toUpperCase());
export const kebabCase = (s) => s.replace(/([a-z0-9])([A-Z])/g, '$1-$2').replace(/[_\s]+/g, '-').toLowerCase();

// Operation name: 'cred.set' | 'llm chat' | 'http_request' -> 'cred_set' | 'llm_chat' | 'http_request'.
export function opName(area, raw) {
  let name = String(raw).toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  if (!name.startsWith(area + '_') && name !== area) name = `${area}_${name}`;
  return name;
}

// Returns { op, cli } where op is the publishable fragment and cli the private bridge data.
export function normalizeOp(area, fragment) {
  const name = opName(area, fragment.name);
  const sub = name === area ? '' : name.slice(area.length + 1).replace(/_/g, '-');
  const params = [];
  const cli = { name, area, sub, params: [] };
  for (const p of fragment.params || []) {
    const published = {};
    for (const key of PARAM_KEYS) if (p[key] !== undefined) published[key] = p[key];
    published.name = camelCase(String(p.name));
    if (!/^[A-Za-z_]\w*$/.test(published.name)) continue;
    params.push(published);
    cli.params.push({ name: published.name, flag: '--' + kebabCase(String(p.name)), positional: p.positional === true,
      multi: published.occurs === '+' || published.occurs === '*' || published.type === 'array', type: published.type });
  }
  const op = { name, access: fragment.access === 'write' || fragment.access === 'dynamic' ? fragment.access : 'read',
    description: fragment.description || `${area} ${sub}`.trim(), params };
  return { op, cli };
}

// Static loaders so `bun build --compile` bundles the area modules — a
// template-literal dynamic import is invisible to the bundler and the binary
// would ship zero areas.
export const AREA_LOADERS = {
  cred: () => import('./cmd-cred.js'),
  llm: () => import('./cmd-llm.js'),
  http: () => import('./cmd-http.js'),
  github: () => import('./cmd-github.js'),
};

// Loads every area's ops. A missing module (not implemented yet) is skipped
// silently; any other import error is reported on stderr and skipped too.
// A custom `resolve` (used by tests) takes precedence over the static loaders.
export async function collectOps({ areas = AREAS, resolve, warn = (m) => process.stderr.write(m + '\n') } = {}) {
  const operations = [];
  const bridge = new Map();
  for (const area of areas) {
    let fragments;
    try {
      let mod;
      if (resolve) mod = await import(resolve(area));
      else {
        const load = AREA_LOADERS[area];
        if (!load) throw Object.assign(new Error(`unknown area: ${area}`), { code: 'ERR_MODULE_NOT_FOUND' });
        mod = await load();
      }
      fragments = mod.ops || [];
    } catch (err) {
      if (err?.code !== 'ERR_MODULE_NOT_FOUND') warn(`schema: skipping ${area}: ${err?.message || err}`);
      continue;
    }
    for (const fragment of fragments) {
      const { op, cli } = normalizeOp(area, fragment);
      if (bridge.has(op.name)) { warn(`schema: duplicate operation ${op.name} ignored`); continue; }
      bridge.set(op.name, cli);
      operations.push(op);
    }
  }
  return { operations, bridge };
}

export async function schemaDocument(options = {}) {
  const { operations } = await collectOps(options);
  return {
    schema: 'cli.schema.v1',
    tool: 'lmconn',
    version: packageVersion(),
    policy: { dryrun: false, readonly: false },
    inputs: ['flags', 'json'],
    operations,
    globals: GLOBALS,
  };
}

const usage = (message) => Object.assign(new Error(message), { code: 'USAGE' });

// argv = ['<op>', '--input-json', DOC | '--input-file', PATH, ...flags] -> ['<area>', '<sub>', ...]
export async function argvFromSchemaCall(argv, options = {}) {
  const [name, ...rest] = argv;
  let document; const flags = [];
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--input-json' || a === '--input-file') {
      if (i + 1 >= rest.length) throw usage(`missing value for ${a}`);
      const value = rest[++i];
      try {
        document = JSON.parse(a === '--input-file' ? readFileSync(value, 'utf8') : value);
      } catch (err) { throw usage(`invalid ${a}: ${err.message}`); }
    } else if (a === '--readonly' || a === '--confirm' || a === '--json') flags.push(a);
    else throw usage(`unexpected argument in schema call: ${a}`);
  }
  if (!document || typeof document !== 'object' || Array.isArray(document)) throw usage('input document must be a JSON object');
  const params = typeof document.op === 'string' && document.params !== undefined ? document.params : document;
  const op = typeof document.op === 'string' ? document.op : name;
  if (op !== name) throw usage(`operation mismatch: argv says ${name}, document says ${op}`);
  if (params === null || typeof params !== 'object' || Array.isArray(params)) throw usage('params must be a JSON object');
  const { bridge } = await collectOps(options);
  const cli = bridge.get(name);
  if (!cli) throw usage(`unknown operation: ${name}`);
  if (flags.includes('--readonly')) {
    const { operations } = await collectOps(options);
    const published = operations.find((o) => o.name === name);
    if (published.access !== 'read') throw Object.assign(new Error(`--readonly refuses ${name} (access ${published.access})`), { code: 'READONLY' });
  }
  const out = [cli.area];
  if (cli.sub) out.push(cli.sub);
  const known = new Set(cli.params.map((p) => p.name));
  for (const key of Object.keys(params)) if (!known.has(key)) throw usage(`unknown param for ${name}: ${key}`);
  for (const p of cli.params.filter((p) => p.positional)) {
    if (params[p.name] === undefined) throw usage(`missing positional param for ${name}: ${p.name}`);
    out.push(String(params[p.name]));
  }
  for (const p of cli.params.filter((p) => !p.positional)) {
    const v = params[p.name];
    if (v === undefined || v === null || v === false) continue;
    if (v === true) { out.push(p.flag); continue; }
    const values = Array.isArray(v) ? v : [v];
    for (const item of values) out.push(p.flag, typeof item === 'string' ? item : JSON.stringify(item));
  }
  return out;
}
