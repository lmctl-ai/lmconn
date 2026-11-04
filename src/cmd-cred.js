import { openDb, setCred, getCred, listCreds, deleteCred, dbPath } from './creds.js';
import { emit, ok, emitFail } from './result.js';
import { endpoint, origins, scopeText, redact, unsafeText, validSecret, securityError } from './oauth-security.js';
import { secureStorePath } from './store-path.js';
import { brokerMode, policy, putPolicy, refuseLegacyWrite, refuseReveal } from './credential-policy.js';

const identity = [
  { name: 'service', type: 'string', occurs: '1', positional: true, description: 'Service name' },
  { name: 'field', type: 'string', occurs: '1', positional: true, description: 'Credential field name' },
];

export const ops = [
  { name: 'cred set', access: 'write', description: 'Store a credential using exactly one of value, env, or stdin', params: [
    ...identity,
    { name: 'value', type: 'string', occurs: '?', description: 'Credential value (visible in argv; prefer env or stdin)' },
    { name: 'env', type: 'string', occurs: '?', description: 'Environment variable containing the credential' },
    { name: 'stdin', type: 'boolean', occurs: '?', description: 'Read the complete credential from stdin' },
  ] },
  { name: 'cred get', access: 'read', description: 'Check presence; reveal returns the value or NOT_FOUND', params: [
    ...identity,
    { name: 'reveal', type: 'boolean', occurs: '?', description: 'Include the secret value in the result for piping' },
  ] },
  { name: 'cred list', access: 'read', description: 'List credential names and timestamps only', params: [] },
  { name: 'cred delete', access: 'write', description: 'Delete a credential', params: [...identity] },
  { name: 'cred path', access: 'read', description: 'Return the credential database path', params: [] },
  { name: 'cred store', access: 'write', description: 'Store an issuer/origin-bound nonexportable Bearer or OAuth2 grant from JSON stdin', params: [
    { name: 'service', type: 'string', occurs: '1', positional: true, description: 'Broker-owned credential handle' },
    { name: 'stdin', type: 'boolean', occurs: '1', description: 'Read the grant and binding from stdin' },
  ] },
  { name: 'cred oauth-store', access: 'write', description: 'Atomically store an OAuth2 token from JSON stdin and return its service handle', params: [
    { name: 'service', type: 'string', occurs: '1', positional: true, description: 'Provider/account service handle' },
    { name: 'stdin', type: 'boolean', occurs: '1', description: 'Read the token and metadata JSON from stdin' },
  ] },
];

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
}

function oauthInput(text, protectedStore, service) {
  let input;
  try { input = JSON.parse(text); } catch { throw new Error('invalid input'); }
  const invalid = () => { throw new Error('invalid input'); };
  if (!input || typeof input !== 'object' || Array.isArray(input)) invalid();
  const allowed = ['kind', 'accessToken', 'refreshToken', 'scopes', 'expiresAt', 'owner', 'source', ...(protectedStore ? ['issuer', 'allowedOrigins', 'refresh'] : [])];
  if (Object.keys(input).some(key => !allowed.includes(key))) invalid();
  if (!(protectedStore ? ['oauth2', 'bearer'].includes(input.kind) : input.kind === 'oauth2') ||
      !validSecret(input.accessToken) || typeof input.owner !== 'string' || !input.owner ||
      typeof input.source !== 'string' || !input.source) invalid();
  if (input.refreshToken !== undefined && (!validSecret(input.refreshToken) || input.kind !== 'oauth2')) invalid();
  const scopes = Array.isArray(input.scopes) ? input.scopes : typeof input.scopes === 'string' ? [input.scopes] : null;
  if (!scopes || scopes.some(scope => typeof scope !== 'string' || !scope)) invalid();
  const secrets = [input.accessToken, input.refreshToken, input.refresh?.clientSecret];
  if ([service, input.owner, input.source].some(v => unsafeText(v) || redact(v, secrets) !== v)) invalid();
  try { input.scopes = scopeText(scopes.join(' '), '', secrets); } catch { invalid(); }
  let expiresAt = null;
  if (input.expiresAt !== undefined && input.expiresAt !== null) {
    if (typeof input.expiresAt !== 'string' || !Number.isFinite(Date.parse(input.expiresAt))) invalid();
    expiresAt = new Date(input.expiresAt).toISOString();
  }
  let binding = null;
  if (protectedStore) {
    const issuer = endpoint(input.issuer, 'Credential issuer');
    if (issuer.search || redact(input.issuer, secrets) !== input.issuer) invalid();
    binding = { noReveal: true, kind: input.kind, issuer: issuer.href, owner: input.owner, origins: origins(input.allowedOrigins), refresh: null };
    if (input.refresh !== undefined) {
      const cfg = input.refresh;
      if (input.kind !== 'oauth2' || !cfg || typeof cfg !== 'object' || Array.isArray(cfg) ||
          Object.keys(cfg).some(k => !['tokenUrl', 'clientId', 'clientSecret', 'authStyle'].includes(k)) ||
          typeof cfg.clientId !== 'string' || !cfg.clientId || (cfg.clientSecret !== undefined && typeof cfg.clientSecret !== 'string') ||
          !['header', 'body'].includes(cfg.authStyle || 'header')) invalid();
      binding.refresh = { tokenUrl: endpoint(cfg.tokenUrl, 'Bound refresh endpoint').href, clientId: cfg.clientId, authStyle: cfg.authStyle || 'header' };
      if (redact(JSON.stringify(binding), secrets) !== JSON.stringify(binding)) invalid();
    }
  }
  if (binding && redact(JSON.stringify(binding), secrets) !== JSON.stringify(binding)) invalid();
  return { ...input, expiresAt, binding };
}
const configFields = ['oauth_client_id', 'oauth_client_secret', 'oauth_auth_url', 'oauth_device_url', 'oauth_token_url', 'oauth_auth_query', 'oauth_auth_style', 'api_key'];
function store(service, input, protectedStore) {
  const db = openDb();
  db.exec('BEGIN IMMEDIATE');
  try {
    const old = policy(service, db);
    if (old?.noReveal) {
      if (!protectedStore || JSON.stringify(old) !== JSON.stringify(input.binding)) throw securityError('Credential issuer/client/origin binding mismatch');
    } else if (!protectedStore) refuseLegacyWrite(service, db);
    for (const field of configFields) deleteCred(service, field, db);
    setCred(service, 'oauth_kind', input.kind, db);
    if (input.kind === 'bearer') {
      for (const field of ['oauth_access_token', 'oauth_refresh_token', 'oauth_expires_at', 'oauth_token_type']) deleteCred(service, field, db);
      setCred(service, 'api_key', input.accessToken, db);
    } else {
      setCred(service, 'oauth_access_token', input.accessToken, db);
      setCred(service, 'oauth_token_type', 'Bearer', db);
      if (input.refreshToken) setCred(service, 'oauth_refresh_token', input.refreshToken, db);
      else deleteCred(service, 'oauth_refresh_token', db);
      if (input.expiresAt) setCred(service, 'oauth_expires_at', input.expiresAt, db);
      else deleteCred(service, 'oauth_expires_at', db);
    }
    if (input.expiresAt) setCred(service, 'oauth_expires_at', input.expiresAt, db);
    else deleteCred(service, 'oauth_expires_at', db);
    setCred(service, 'oauth_scope', input.scopes, db);
    setCred(service, 'oauth_owner', input.owner, db);
    setCred(service, 'oauth_source', input.source, db);
    if (input.binding?.refresh) {
      const cfg = input.binding.refresh;
      setCred(service, 'oauth_token_url', cfg.tokenUrl, db); setCred(service, 'oauth_client_id', cfg.clientId, db);
      setCred(service, 'oauth_auth_style', cfg.authStyle, db); setCred(service, 'oauth_client_secret', input.refresh.clientSecret || '', db);
    }
    putPolicy(service, input.binding || { noReveal: false, kind: 'oauth2', issuer: null, owner: input.owner, origins: [], refresh: null }, db);
    db.exec('COMMIT');
  } catch (err) { db.exec('ROLLBACK'); throw err; }
}

export async function run(args) {
  const [command, service, field, ...options] = args;
  const usage = () => emitFail('USAGE', 'Usage: cred set <service> <field> (--value V | --env VAR | --stdin), oauth-store <service> --stdin, get <service> <field> [--reveal], delete <service> <field>, list, or path');
  if (!['set', 'get', 'list', 'delete', 'path', 'oauth-store', 'store'].includes(command)) return usage();
  if (command === 'list' || command === 'path') {
    if (args.length !== 1) return usage();
  } else if ((command === 'oauth-store' || command === 'store')) {
    if (!service || service.startsWith('--') || field !== '--stdin' || options.length) return usage();
  } else {
    if (!service || !field || service.startsWith('--') || field.startsWith('--')) return usage();
    if (command === 'delete' && options.length) return usage();
    if (command === 'get' && !(options.length === 0 || (options.length === 1 && options[0] === '--reveal'))) return usage();
    if (command === 'set' && !(
      (options.length === 1 && options[0] === '--stdin') ||
      (options.length === 2 && ['--value', '--env'].includes(options[0]) && !options[1].startsWith('--'))
    )) return usage();
  }

  let db;
  let result;
  try {
    if ((command === 'oauth-store' || command === 'store')) {
      const protectedStore = command === 'store';
      const input = oauthInput(await readStdin(), protectedStore, service);
      if (protectedStore) secureStorePath(dbPath(), true);
      else if (brokerMode()) throw securityError('Broker mode requires cred store');
      store(service, input, protectedStore);
      result = { provider: service, handle: service, kind: input.kind, stored: true };
    } else if (command === 'path') {
      result = { path: dbPath() };
    } else {
      let value;
      if (command === 'set') {
        if (options[0] === '--env') {
          value = process.env[options[1]];
          if (value === undefined || !options[1]) return emitFail('USAGE', 'The named environment variable must be set');
        } else if (options[0] === '--stdin') {
          const chunks = [];
          for await (const chunk of process.stdin) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
          value = Buffer.concat(chunks).toString('utf8');
        } else {
          process.stderr.write('Warning: --value exposes credentials in argv, which is visible to other processes. Prefer --env or --stdin.\n');
          value = options[1];
        }
      }
      db = openDb();
      if (command === 'set') refuseLegacyWrite(service, db);
      if (command === 'get' && options.length) refuseReveal(service, db);
      if (command === 'set') {
        setCred(service, field, value, db);
        result = { service, field, stored: true };
      } else if (command === 'get') {
        value = getCred(service, field, db);
        if (options.length && value === null) return emitFail('NOT_FOUND', 'Credential not found');
        result = { service, field, set: value !== null };
        if (options.length) result.value = value;
      } else if (command === 'list') {
        result = listCreds(db);
      } else {
        result = { deleted: deleteCred(service, field, db) };
      }
    }
  } catch (err) {
    // Never echo underlying errors: they can contain credential input.
    if (['CREDENTIAL_POLICY', 'STORE_SECURITY'].includes(err.code)) return emitFail(err.code, err.message);
    return emitFail(['oauth-store', 'store'].includes(command) && err?.message === 'invalid input' ? 'CREDENTIAL_INPUT' : 'CREDENTIAL_ERROR',
      ['oauth-store', 'store'].includes(command) && err?.message === 'invalid input' ? 'OAuth credential input is invalid' : 'Credential operation failed');
  }
  // The connection stays cached (creds.js); the process exits after one
  // command and the runtime closes it. Long-lived hosts call closeDb().
  emit(ok(result));
  return 0;
}
