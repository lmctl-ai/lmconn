import { openDb, setCred, getCred, listCreds, deleteCred, dbPath } from './creds.js';
import { emit, ok, emitFail } from './result.js';

const identity = [
  { name: 'service', type: 'string', occurs: '1', description: 'Service name' },
  { name: 'field', type: 'string', occurs: '1', description: 'Credential field name' },
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
];

export async function run(args) {
  const [command, service, field, ...options] = args;
  const usage = () => emitFail('USAGE', 'Usage: cred set <service> <field> (--value V | --env VAR | --stdin), get <service> <field> [--reveal], delete <service> <field>, list, or path');
  if (!['set', 'get', 'list', 'delete', 'path'].includes(command)) return usage();
  if (command === 'list' || command === 'path') {
    if (args.length !== 1) return usage();
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
    if (command === 'path') {
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
  } catch {
    // Never echo underlying errors: they can contain credential input.
    return emitFail('CREDENTIAL_ERROR', 'Credential operation failed');
  } finally {
    db?.close();
  }
  emit(ok(result));
  return 0;
}
