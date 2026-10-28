// Argument router. Each area lives in src/cmd-<area>.js and exports:
//   export async function run(args) -> number (exit code; emit()s its envelope)
//   export const ops = [...]  (cli.schema.v1 operation fragments, optional)
// Missing module = not implemented yet, exit 2 with a clear name.

import { emit, ok, emitFail } from './result.js';

const VERSION = '0.1.0';

const AREAS = new Set(['cred', 'llm', 'http', 'github']);

const USAGE = [
  'lmconn — connectors for lmscript',
  '',
  'usage:',
  '  lmconn --version',
  '  lmconn --cli-schema --json        print the cli.schema.v1 document',
  '  lmconn cred <set|get|list|delete> ...',
  '  lmconn llm <providers|chat|probe> ...',
  '  lmconn http <request> ...',
  '  lmconn github <...> ...',
].join('\n');

export async function main(argv) {
  if (argv.includes('--version') || argv.includes('-v')) {
    emit(ok({ name: 'lmconn', version: VERSION }));
    return 0;
  }
  if (argv.includes('--cli-schema')) {
    const mod = await import('./schema.js');
    emit(ok(mod.schemaDocument()));
    return 0;
  }
  const area = argv[0];
  if (!area || argv.includes('--help') || argv.includes('-h')) {
    process.stderr.write(USAGE + '\n');
    return area ? 0 : 2;
  }
  if (!AREAS.has(area)) {
    return emitFail('USAGE', `unknown area: ${area}`, { areas: [...AREAS] });
  }
  try {
    const mod = await import(`./cmd-${area}.js`);
    return await mod.run(argv.slice(1));
  } catch (err) {
    if (err?.code === 'ERR_MODULE_NOT_FOUND' && String(err?.message).includes(`cmd-${area}`)) {
      return emitFail('NOT_IMPLEMENTED', `area not implemented yet: ${area}`);
    }
    throw err;
  }
}
