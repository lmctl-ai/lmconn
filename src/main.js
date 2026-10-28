// Argument router. Each area lives in src/cmd-<area>.js and exports:
//   export async function run(args) -> number (exit code; emit()s its envelope)
//   export const ops = [...]  (cli.schema.v1 operation fragments, optional)
// Missing module = not implemented yet, exit 2 with a clear name.

import { readFileSync } from 'node:fs';
import { emit, ok, emitFail } from './result.js';

const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

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
    // lmapi contract: the bare cli.schema.v1 document, not the envelope (lmscript imports it as is).
    const mod = await import('./schema.js');
    process.stdout.write(JSON.stringify(await mod.schemaDocument(), null, 2) + '\n');
    return 0;
  }
  if (argv.includes('--input-json') || argv.includes('--input-file')) {
    // Schema-module call from lmscript: lmconn <op> --input-json '{"op","params"}' -> ordinary argv.
    const mod = await import('./schema.js');
    try {
      argv = await mod.argvFromSchemaCall(argv);
    } catch (err) {
      return emitFail(err.code === 'USAGE' || err.code === 'READONLY' ? err.code : 'USAGE', err.message);
    }
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
