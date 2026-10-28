import { readFile } from 'node:fs/promises';
import { emit, ok, emitFail } from './result.js';
import { providers, resolveKey } from './providers/index.js';
import { chatApi } from './providers/api.js';

const usage = (message) => Object.assign(new Error(message), { code: 'USAGE' });
function checkProvider(name) {
  if (!Object.hasOwn(providers, name)) throw usage(`unknown provider: ${name}; known providers: ${Object.keys(providers).join(', ')}`);
}
async function optionalModule(path) {
  try { return await import(path); }
  catch (err) {
    if (err.code === 'ERR_MODULE_NOT_FOUND') throw Object.assign(new Error(`adapter not implemented yet: ${path}`), { code: 'NOT_IMPLEMENTED' });
    throw err;
  }
}

export async function run(args) {
  try {
    const [command, ...rest] = args;
    if (command === 'providers') {
      if (rest.length) throw usage('usage: lmconn llm providers');
      emit(ok(Object.entries(providers).map(([name, p]) => ({ name, kind: p.kind,
        defaultModel: p.defaultModel ?? null, key: resolveKey(name).source }))));
    } else if (command === 'chat') {
      const [name, ...flags] = rest;
      checkProvider(name);
      const options = {};
      for (let i = 0; i < flags.length; i++) {
        const flag = flags[i];
        if (!['--model', '--system', '--max-tokens', '--prompt', '--prompt-file', '--stdin'].includes(flag)) throw usage(`unknown option: ${flag}`);
        if (Object.hasOwn(options, flag)) throw usage(`duplicate option: ${flag}`);
        if (flag === '--stdin') options[flag] = true;
        else {
          if (i + 1 >= flags.length || flags[i + 1].startsWith('--')) throw usage(`missing value for ${flag}`);
          options[flag] = flags[++i];
        }
      }
      if (['--prompt', '--prompt-file', '--stdin'].filter(flag => Object.hasOwn(options, flag)).length > 1) throw usage('choose only one of --prompt, --prompt-file, --stdin');
      const maxTokens = options['--max-tokens'] === undefined ? 256 : Number(options['--max-tokens']);
      if (!Number.isSafeInteger(maxTokens) || maxTokens < 1) throw usage('--max-tokens must be a positive integer');
      let prompt = options['--prompt'];
      if (Object.hasOwn(options, '--prompt-file')) prompt = await readFile(options['--prompt-file'], 'utf8');
      if (prompt === undefined) {
        const chunks = [];
        for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
        prompt = Buffer.concat(chunks).toString('utf8');
      }
      const p = providers[name];
      const request = { prompt, system: options['--system'], model: options['--model'], maxTokens };
      let result;
      if (p.kind === 'api') result = await chatApi(name, request);
      else if (p.kind === 'cli') {
        const { chatCli } = await optionalModule('./providers/cli.js');
        result = await chatCli(name, { prompt, system: request.system, timeoutMs: p.timeoutMs });
      } else throw Object.assign(new Error(`unsupported provider kind: ${p.kind}`), { code: 'NOT_IMPLEMENTED' });
      emit(ok({ ...result, provider: name, model: result.model ?? p.defaultModel ?? null }));
    } else if (command === 'probe') {
      const names = rest.length ? rest : Object.keys(providers);
      names.forEach(checkProvider);
      const { probe } = await optionalModule('./llm-probe.js');
      emit(ok(await probe(names)));
    } else throw usage('usage: lmconn llm <providers|chat|probe>');
    return 0;
  } catch (err) {
    const known = ['USAGE', 'NOT_IMPLEMENTED', 'MISSING_KEY', 'HTTP_ERROR', 'TIMEOUT', 'API_ERROR', 'INVALID_RESPONSE'];
    return emitFail(known.includes(err.code) ? err.code : 'LLM_ERROR', known.includes(err.code) ? err.message : 'LLM command failed');
  }
}

export const ops = [
  { name: 'llm providers', access: 'read', description: 'List providers and credential sources (never keys)', params: [] },
  { name: 'llm chat', access: 'write', description: 'Send a prompt to an LLM provider', params: [
    { name: 'provider', type: 'string', positional: true, description: 'Provider name' },
    ...['model', 'system', 'prompt', 'prompt-file'].map(name => ({ name, type: 'string', occurs: '?', description: name === 'prompt-file' ? 'Read prompt from a UTF-8 file' : name })),
    { name: 'max-tokens', type: 'number', occurs: '?', default: 256, description: 'Maximum API completion tokens' },
    { name: 'stdin', type: 'boolean', occurs: '?', description: 'Read prompt from stdin (default without a prompt option)' },
  ] },
  { name: 'llm probe', access: 'write', description: 'Probe selected providers, or all providers by default', params: [
    { name: 'provider', type: 'array', items: 'string', occurs: '*', description: 'Provider names' },
  ] },
];
