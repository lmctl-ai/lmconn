import { readFile } from 'node:fs/promises';
import { emit, ok, emitFail } from './result.js';
import { converse } from './acp.js';

const usage = (message) => Object.assign(new Error(message), { code: 'USAGE' });
const VALUE_FLAGS = ['--command', '--arg', '--prompt', '--prompts-file', '--cwd', '--timeout-ms'];

function parse(args) {
  const o = { arg: [], prompt: [], autoApprove: false };
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (flag === '--auto-approve') { o.autoApprove = true; continue; }
    if (!VALUE_FLAGS.includes(flag)) throw usage(`unknown option: ${flag}`);
    if (i + 1 >= args.length) throw usage(`missing value for ${flag}`);
    const value = args[++i]; // agent args may legitimately start with "--"
    if (flag === '--arg' || flag === '--prompt') o[flag.slice(2)].push(value);
    else {
      const key = flag.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
      if (o[key] !== undefined) throw usage(`duplicate option: ${flag}`);
      o[key] = value;
    }
  }
  return o;
}

export async function run(args) {
  try {
    const [command, ...rest] = args;
    if (command !== 'chat') throw usage('usage: lmconn acp chat --command CMD [--arg A]... --prompt P [--prompt P]... [--prompts-file F] [--cwd DIR] [--timeout-ms N] [--auto-approve]');
    const o = parse(rest);
    if (!o.command) throw usage('--command is required');
    let prompts = o.prompt;
    if (o.promptsFile !== undefined) {
      let fromFile;
      try { fromFile = JSON.parse(await readFile(o.promptsFile, 'utf8')); } catch (err) { throw usage(`cannot read --prompts-file: ${err.message}`); }
      if (!Array.isArray(fromFile) || !fromFile.every(p => typeof p === 'string')) throw usage('--prompts-file must hold a JSON array of strings');
      prompts = [...fromFile, ...prompts];
    }
    if (prompts.length === 0) throw usage('at least one --prompt (or --prompts-file) is required');
    const timeoutMs = o.timeoutMs === undefined ? 30000 : Number(o.timeoutMs);
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw usage('--timeout-ms must be a positive integer');
    const result = await converse({ command: o.command, args: o.arg, prompts, sessionCwd: o.cwd, cwd: o.cwd, timeoutMs, autoApprove: o.autoApprove });
    emit(ok(result));
    return 0;
  } catch (err) {
    const known = ['USAGE', 'SPAWN', 'AGENT_EXIT', 'AGENT_ERROR', 'PROTOCOL', 'TIMEOUT'];
    return emitFail(known.includes(err.code) ? err.code : 'ACP_ERROR', known.includes(err.code) ? err.message : 'ACP command failed');
  }
}

export const ops = [
  { name: 'acp chat', access: 'write', description: 'Run a multi-turn conversation with an ACP (Agent Client Protocol) agent over stdio', params: [
    { name: 'command', type: 'string', description: 'Agent executable to spawn' },
    { name: 'arg', type: 'array', items: 'string', occurs: '*', description: 'Argument for the agent executable (repeatable)' },
    { name: 'prompt', type: 'array', items: 'string', occurs: '*', description: 'User turn, in order (repeatable)' },
    { name: 'prompts-file', type: 'string', occurs: '?', description: 'JSON array of user turns, sent before any --prompt' },
    { name: 'cwd', type: 'string', occurs: '?', description: 'Working directory for the agent and the session' },
    { name: 'timeout-ms', type: 'number', occurs: '?', default: 30000, description: 'Per-request timeout' },
    { name: 'auto-approve', type: 'boolean', occurs: '?', description: 'Select the first allow option when the agent asks permission (default: cancel)' },
  ] },
];
