import { emit, ok, emitFail } from './result.js';
import { withMcp } from './mcp.js';

const usage = (message) => Object.assign(new Error(message), { code: 'USAGE' });
const VALUE_FLAGS = ['--command', '--arg', '--tool', '--arguments', '--call', '--uri', '--name', '--cwd', '--timeout-ms'];
const USAGE = 'usage: lmconn mcp <tools|call|session|resources|read|prompts|prompt> --command CMD [--arg A]... [--timeout-ms N]';

function parse(args) {
  const o = { arg: [], call: [] };
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (!VALUE_FLAGS.includes(flag)) throw usage(`unknown option: ${flag}`);
    if (i + 1 >= args.length) throw usage(`missing value for ${flag}`);
    const value = args[++i]; // server args may legitimately start with "--"
    const key = flag.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    if (key === 'arg' || key === 'call') o[key].push(value);
    else if (o[key] !== undefined) throw usage(`duplicate option: ${flag}`);
    else o[key] = value;
  }
  return o;
}
function jsonObject(text, what) {
  let v;
  try { v = JSON.parse(text); } catch (err) { throw usage(`${what} must be JSON: ${err.message}`); }
  if (v === null || typeof v !== 'object' || Array.isArray(v)) throw usage(`${what} must be a JSON object`);
  return v;
}

export async function run(args) {
  try {
    const [sub, ...rest] = args;
    if (!['tools', 'call', 'session', 'resources', 'read', 'prompts', 'prompt'].includes(sub)) throw usage(USAGE);
    const o = parse(rest);
    if (!o.command) throw usage('--command is required');
    const timeoutMs = o.timeoutMs === undefined ? 30000 : Number(o.timeoutMs);
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw usage('--timeout-ms must be a positive integer');
    const need = (value, flag) => { if (!value) throw usage(`${flag} is required for mcp ${sub}`); return value; };
    let calls;
    if (sub === 'call') calls = [{ name: need(o.tool, '--tool'), arguments: o.arguments === undefined ? {} : jsonObject(o.arguments, '--arguments') }];
    if (sub === 'session') {
      if (o.call.length === 0) throw usage('mcp session needs at least one --call \'{"name":...,"arguments":{...}}\'');
      calls = o.call.map(c => { const v = jsonObject(c, '--call'); if (typeof v.name !== 'string') throw usage('--call needs a string "name"'); return { name: v.name, arguments: v.arguments ?? {} }; });
    }
    if (sub === 'read') need(o.uri, '--uri');
    if (sub === 'prompt') need(o.name, '--name');
    const result = await withMcp({ command: o.command, args: o.arg, cwd: o.cwd, timeoutMs }, async client => {
      const server = { serverInfo: client.serverInfo, capabilities: client.capabilities };
      if (sub === 'tools') return { ...server, tools: await client.listTools() };
      if (sub === 'resources') return { ...server, resources: await client.listResources() };
      if (sub === 'prompts') return { ...server, prompts: await client.listPrompts() };
      if (sub === 'read') return { ...server, contents: await client.readResource(o.uri) };
      if (sub === 'prompt') return { ...server, ...await client.getPrompt(o.name, o.arguments === undefined ? {} : jsonObject(o.arguments, '--arguments')) };
      const results = [];
      for (const c of calls) results.push(await client.callTool(c.name, c.arguments));
      return { ...server, results };
    });
    emit(ok(result));
    return 0;
  } catch (err) {
    const known = ['USAGE', 'SPAWN', 'SERVER_EXIT', 'SERVER_ERROR', 'PROTOCOL', 'TIMEOUT'];
    return emitFail(known.includes(err.code) ? err.code : 'MCP_ERROR', known.includes(err.code) ? err.message : 'MCP command failed');
  }
}

const target = [
  { name: 'command', type: 'string', description: 'MCP server executable to spawn (stdio)' },
  { name: 'arg', type: 'array', items: 'string', occurs: '*', description: 'Argument for the server executable (repeatable)' },
  { name: 'cwd', type: 'string', occurs: '?', description: 'Working directory for the server' },
  { name: 'timeout-ms', type: 'number', occurs: '?', default: 30000, description: 'Per-request timeout' },
];
export const ops = [
  { name: 'mcp tools', access: 'read', description: 'List the tools of a stdio MCP server', params: target },
  { name: 'mcp resources', access: 'read', description: 'List the resources of a stdio MCP server', params: target },
  { name: 'mcp prompts', access: 'read', description: 'List the prompts of a stdio MCP server', params: target },
  { name: 'mcp read', access: 'read', description: 'Read a resource from a stdio MCP server', params: [...target, { name: 'uri', type: 'string', description: 'Resource URI' }] },
  { name: 'mcp prompt', access: 'read', description: 'Get a prompt from a stdio MCP server', params: [...target,
    { name: 'name', type: 'string', description: 'Prompt name' }, { name: 'arguments', type: 'string', occurs: '?', description: 'Prompt arguments as a JSON object' }] },
  { name: 'mcp call', access: 'write', description: 'Call one tool on a stdio MCP server', params: [...target,
    { name: 'tool', type: 'string', description: 'Tool name' }, { name: 'arguments', type: 'string', occurs: '?', description: 'Tool arguments as a JSON object' }] },
  { name: 'mcp session', access: 'write', description: 'Call several tools in order within one MCP session', params: [...target,
    { name: 'call', type: 'array', items: 'string', occurs: '+', description: 'JSON {"name":...,"arguments":{...}} per call (repeatable)' }] },
];
