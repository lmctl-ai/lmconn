// Minimal Model Context Protocol (MCP) client over stdio (protocol 2025-11-25).
//
// Spawns an MCP server subprocess (e.g. `npx some-mcp-server`, or
// `lmmock stdio mcp ...` in tests) and speaks newline-delimited JSON-RPC 2.0 to
// it (transport in rpc-stdio.js). No network involved. Server-initiated requests
// (sampling, elicitation, roots) are refused with "method not found" because the
// client advertises no capabilities; `ping` is answered.

import { StdioRpc, RpcError } from './rpc-stdio.js';

export const PROTOCOL_VERSION = '2025-11-25';

export class McpClient extends StdioRpc {
  #logs = [];

  constructor(opts = {}) { super(opts, { exit: 'SERVER_EXIT', error: 'SERVER_ERROR' }); this.serverInfo = null; this.capabilities = null; }

  async start() {
    this.spawnPeer();
    const init = await this.request('initialize', { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: 'lmconn', version: '0.1.0' } });
    if (init?.protocolVersion !== PROTOCOL_VERSION) throw new RpcError('PROTOCOL', `server speaks MCP ${init?.protocolVersion}, client supports ${PROTOCOL_VERSION}`);
    this.serverInfo = init.serverInfo ?? null;
    this.capabilities = init.capabilities ?? {};
    this.notify('notifications/initialized');
    return init;
  }

  async listTools() { return (await this.request('tools/list', {})).tools ?? []; }
  async listResources() { return (await this.request('resources/list', {})).resources ?? []; }
  async listPrompts() { return (await this.request('prompts/list', {})).prompts ?? []; }
  async readResource(uri) { return (await this.request('resources/read', { uri })).contents ?? []; }
  async getPrompt(name, args = {}) { return this.request('prompts/get', { name, arguments: args }); }
  ping() { return this.request('ping', {}); }

  // Call a tool. `logs` holds notifications/message payloads the server sent
  // while the call was in flight.
  async callTool(name, args = {}) {
    if (typeof name !== 'string' || !name) throw new RpcError('USAGE', 'tool name is required');
    this.#logs = [];
    const res = await this.request('tools/call', { name, arguments: args });
    const content = res?.content ?? [];
    return { name, content, text: content.filter(c => c.type === 'text').map(c => c.text).join(''), isError: res?.isError === true, logs: this.#logs };
  }

  onNotification(msg) { if (msg.method === 'notifications/message') this.#logs.push(msg.params); }
  onRequest(msg) { return msg.method === 'ping' ? { result: {} } : super.onRequest(msg); }
}

// Run `fn(client)` against a freshly started server and always clean up.
export async function withMcp(opts, fn) {
  const client = new McpClient(opts);
  try { await client.start(); return await fn(client); } finally { await client.close(); }
}
