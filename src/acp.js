// Minimal Agent Client Protocol (ACP) client over stdio.
//
// Spawns an agent subprocess (e.g. `gemini --experimental-acp`, or
// `lmmock stdio acp ...` in tests) and speaks newline-delimited JSON-RPC 2.0 to
// it (transport in rpc-stdio.js): initialize -> session/new -> any number of
// session/prompt turns. Agent text streams back as session/update
// `agent_message_chunk` notifications and each turn ends with a `stopReason`.
//
// Requests the agent makes of the client are answered conservatively:
//   session/request_permission  -> cancelled, or the first allow option with
//                                  autoApprove: true
//   fs/* and terminal/*         -> JSON-RPC "method not found" (not advertised)

import { StdioRpc, RpcError } from './rpc-stdio.js';

export { RpcError as AcpError };
export const PROTOCOL_VERSION = 1;

export class AcpClient extends StdioRpc {
  #autoApprove; #listeners = new Set();

  constructor({ autoApprove = false, ...opts } = {}) {
    super(opts, { exit: 'AGENT_EXIT', error: 'AGENT_ERROR' });
    this.#autoApprove = autoApprove;
    this.sessionId = null;
    this.agentCapabilities = null;
  }

  async start() {
    this.spawnPeer();
    const init = await this.request('initialize', {
      protocolVersion: PROTOCOL_VERSION,
      clientCapabilities: { fs: { readTextFile: false, writeTextFile: false }, terminal: false },
    });
    if (init?.protocolVersion !== PROTOCOL_VERSION) throw new RpcError('PROTOCOL', `agent speaks ACP protocol ${init?.protocolVersion}, client supports ${PROTOCOL_VERSION}`);
    this.agentCapabilities = init.agentCapabilities ?? {};
    this.notify('notifications/initialized');
    return init;
  }

  async newSession({ cwd = process.cwd(), mcpServers = [] } = {}) {
    const res = await this.request('session/new', { cwd, mcpServers });
    if (typeof res?.sessionId !== 'string' || !res.sessionId) throw new RpcError('PROTOCOL', 'session/new returned no sessionId');
    this.sessionId = res.sessionId;
    return res;
  }

  // One conversation turn. Resolves with the concatenated agent text, the
  // ordered chunk list, every raw session/update and the stopReason.
  async prompt(text) {
    if (!this.sessionId) throw new RpcError('USAGE', 'call newSession() before prompt()');
    if (typeof text !== 'string') throw new RpcError('USAGE', 'prompt must be a string');
    const updates = [];
    const listener = msg => {
      if (msg.method === 'session/update' && msg.params?.sessionId === this.sessionId) updates.push(msg.params.update);
    };
    this.#listeners.add(listener);
    try {
      const res = await this.request('session/prompt', { sessionId: this.sessionId, prompt: [{ type: 'text', text }] });
      const chunks = updates.filter(u => u?.sessionUpdate === 'agent_message_chunk' && u.content?.type === 'text').map(u => u.content.text);
      return { text: chunks.join(''), chunks, stopReason: res?.stopReason ?? null, updates };
    } finally { this.#listeners.delete(listener); }
  }

  onNotification(msg) { for (const l of this.#listeners) l(msg); }

  onRequest(msg) {
    if (msg.method === 'session/request_permission') {
      const allow = (msg.params?.options ?? []).find(o => String(o.kind).startsWith('allow'));
      const outcome = this.#autoApprove && allow ? { outcome: 'selected', optionId: allow.optionId } : { outcome: 'cancelled' };
      return { result: { outcome } };
    }
    return super.onRequest(msg);
  }
}

// Convenience: run a whole multi-turn conversation and always clean up.
export async function converse({ prompts, sessionCwd, ...opts }) {
  if (!Array.isArray(prompts) || prompts.length === 0) throw new RpcError('USAGE', 'at least one prompt is required');
  const client = new AcpClient(opts);
  try {
    await client.start();
    await client.newSession({ cwd: sessionCwd });
    const turns = [];
    for (const prompt of prompts) {
      const turn = await client.prompt(prompt);
      turns.push({ prompt, text: turn.text, chunks: turn.chunks, stopReason: turn.stopReason });
    }
    return { sessionId: client.sessionId, agentCapabilities: client.agentCapabilities, turns };
  } finally { await client.close(); }
}
