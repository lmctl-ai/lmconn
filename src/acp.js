// Minimal Agent Client Protocol (ACP) client over stdio.
//
// Spawns an agent subprocess (e.g. `gemini --experimental-acp`, or
// `lmmock stdio acp ...` in tests) and speaks newline-delimited JSON-RPC 2.0 to
// it: initialize -> session/new -> any number of session/prompt turns. Agent
// text streams back as session/update `agent_message_chunk` notifications and
// each turn ends with a `stopReason`. Zero dependencies.
//
// Requests the agent makes of the client are answered conservatively:
//   session/request_permission  -> cancelled, or the first allow option with
//                                  autoApprove: true
//   fs/* and terminal/*         -> JSON-RPC "method not found" (not advertised)

import { spawn } from 'node:child_process';

export const PROTOCOL_VERSION = 1;
const STDERR_CAP = 500;

export class AcpError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.code = code;
    Object.assign(this, extra);
  }
}

export class AcpClient {
  #child; #buffer = ''; #nextId = 1; #pending = new Map(); #closed = false;
  #stderr = ''; #exit = null; #listeners = new Set(); #opts;

  constructor({ command, args = [], cwd, env, timeoutMs = 30000, autoApprove = false } = {}) {
    if (typeof command !== 'string' || !command) throw new AcpError('USAGE', 'command is required');
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new AcpError('USAGE', 'timeoutMs must be a positive number');
    this.#opts = { command, args, cwd, env, timeoutMs, autoApprove };
    this.sessionId = null;
    this.agentCapabilities = null;
  }

  get stderr() { return this.#stderr; }

  async start() {
    const { command, args, cwd, env } = this.#opts;
    this.#child = spawn(command, args, { cwd, env: env ? { ...process.env, ...env } : process.env, shell: false, stdio: ['pipe', 'pipe', 'pipe'] });
    this.#child.stdout.setEncoding('utf8');
    this.#child.stderr.setEncoding('utf8');
    this.#child.stdout.on('data', chunk => this.#onData(chunk));
    this.#child.stderr.on('data', chunk => { this.#stderr = (this.#stderr + chunk).slice(-STDERR_CAP); });
    this.#child.stdin.on('error', () => {});
    this.#child.on('error', error => this.#fail(new AcpError('SPAWN', `agent ${command}: ${error.message}`)));
    this.#child.on('close', (code, signal) => {
      this.#exit = { code, signal };
      this.#fail(new AcpError('AGENT_EXIT', `agent exited${code === null ? '' : ` with code ${code}`}${signal ? ` (signal ${signal})` : ''}${this.#stderr ? `: ${this.#stderr.trim()}` : ''}`));
    });
    const init = await this.request('initialize', {
      protocolVersion: PROTOCOL_VERSION,
      clientCapabilities: { fs: { readTextFile: false, writeTextFile: false }, terminal: false },
    });
    if (init?.protocolVersion !== PROTOCOL_VERSION) throw new AcpError('PROTOCOL', `agent speaks ACP protocol ${init?.protocolVersion}, client supports ${PROTOCOL_VERSION}`);
    this.agentCapabilities = init.agentCapabilities ?? {};
    this.notify('notifications/initialized');
    return init;
  }

  async newSession({ cwd = process.cwd(), mcpServers = [] } = {}) {
    const res = await this.request('session/new', { cwd, mcpServers });
    if (typeof res?.sessionId !== 'string' || !res.sessionId) throw new AcpError('PROTOCOL', 'session/new returned no sessionId');
    this.sessionId = res.sessionId;
    return res;
  }

  // One conversation turn. Resolves with the concatenated agent text, the
  // ordered chunk list, every raw session/update and the stopReason.
  async prompt(text) {
    if (!this.sessionId) throw new AcpError('USAGE', 'call newSession() before prompt()');
    if (typeof text !== 'string') throw new AcpError('USAGE', 'prompt must be a string');
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

  request(method, params) {
    if (this.#closed) return Promise.reject(this.#closedError());
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new AcpError('TIMEOUT', `${method} timed out after ${this.#opts.timeoutMs}ms`));
      }, this.#opts.timeoutMs);
      this.#pending.set(id, { method, resolve, reject, timer });
      this.#send({ jsonrpc: '2.0', id, method, params });
    });
  }

  notify(method, params) {
    this.#send(params === undefined ? { jsonrpc: '2.0', method } : { jsonrpc: '2.0', method, params });
  }

  async close() {
    if (!this.#child) return;
    this.#closed = true;
    this.#child.stdin.end();
    if (this.#exit) return;
    await new Promise(resolve => {
      const kill = setTimeout(() => this.#child.kill('SIGKILL'), 2000);
      this.#child.once('close', () => { clearTimeout(kill); resolve(); });
    });
  }

  #closedError() { return new AcpError('AGENT_EXIT', 'agent connection is closed'); }
  #send(message) {
    if (!this.#child?.stdin.writable) return;
    this.#child.stdin.write(JSON.stringify(message) + '\n');
  }
  #fail(error) {
    this.#closed = true;
    for (const [id, p] of this.#pending) { clearTimeout(p.timer); this.#pending.delete(id); p.reject(error); }
  }
  #onData(chunk) {
    this.#buffer += chunk;
    let nl;
    while ((nl = this.#buffer.indexOf('\n')) >= 0) {
      const line = this.#buffer.slice(0, nl).trim();
      this.#buffer = this.#buffer.slice(nl + 1);
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { this.#fail(new AcpError('PROTOCOL', 'agent wrote a non-JSON line on stdout')); this.#child.kill('SIGKILL'); return; }
      this.#onMessage(msg);
    }
  }
  #onMessage(msg) {
    if (msg.method !== undefined) {
      if (msg.id === undefined) { for (const l of this.#listeners) l(msg); return; }
      this.#send(this.#answer(msg));
      return;
    }
    const p = this.#pending.get(msg.id);
    if (!p) return;
    this.#pending.delete(msg.id);
    clearTimeout(p.timer);
    if (msg.error) p.reject(new AcpError('AGENT_ERROR', `${p.method}: ${msg.error.message ?? 'agent error'}`, { rpcCode: msg.error.code }));
    else p.resolve(msg.result);
  }
  // Reply to an agent->client request.
  #answer(msg) {
    if (msg.method === 'session/request_permission') {
      const allow = (msg.params?.options ?? []).find(o => String(o.kind).startsWith('allow'));
      const outcome = this.#opts.autoApprove && allow ? { outcome: 'selected', optionId: allow.optionId } : { outcome: 'cancelled' };
      return { jsonrpc: '2.0', id: msg.id, result: { outcome } };
    }
    return { jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: `client does not implement ${msg.method}` } };
  }
}

// Convenience: run a whole multi-turn conversation and always clean up.
export async function converse({ prompts, sessionCwd, ...opts }) {
  if (!Array.isArray(prompts) || prompts.length === 0) throw new AcpError('USAGE', 'at least one prompt is required');
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
