// Shared transport for stdio JSON-RPC 2.0 clients (ACP, MCP): spawn a peer
// subprocess, exchange newline-delimited messages, correlate requests with
// responses, enforce per-request timeouts and surface typed errors.
// Subclasses supply `label`-based error codes and override onNotification /
// onRequest to handle peer-initiated messages.

import { spawn } from 'node:child_process';

const STDERR_CAP = 500;

export class RpcError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.code = code;
    Object.assign(this, extra);
  }
}

export class StdioRpc {
  #child; #buffer = ''; #nextId = 1; #pending = new Map(); #closed = false; #stderr = ''; #exit = null;
  #opts;

  // codes: { exit, error } error codes for peer exit / peer JSON-RPC error.
  constructor({ command, args = [], cwd, env, timeoutMs = 30000 } = {}, codes = { exit: 'PEER_EXIT', error: 'PEER_ERROR' }) {
    if (typeof command !== 'string' || !command) throw new RpcError('USAGE', 'command is required');
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new RpcError('USAGE', 'timeoutMs must be a positive number');
    this.#opts = { command, args, cwd, env, timeoutMs, codes };
  }

  get stderr() { return this.#stderr; }

  // Hooks for subclasses.
  onNotification(_msg) {}
  onRequest(msg) { return { code: -32601, message: `client does not implement ${msg.method}` }; } // return {result}|{code,message}

  spawnPeer() {
    const { command, args, cwd, env, codes } = this.#opts;
    this.#child = spawn(command, args, { cwd, env: env ? { ...process.env, ...env } : process.env, shell: false, stdio: ['pipe', 'pipe', 'pipe'] });
    this.#child.stdout.setEncoding('utf8');
    this.#child.stderr.setEncoding('utf8');
    this.#child.stdout.on('data', chunk => this.#onData(chunk));
    this.#child.stderr.on('data', chunk => { this.#stderr = (this.#stderr + chunk).slice(-STDERR_CAP); });
    this.#child.stdin.on('error', () => {});
    this.#child.on('error', error => this.#fail(new RpcError('SPAWN', `${command}: ${error.message}`)));
    this.#child.on('close', (code, signal) => {
      this.#exit = { code, signal };
      this.#fail(new RpcError(codes.exit, `peer exited${code === null ? '' : ` with code ${code}`}${signal ? ` (signal ${signal})` : ''}${this.#stderr ? `: ${this.#stderr.trim()}` : ''}`));
    });
  }

  request(method, params) {
    if (this.#closed) return Promise.reject(new RpcError(this.#opts.codes.exit, 'connection is closed'));
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new RpcError('TIMEOUT', `${method} timed out after ${this.#opts.timeoutMs}ms`));
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
      try { msg = JSON.parse(line); } catch { this.#fail(new RpcError('PROTOCOL', 'peer wrote a non-JSON line on stdout')); this.#child.kill('SIGKILL'); return; }
      this.#onMessage(msg);
    }
  }
  #onMessage(msg) {
    if (msg.method !== undefined) {
      if (msg.id === undefined) { this.onNotification(msg); return; }
      const reply = this.onRequest(msg);
      this.#send(reply.code !== undefined
        ? { jsonrpc: '2.0', id: msg.id, error: { code: reply.code, message: reply.message } }
        : { jsonrpc: '2.0', id: msg.id, result: reply.result });
      return;
    }
    const p = this.#pending.get(msg.id);
    if (!p) return;
    this.#pending.delete(msg.id);
    clearTimeout(p.timer);
    if (msg.error) p.reject(new RpcError(this.#opts.codes.error, `${p.method}: ${msg.error.message ?? 'peer error'}`, { rpcCode: msg.error.code }));
    else p.resolve(msg.result);
  }
}
