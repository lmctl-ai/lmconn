// Valkey / Redis client connector supporting both native RESP and REST protocols.
// Zero external dependencies.
//
// Usage:
//   lmconn valkey ping [--host H] [--port P] [--mode resp|rest]
//   lmconn valkey get <key> [--host H] [--port P] [--mode resp|rest]
//   lmconn valkey set <key> <value> [--host H] [--port P] [--mode resp|rest]
//   lmconn valkey del <key> [--host H] [--port P] [--mode resp|rest]
//   lmconn valkey cmd <COMMAND> [args...] [--host H] [--port P] [--mode resp|rest]

import net from 'node:net';
import { emit, ok, emitFail } from './result.js';

export const ops = [
  { name: 'valkey ping', access: 'read', description: 'Ping Valkey server via native RESP or REST', params: [
    { name: 'host', type: 'string', occurs: '?', default: '127.0.0.1', description: 'Valkey host' },
    { name: 'port', type: 'number', occurs: '?', description: 'Valkey port (default 6379 for resp, 8080 for rest)' },
    { name: 'mode', type: 'string', occurs: '?', default: 'resp', enum: ['resp', 'rest'], description: 'Protocol mode: resp or rest' },
    { name: 'timeout', type: 'number', occurs: '?', default: 5000, description: 'Timeout in milliseconds' },
  ] },
  { name: 'valkey get', access: 'read', description: 'Get a key from Valkey', params: [
    { name: 'key', type: 'string', occurs: '1', positional: true, description: 'Key name' },
    { name: 'host', type: 'string', occurs: '?', default: '127.0.0.1', description: 'Valkey host' },
    { name: 'port', type: 'number', occurs: '?', description: 'Valkey port' },
    { name: 'mode', type: 'string', occurs: '?', default: 'resp', enum: ['resp', 'rest'], description: 'Protocol mode: resp or rest' },
    { name: 'timeout', type: 'number', occurs: '?', default: 5000, description: 'Timeout in milliseconds' },
  ] },
  { name: 'valkey set', access: 'write', description: 'Set a key in Valkey', params: [
    { name: 'key', type: 'string', occurs: '1', positional: true, description: 'Key name' },
    { name: 'value', type: 'string', occurs: '1', positional: true, description: 'Value to store' },
    { name: 'host', type: 'string', occurs: '?', default: '127.0.0.1', description: 'Valkey host' },
    { name: 'port', type: 'number', occurs: '?', description: 'Valkey port' },
    { name: 'mode', type: 'string', occurs: '?', default: 'resp', enum: ['resp', 'rest'], description: 'Protocol mode: resp or rest' },
    { name: 'timeout', type: 'number', occurs: '?', default: 5000, description: 'Timeout in milliseconds' },
  ] },
  { name: 'valkey del', access: 'write', description: 'Delete a key in Valkey', params: [
    { name: 'key', type: 'string', occurs: '1', positional: true, description: 'Key name' },
    { name: 'host', type: 'string', occurs: '?', default: '127.0.0.1', description: 'Valkey host' },
    { name: 'port', type: 'number', occurs: '?', description: 'Valkey port' },
    { name: 'mode', type: 'string', occurs: '?', default: 'resp', enum: ['resp', 'rest'], description: 'Protocol mode: resp or rest' },
    { name: 'timeout', type: 'number', occurs: '?', default: 5000, description: 'Timeout in milliseconds' },
  ] },
  { name: 'valkey cmd', access: 'write', description: 'Execute arbitrary command against Valkey', params: [
    { name: 'command', type: 'string', occurs: '1', positional: true, description: 'Command name' },
    { name: 'args', type: 'array', items: 'string', occurs: '*', description: 'Command arguments' },
    { name: 'host', type: 'string', occurs: '?', default: '127.0.0.1', description: 'Valkey host' },
    { name: 'port', type: 'number', occurs: '?', description: 'Valkey port' },
    { name: 'mode', type: 'string', occurs: '?', default: 'resp', enum: ['resp', 'rest'], description: 'Protocol mode: resp or rest' },
    { name: 'timeout', type: 'number', occurs: '?', default: 5000, description: 'Timeout in milliseconds' },
  ] },
];

function formatResp(args) {
  let out = `*${args.length}\r\n`;
  for (const arg of args) {
    const s = String(arg);
    out += `$${Buffer.byteLength(s)}\r\n${s}\r\n`;
  }
  return Buffer.from(out);
}

function parseResp(buf, offset = 0) {
  if (offset >= buf.length) return { needed: true };
  const type = String.fromCharCode(buf[offset]);
  const crlf = buf.indexOf('\r\n', offset + 1);
  if (crlf === -1) return { needed: true };
  const line = buf.toString('utf8', offset + 1, crlf);

  if (type === '+') {
    return { val: line, next: crlf + 2 };
  } else if (type === '-') {
    throw Object.assign(new Error(line), { code: 'VALKEY_ERROR' });
  } else if (type === ':') {
    return { val: parseInt(line, 10), next: crlf + 2 };
  } else if (type === '$') {
    const len = parseInt(line, 10);
    if (len === -1) return { val: null, next: crlf + 2 };
    const strStart = crlf + 2;
    const strEnd = strStart + len;
    if (buf.length < strEnd + 2) return { needed: true };
    const val = buf.toString('utf8', strStart, strEnd);
    return { val, next: strEnd + 2 };
  } else if (type === '*') {
    const count = parseInt(line, 10);
    if (count === -1) return { val: null, next: crlf + 2 };
    let curr = crlf + 2;
    const items = [];
    for (let i = 0; i < count; i++) {
      const res = parseResp(buf, curr);
      if (res.needed) return { needed: true };
      items.push(res.val);
      curr = res.next;
    }
    return { val: items, next: curr };
  } else if (type === '#') {
    return { val: line === 't', next: crlf + 2 };
  } else if (type === ',') {
    return { val: parseFloat(line), next: crlf + 2 };
  } else if (type === '_') {
    return { val: null, next: crlf + 2 };
  } else {
    throw Object.assign(new Error(`Unknown RESP prefix: ${type}`), { code: 'PROTOCOL_ERROR' });
  }
}

export async function sendResp(host, port, cmdArgs, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    let buffer = Buffer.alloc(0);
    let resolved = false;

    const timer = setTimeout(() => {
      socket.destroy();
      reject(Object.assign(new Error(`Valkey connection timed out after ${timeoutMs}ms`), { code: 'TIMEOUT' }));
    }, timeoutMs);

    socket.on('connect', () => {
      socket.write(formatResp(cmdArgs));
    });

    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      try {
        const parsed = parseResp(buffer);
        if (!parsed.needed) {
          resolved = true;
          clearTimeout(timer);
          socket.end();
          resolve(parsed.val);
        }
      } catch (err) {
        resolved = true;
        clearTimeout(timer);
        socket.destroy();
        reject(err);
      }
    });

    socket.on('error', (err) => {
      clearTimeout(timer);
      if (!resolved) {
        resolved = true;
        reject(Object.assign(new Error(`Connection failed: ${err.message}`), { code: 'NETWORK' }));
      }
    });

    socket.on('close', () => {
      clearTimeout(timer);
      if (!resolved) {
        resolved = true;
        reject(Object.assign(new Error('Connection closed before reply received'), { code: 'NETWORK' }));
      }
    });
  });
}

export async function sendRest(host, port, cmdArgs, timeoutMs = 5000) {
  const [cmd, ...args] = cmdArgs;
  const c = cmd.toLowerCase();
  let url;
  let init = { signal: AbortSignal.timeout(timeoutMs) };

  if (c === 'ping') {
    url = `http://${host}:${port}/ping`;
  } else if (c === 'get' && args.length === 1) {
    url = `http://${host}:${port}/get/${encodeURIComponent(args[0])}`;
  } else if (c === 'set' && args.length === 2) {
    url = `http://${host}:${port}/set/${encodeURIComponent(args[0])}`;
    init.method = 'POST';
    init.body = String(args[1]);
  } else if ((c === 'del' || c === 'delete') && args.length === 1) {
    url = `http://${host}:${port}/keys/${encodeURIComponent(args[0])}`;
    init.method = 'DELETE';
  } else {
    url = `http://${host}:${port}/cmd`;
    init.method = 'POST';
    init.headers = { 'Content-Type': 'application/json' };
    init.body = JSON.stringify(cmdArgs);
  }

  let res;
  try {
    res = await fetch(url, init);
  } catch (err) {
    throw Object.assign(new Error(`REST request failed: ${err.message}`), { code: 'NETWORK' });
  }

  let data;
  try {
    data = await res.json();
  } catch (err) {
    throw Object.assign(new Error(`Invalid JSON reply from REST endpoint: ${err.message}`), { code: 'PROTOCOL_ERROR' });
  }

  if (data && data.ok === false) {
    throw Object.assign(new Error(data.error || 'REST error'), { code: 'VALKEY_ERROR' });
  }
  return data ? data.result : null;
}

export async function run(args) {
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    process.stderr.write(
      'Usage:\n' +
      '  lmconn valkey ping [--host H] [--port P] [--mode resp|rest]\n' +
      '  lmconn valkey get <key> [--host H] [--port P] [--mode resp|rest]\n' +
      '  lmconn valkey set <key> <val> [--host H] [--port P] [--mode resp|rest]\n' +
      '  lmconn valkey del <key> [--host H] [--port P] [--mode resp|rest]\n' +
      '  lmconn valkey cmd <COMMAND> [args...] [--host H] [--port P] [--mode resp|rest]\n'
    );
    return args.length === 0 ? 2 : 0;
  }

  const sub = args[0];
  let host = process.env.VALKEY_HOST || process.env.REDIS_HOST || '127.0.0.1';
  let port = undefined;
  let mode = 'resp';
  let timeout = 5000;
  const positional = [];

  for (let i = 1; i < args.length; i++) {
    const a = args[i];
    if (a === '--host') {
      if (i + 1 >= args.length) return emitFail('USAGE', 'Missing value for --host');
      host = args[++i];
    } else if (a === '--port') {
      if (i + 1 >= args.length) return emitFail('USAGE', 'Missing value for --port');
      port = parseInt(args[++i], 10);
    } else if (a === '--mode') {
      if (i + 1 >= args.length) return emitFail('USAGE', 'Missing value for --mode');
      mode = args[++i].toLowerCase();
      if (!['resp', 'rest'].includes(mode)) return emitFail('USAGE', 'Mode must be resp or rest');
    } else if (a === '--timeout') {
      if (i + 1 >= args.length) return emitFail('USAGE', 'Missing value for --timeout');
      timeout = parseInt(args[++i], 10);
    } else if (a.startsWith('--')) {
      return emitFail('USAGE', `Unknown option: ${a}`);
    } else {
      positional.push(a);
    }
  }

  if (port === undefined) {
    if (mode === 'rest') {
      port = parseInt(process.env.VALKEY_REST_PORT || '8080', 10);
    } else {
      port = parseInt(process.env.VALKEY_PORT || process.env.REDIS_PORT || '6379', 10);
    }
  }

  let cmdArgs = [];
  if (sub === 'ping') {
    cmdArgs = ['PING'];
  } else if (sub === 'get') {
    if (positional.length !== 1) return emitFail('USAGE', 'Usage: valkey get <key>');
    cmdArgs = ['GET', positional[0]];
  } else if (sub === 'set') {
    if (positional.length !== 2) return emitFail('USAGE', 'Usage: valkey set <key> <value>');
    cmdArgs = ['SET', positional[0], positional[1]];
  } else if (sub === 'del' || sub === 'delete') {
    if (positional.length !== 1) return emitFail('USAGE', 'Usage: valkey del <key>');
    cmdArgs = ['DEL', positional[0]];
  } else if (sub === 'cmd') {
    if (positional.length === 0) return emitFail('USAGE', 'Usage: valkey cmd <COMMAND> [args...]');
    cmdArgs = positional;
  } else {
    return emitFail('USAGE', `Unknown valkey subcommand: ${sub}`);
  }

  try {
    const result = mode === 'rest'
      ? await sendRest(host, port, cmdArgs, timeout)
      : await sendResp(host, port, cmdArgs, timeout);
    emit(ok({ mode, host, port, result }));
    return 0;
  } catch (err) {
    return emitFail(err.code || 'VALKEY_ERROR', err.message);
  }
}
