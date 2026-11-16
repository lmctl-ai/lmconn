// OpenLDAP / LDAPv3 client connector supporting both native LDAPv3 (ASN.1 BER over TCP)
// and REST HTTP protocols. Zero external dependencies.
//
// Usage:
//   lmconn ldap ping [--host H] [--port P] [--mode ldap|rest]
//   lmconn ldap bind --dn <DN> --password <PW> [--host H] [--port P] [--mode ldap|rest]
//   lmconn ldap search [--base <DN>] [--filter <FILTER>] [--scope base|one|sub] [--host H] [--port P] [--mode ldap|rest]
//   lmconn ldap get <DN> [--host H] [--port P] [--mode ldap|rest]
//   lmconn ldap add <DN> <JSON_ATTRS> [--host H] [--port P] [--mode ldap|rest] [--bind-dn DN] [--bind-pw PW]
//   lmconn ldap modify <DN> <JSON_MODS> [--host H] [--port P] [--mode ldap|rest] [--bind-dn DN] [--bind-pw PW]
//   lmconn ldap del <DN> [--host H] [--port P] [--mode ldap|rest] [--bind-dn DN] [--bind-pw PW]

import net from 'node:net';
import { emit, ok, emitFail } from './result.js';

export const ops = [
  { name: 'ldap ping', access: 'read', description: 'Ping LDAP server via native LDAPv3 RootDSE query or REST', params: [
    { name: 'host', type: 'string', occurs: '?', default: '127.0.0.1', description: 'LDAP host' },
    { name: 'port', type: 'number', occurs: '?', description: 'LDAP port (default 389 for ldap, 8080 for rest)' },
    { name: 'mode', type: 'string', occurs: '?', default: 'ldap', enum: ['ldap', 'rest'], description: 'Protocol mode: ldap or rest' },
    { name: 'timeout', type: 'number', occurs: '?', default: 5000, description: 'Timeout in milliseconds' },
  ] },
  { name: 'ldap bind', access: 'read', description: 'Authenticate (Simple Bind) against LDAP server', params: [
    { name: 'dn', type: 'string', occurs: '1', description: 'Bind DN' },
    { name: 'password', type: 'string', occurs: '1', description: 'Bind password' },
    { name: 'host', type: 'string', occurs: '?', default: '127.0.0.1', description: 'LDAP host' },
    { name: 'port', type: 'number', occurs: '?', description: 'LDAP port' },
    { name: 'mode', type: 'string', occurs: '?', default: 'ldap', enum: ['ldap', 'rest'], description: 'Protocol mode: ldap or rest' },
    { name: 'timeout', type: 'number', occurs: '?', default: 5000, description: 'Timeout in milliseconds' },
  ] },
  { name: 'ldap search', access: 'read', description: 'Search LDAP entries by base DN, scope, and RFC 4515 filter', params: [
    { name: 'base', type: 'string', occurs: '?', default: '', description: 'Search base DN' },
    { name: 'filter', type: 'string', occurs: '?', default: '(objectClass=*)', description: 'Search filter' },
    { name: 'scope', type: 'string', occurs: '?', default: 'sub', enum: ['base', 'one', 'sub'], description: 'Search scope' },
    { name: 'bind-dn', type: 'string', occurs: '?', description: 'Optional Bind DN' },
    { name: 'bind-pw', type: 'string', occurs: '?', description: 'Optional Bind password' },
    { name: 'host', type: 'string', occurs: '?', default: '127.0.0.1', description: 'LDAP host' },
    { name: 'port', type: 'number', occurs: '?', description: 'LDAP port' },
    { name: 'mode', type: 'string', occurs: '?', default: 'ldap', enum: ['ldap', 'rest'], description: 'Protocol mode: ldap or rest' },
    { name: 'timeout', type: 'number', occurs: '?', default: 5000, description: 'Timeout in milliseconds' },
  ] },
  { name: 'ldap get', access: 'read', description: 'Get a single LDAP entry by DN', params: [
    { name: 'dn', type: 'string', occurs: '1', positional: true, description: 'Distinguished Name (DN)' },
    { name: 'bind-dn', type: 'string', occurs: '?', description: 'Optional Bind DN' },
    { name: 'bind-pw', type: 'string', occurs: '?', description: 'Optional Bind password' },
    { name: 'host', type: 'string', occurs: '?', default: '127.0.0.1', description: 'LDAP host' },
    { name: 'port', type: 'number', occurs: '?', description: 'LDAP port' },
    { name: 'mode', type: 'string', occurs: '?', default: 'ldap', enum: ['ldap', 'rest'], description: 'Protocol mode: ldap or rest' },
    { name: 'timeout', type: 'number', occurs: '?', default: 5000, description: 'Timeout in milliseconds' },
  ] },
  { name: 'ldap add', access: 'write', description: 'Add an LDAP entry with JSON attributes', params: [
    { name: 'dn', type: 'string', occurs: '1', positional: true, description: 'Distinguished Name (DN)' },
    { name: 'attributes', type: 'string', occurs: '1', positional: true, description: 'JSON object of attributes' },
    { name: 'bind-dn', type: 'string', occurs: '?', description: 'Optional Bind DN' },
    { name: 'bind-pw', type: 'string', occurs: '?', description: 'Optional Bind password' },
    { name: 'host', type: 'string', occurs: '?', default: '127.0.0.1', description: 'LDAP host' },
    { name: 'port', type: 'number', occurs: '?', description: 'LDAP port' },
    { name: 'mode', type: 'string', occurs: '?', default: 'ldap', enum: ['ldap', 'rest'], description: 'Protocol mode: ldap or rest' },
    { name: 'timeout', type: 'number', occurs: '?', default: 5000, description: 'Timeout in milliseconds' },
  ] },
  { name: 'ldap modify', access: 'write', description: 'Modify an LDAP entry with JSON attributes', params: [
    { name: 'dn', type: 'string', occurs: '1', positional: true, description: 'Distinguished Name (DN)' },
    { name: 'changes', type: 'string', occurs: '1', positional: true, description: 'JSON object of attribute replacements' },
    { name: 'bind-dn', type: 'string', occurs: '?', description: 'Optional Bind DN' },
    { name: 'bind-pw', type: 'string', occurs: '?', description: 'Optional Bind password' },
    { name: 'host', type: 'string', occurs: '?', default: '127.0.0.1', description: 'LDAP host' },
    { name: 'port', type: 'number', occurs: '?', description: 'LDAP port' },
    { name: 'mode', type: 'string', occurs: '?', default: 'ldap', enum: ['ldap', 'rest'], description: 'Protocol mode: ldap or rest' },
    { name: 'timeout', type: 'number', occurs: '?', default: 5000, description: 'Timeout in milliseconds' },
  ] },
  { name: 'ldap del', access: 'write', description: 'Delete an LDAP entry by DN', params: [
    { name: 'dn', type: 'string', occurs: '1', positional: true, description: 'Distinguished Name (DN)' },
    { name: 'bind-dn', type: 'string', occurs: '?', description: 'Optional Bind DN' },
    { name: 'bind-pw', type: 'string', occurs: '?', description: 'Optional Bind password' },
    { name: 'host', type: 'string', occurs: '?', default: '127.0.0.1', description: 'LDAP host' },
    { name: 'port', type: 'number', occurs: '?', description: 'LDAP port' },
    { name: 'mode', type: 'string', occurs: '?', default: 'ldap', enum: ['ldap', 'rest'], description: 'Protocol mode: ldap or rest' },
    { name: 'timeout', type: 'number', occurs: '?', default: 5000, description: 'Timeout in milliseconds' },
  ] },
];

// ---- ASN.1 BER helpers for RFC 4511 LDAPv3 ----

export function berLength(len) {
  if (len < 128) return Buffer.from([len]);
  const bytes = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export function berTag(tag, content) {
  const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
  return Buffer.concat([Buffer.from([tag]), berLength(buf.length), buf]);
}

export function berInt(val, tag = 0x02) {
  let v = Number(val);
  if (v === 0) return berTag(tag, Buffer.from([0]));
  const bytes = [];
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  if (bytes[0] & 0x80) bytes.unshift(0);
  return berTag(tag, Buffer.from(bytes));
}

export function berEnum(val) {
  return berInt(val, 0x0a);
}

export function berBool(val) {
  return berTag(0x01, Buffer.from([val ? 0xff : 0x00]));
}

export function berOctetString(str, tag = 0x04) {
  return berTag(tag, Buffer.from(String(str ?? ''), 'utf8'));
}

export function berSeq(items, tag = 0x30) {
  return berTag(tag, Buffer.concat(items));
}

export function berSet(items) {
  return berTag(0x31, Buffer.concat(items));
}

export function readBerNode(buf, offset = 0) {
  if (offset >= buf.length) return { needed: true };
  const tag = buf[offset];
  if (offset + 1 >= buf.length) return { needed: true };
  let lenByte = buf[offset + 1];
  let len = 0;
  let hdrLen = 2;
  if ((lenByte & 0x80) === 0) {
    len = lenByte;
  } else {
    const numBytes = lenByte & 0x7f;
    if (offset + 2 + numBytes > buf.length) return { needed: true };
    for (let i = 0; i < numBytes; i++) {
      len = (len * 256) + buf[offset + 2 + i];
    }
    hdrLen = 2 + numBytes;
  }
  const start = offset + hdrLen;
  const end = start + len;
  if (end > buf.length) return { needed: true };
  return {
    tag,
    start,
    end,
    value: buf.subarray(start, end),
    next: end,
  };
}

export function readBerChildren(buf) {
  const children = [];
  let off = 0;
  while (off < buf.length) {
    const node = readBerNode(buf, off);
    if (node.needed) break;
    children.push(node);
    off = node.next;
  }
  return children;
}

export function decodeBerInt(valueBuf) {
  if (!valueBuf || valueBuf.length === 0) return 0;
  let n = 0;
  for (let i = 0; i < valueBuf.length; i++) {
    n = (n * 256) + valueBuf[i];
  }
  return n;
}

// Compile RFC 4515 string filter into BER Filter CHOICE
export function encodeFilter(filterStr) {
  let f = String(filterStr || '(objectClass=*)').trim();
  if (f.startsWith('(') && f.endsWith(')')) {
    f = f.slice(1, -1).trim();
  }
  if (!f) f = 'objectClass=*';

  if (f.startsWith('&') || f.startsWith('|')) {
    const tag = f[0] === '&' ? 0xa0 : 0xa1;
    const sub = parseFilterList(f.slice(1).trim());
    return berSeq(sub.map(encodeFilter), tag);
  }
  if (f.startsWith('!')) {
    const inner = f.slice(1).trim();
    return berTag(0xa2, encodeFilter(inner));
  }

  const eqIdx = f.indexOf('=');
  if (eqIdx === -1) {
    return berOctetString(f, 0x87);
  }
  const attr = f.slice(0, eqIdx).trim();
  const rawVal = f.slice(eqIdx + 1);
  if (rawVal === '*') {
    return berOctetString(attr, 0x87); // present [7]
  }
  if (rawVal.includes('*')) {
    const parts = rawVal.split('*');
    const subItems = [];
    for (let i = 0; i < parts.length; i++) {
      if (parts[i] === '') continue;
      if (i === 0) subItems.push(berOctetString(parts[i], 0x80)); // initial [0]
      else if (i === parts.length - 1) subItems.push(berOctetString(parts[i], 0x82)); // final [2]
      else subItems.push(berOctetString(parts[i], 0x81)); // any [1]
    }
    return berSeq([berOctetString(attr), berSeq(subItems)], 0xa4); // substrings [4]
  }
  return berSeq([berOctetString(attr), berOctetString(rawVal)], 0xa3); // equalityMatch [3]
}

function parseFilterList(str) {
  const list = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < str.length; i++) {
    if (str[i] === '(') {
      if (depth === 0) start = i;
      depth++;
    } else if (str[i] === ')') {
      depth--;
      if (depth === 0 && start !== -1) {
        list.push(str.slice(start, i + 1));
        start = -1;
      }
    }
  }
  return list.length > 0 ? list : [str];
}

export function buildBindRequest(msgId, dn = '', password = '') {
  const bindOp = berSeq([
    berInt(3),
    berOctetString(dn),
    berOctetString(password, 0x80),
  ], 0x60);
  return berSeq([berInt(msgId), bindOp]);
}

export function buildUnbindRequest(msgId) {
  return berSeq([berInt(msgId), berTag(0x42, Buffer.alloc(0))]);
}

export function buildSearchRequest(msgId, baseDn = '', scope = 'sub', filter = '(objectClass=*)', attrs = []) {
  const scopeVal = scope === 'base' ? 0 : scope === 'one' ? 1 : 2;
  const searchOp = berSeq([
    berOctetString(baseDn),
    berEnum(scopeVal),
    berEnum(0), // neverDerefAliases
    berInt(0),  // sizeLimit
    berInt(0),  // timeLimit
    berBool(false), // typesOnly
    encodeFilter(filter),
    berSeq(attrs.map((a) => berOctetString(a))),
  ], 0x63);
  return berSeq([berInt(msgId), searchOp]);
}

export function buildAddRequest(msgId, dn, attrsObj) {
  const attrList = [];
  for (const [k, v] of Object.entries(attrsObj || {})) {
    if (k.toLowerCase() === 'dn') continue;
    const vals = Array.isArray(v) ? v : [v];
    attrList.push(berSeq([
      berOctetString(k),
      berSet(vals.map((item) => berOctetString(String(item)))),
    ]));
  }
  const addOp = berSeq([berOctetString(dn), berSeq(attrList)], 0x68);
  return berSeq([berInt(msgId), addOp]);
}

export function buildModifyRequest(msgId, dn, modsObj) {
  const changes = [];
  for (const [k, v] of Object.entries(modsObj || {})) {
    if (k.toLowerCase() === 'dn') continue;
    const vals = Array.isArray(v) ? v : (v === null ? [] : [v]);
    const opEnum = vals.length === 0 ? 1 : 2; // 1 = delete, 2 = replace
    changes.push(berSeq([
      berEnum(opEnum),
      berSeq([
        berOctetString(k),
        berSet(vals.map((item) => berOctetString(String(item)))),
      ]),
    ]));
  }
  const modOp = berSeq([berOctetString(dn), berSeq(changes)], 0x66);
  return berSeq([berInt(msgId), modOp]);
}

export function buildDelRequest(msgId, dn) {
  return berSeq([berInt(msgId), berOctetString(dn, 0x4a)]);
}

function parseLdapResult(opValue) {
  const fields = readBerChildren(opValue);
  const code = fields.length > 0 ? decodeBerInt(fields[0].value) : 0;
  const matchedDN = fields.length > 1 ? fields[1].value.toString('utf8') : '';
  const diagnosticMessage = fields.length > 2 ? fields[2].value.toString('utf8') : '';
  return { code, matchedDN, diagnosticMessage };
}

function parseSearchEntry(opValue) {
  const fields = readBerChildren(opValue);
  const dn = fields.length > 0 ? fields[0].value.toString('utf8') : '';
  const attributes = {};
  if (fields.length > 1) {
    const attrSeq = readBerChildren(fields[1].value);
    for (const attrNode of attrSeq) {
      const parts = readBerChildren(attrNode.value);
      if (parts.length >= 2) {
        const name = parts[0].value.toString('utf8');
        const vals = readBerChildren(parts[1].value).map((v) => v.value.toString('utf8'));
        attributes[name] = vals.length === 1 ? vals[0] : vals;
      }
    }
  }
  return { dn, attributes };
}

export async function sendLdap(host, port, requestSpec, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    let buffer = Buffer.alloc(0);
    let resolved = false;
    let msgId = 1;
    const entries = [];
    const bindDn = requestSpec.bindDn || '';
    const bindPw = requestSpec.bindPw || '';
    const needPreBind = Boolean(bindDn) && requestSpec.op !== 'bind';
    let stage = needPreBind ? 'prebind' : 'main';

    const timer = setTimeout(() => {
      socket.destroy();
      reject(Object.assign(new Error(`LDAP connection timed out after ${timeoutMs}ms`), { code: 'TIMEOUT' }));
    }, timeoutMs);

    const finish = (err, val) => {
      if (resolved) return;
      resolved = true;
      clearTimeout(timer);
      try {
        socket.write(buildUnbindRequest(++msgId));
      } catch {}
      socket.end();
      if (err) reject(err);
      else resolve(val);
    };

    const sendMainRequest = () => {
      const id = ++msgId;
      switch (requestSpec.op) {
        case 'ping':
          socket.write(buildSearchRequest(id, '', 'base', '(objectClass=*)', ['namingContexts', 'supportedLDAPVersion']));
          break;
        case 'bind':
          socket.write(buildBindRequest(id, requestSpec.dn, requestSpec.password));
          break;
        case 'search':
          socket.write(buildSearchRequest(id, requestSpec.base || '', requestSpec.scope || 'sub', requestSpec.filter || '(objectClass=*)', requestSpec.attrs || []));
          break;
        case 'get':
          socket.write(buildSearchRequest(id, requestSpec.dn, 'base', '(objectClass=*)', []));
          break;
        case 'add':
          socket.write(buildAddRequest(id, requestSpec.dn, requestSpec.attributes));
          break;
        case 'modify':
          socket.write(buildModifyRequest(id, requestSpec.dn, requestSpec.changes));
          break;
        case 'del':
          socket.write(buildDelRequest(id, requestSpec.dn));
          break;
        default:
          finish(Object.assign(new Error(`Unknown LDAP operation: ${requestSpec.op}`), { code: 'USAGE' }));
      }
    };

    socket.on('connect', () => {
      if (stage === 'prebind') {
        socket.write(buildBindRequest(msgId, bindDn, bindPw));
      } else {
        sendMainRequest();
      }
    });

    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      try {
        while (buffer.length > 0) {
          const msg = readBerNode(buffer, 0);
          if (msg.needed) break;
          buffer = buffer.subarray(msg.next);
          const children = readBerChildren(msg.value);
          if (children.length < 2) continue;
          const protoOp = children[1];

          if (stage === 'prebind') {
            const res = parseLdapResult(protoOp.value);
            if (res.code !== 0) {
              return finish(Object.assign(new Error(`LDAP bind failed (${res.code}): ${res.diagnosticMessage || 'Invalid credentials'}`), { code: 'LDAP_AUTH_ERROR' }));
            }
            stage = 'main';
            sendMainRequest();
            continue;
          }

          // SearchResultEntry (0x64)
          if (protoOp.tag === 0x64) {
            entries.push(parseSearchEntry(protoOp.value));
            continue;
          }
          // SearchResultReference (0x73) -> ignore and wait for SearchResultDone
          if (protoOp.tag === 0x73) {
            continue;
          }

          // BindResponse (0x61), SearchResultDone (0x65), ModifyResponse (0x67), AddResponse (0x69), DelResponse (0x6b)
          const res = parseLdapResult(protoOp.value);
          if (requestSpec.op === 'ping') {
            if (res.code !== 0) {
              return finish(Object.assign(new Error(`LDAP ping failed (${res.code}): ${res.diagnosticMessage}`), { code: 'LDAP_ERROR' }));
            }
            return finish(null, 'PONG');
          }
          if (requestSpec.op === 'bind') {
            if (res.code !== 0) {
              return finish(Object.assign(new Error(`LDAP bind failed (${res.code}): ${res.diagnosticMessage || 'Invalid credentials'}`), { code: 'LDAP_AUTH_ERROR' }));
            }
            return finish(null, { bound: true, dn: requestSpec.dn });
          }
          if (requestSpec.op === 'search') {
            if (res.code !== 0) {
              return finish(Object.assign(new Error(`LDAP search failed (${res.code}): ${res.diagnosticMessage}`), { code: 'LDAP_ERROR' }));
            }
            return finish(null, entries);
          }
          if (requestSpec.op === 'get') {
            if (res.code === 32) { // noSuchObject
              return finish(null, null);
            }
            if (res.code !== 0) {
              return finish(Object.assign(new Error(`LDAP get failed (${res.code}): ${res.diagnosticMessage}`), { code: 'LDAP_ERROR' }));
            }
            return finish(null, entries.length > 0 ? entries[0] : null);
          }
          if (requestSpec.op === 'add' || requestSpec.op === 'modify') {
            if (res.code !== 0) {
              return finish(Object.assign(new Error(`LDAP ${requestSpec.op} failed (${res.code}): ${res.diagnosticMessage}`), { code: 'LDAP_ERROR' }));
            }
            return finish(null, 'OK');
          }
          if (requestSpec.op === 'del') {
            if (res.code === 32) return finish(null, 0);
            if (res.code !== 0) {
              return finish(Object.assign(new Error(`LDAP delete failed (${res.code}): ${res.diagnosticMessage}`), { code: 'LDAP_ERROR' }));
            }
            return finish(null, 1);
          }
        }
      } catch (err) {
        finish(err);
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
        reject(Object.assign(new Error('Connection closed before LDAP response received'), { code: 'NETWORK' }));
      }
    });
  });
}

export async function sendRest(host, port, requestSpec, timeoutMs = 5000) {
  let url;
  const init = { signal: AbortSignal.timeout(timeoutMs) };

  switch (requestSpec.op) {
    case 'ping':
      url = `http://${host}:${port}/ping`;
      break;
    case 'bind':
      url = `http://${host}:${port}/bind`;
      init.method = 'POST';
      init.headers = { 'Content-Type': 'application/json' };
      init.body = JSON.stringify({ dn: requestSpec.dn, password: requestSpec.password });
      break;
    case 'search': {
      const params = new URLSearchParams();
      if (requestSpec.base) params.set('base', requestSpec.base);
      if (requestSpec.filter) params.set('filter', requestSpec.filter);
      if (requestSpec.scope) params.set('scope', requestSpec.scope);
      url = `http://${host}:${port}/search?${params.toString()}`;
      break;
    }
    case 'get':
      url = `http://${host}:${port}/entry/${encodeURIComponent(requestSpec.dn)}`;
      break;
    case 'add':
      url = `http://${host}:${port}/entry/${encodeURIComponent(requestSpec.dn)}`;
      init.method = 'PUT';
      init.headers = { 'Content-Type': 'application/json' };
      init.body = JSON.stringify(requestSpec.attributes);
      break;
    case 'modify':
      url = `http://${host}:${port}/entry/${encodeURIComponent(requestSpec.dn)}`;
      init.method = 'POST';
      init.headers = { 'Content-Type': 'application/json' };
      init.body = JSON.stringify(requestSpec.changes);
      break;
    case 'del':
      url = `http://${host}:${port}/entry/${encodeURIComponent(requestSpec.dn)}`;
      init.method = 'DELETE';
      break;
    default:
      throw Object.assign(new Error(`Unknown LDAP operation: ${requestSpec.op}`), { code: 'USAGE' });
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
    if (requestSpec.op === 'get' && res.status === 404) return null;
    const code = res.status === 401 ? 'LDAP_AUTH_ERROR' : 'LDAP_ERROR';
    throw Object.assign(new Error(data.error || 'LDAP REST error'), { code });
  }
  return data ? data.result : null;
}

export async function run(args) {
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    process.stderr.write(
      'Usage:\n' +
      '  lmconn ldap ping [--host H] [--port P] [--mode ldap|rest]\n' +
      '  lmconn ldap bind --dn <DN> --password <PW> [--host H] [--port P] [--mode ldap|rest]\n' +
      '  lmconn ldap search [--base <DN>] [--filter <FILTER>] [--scope base|one|sub] [--host H] [--port P] [--mode ldap|rest]\n' +
      '  lmconn ldap get <DN> [--host H] [--port P] [--mode ldap|rest]\n' +
      '  lmconn ldap add <DN> <JSON_ATTRS> [--host H] [--port P] [--mode ldap|rest] [--bind-dn DN] [--bind-pw PW]\n' +
      '  lmconn ldap modify <DN> <JSON_MODS> [--host H] [--port P] [--mode ldap|rest] [--bind-dn DN] [--bind-pw PW]\n' +
      '  lmconn ldap del <DN> [--host H] [--port P] [--mode ldap|rest] [--bind-dn DN] [--bind-pw PW]\n'
    );
    return args.length === 0 ? 2 : 0;
  }

  const sub = args[0];
  let host = process.env.LDAP_HOST || '127.0.0.1';
  let port = undefined;
  let mode = 'ldap';
  let timeout = 5000;
  let base = process.env.LDAP_BASE_DN || '';
  let filter = '(objectClass=*)';
  let scope = 'sub';
  let dnOpt = '';
  let pwOpt = '';
  let bindDn = process.env.LDAP_BIND_DN || '';
  let bindPw = process.env.LDAP_BIND_PW || '';
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
      if (!['ldap', 'rest'].includes(mode)) return emitFail('USAGE', 'Mode must be ldap or rest');
    } else if (a === '--timeout') {
      if (i + 1 >= args.length) return emitFail('USAGE', 'Missing value for --timeout');
      timeout = parseInt(args[++i], 10);
    } else if (a === '--base') {
      if (i + 1 >= args.length) return emitFail('USAGE', 'Missing value for --base');
      base = args[++i];
    } else if (a === '--filter') {
      if (i + 1 >= args.length) return emitFail('USAGE', 'Missing value for --filter');
      filter = args[++i];
    } else if (a === '--scope') {
      if (i + 1 >= args.length) return emitFail('USAGE', 'Missing value for --scope');
      scope = args[++i].toLowerCase();
      if (!['base', 'one', 'sub'].includes(scope)) return emitFail('USAGE', 'Scope must be base, one, or sub');
    } else if (a === '--dn') {
      if (i + 1 >= args.length) return emitFail('USAGE', 'Missing value for --dn');
      dnOpt = args[++i];
    } else if (a === '--password') {
      if (i + 1 >= args.length) return emitFail('USAGE', 'Missing value for --password');
      pwOpt = args[++i];
    } else if (a === '--bind-dn') {
      if (i + 1 >= args.length) return emitFail('USAGE', 'Missing value for --bind-dn');
      bindDn = args[++i];
    } else if (a === '--bind-pw') {
      if (i + 1 >= args.length) return emitFail('USAGE', 'Missing value for --bind-pw');
      bindPw = args[++i];
    } else if (a.startsWith('--')) {
      return emitFail('USAGE', `Unknown option: ${a}`);
    } else {
      positional.push(a);
    }
  }

  if (port === undefined) {
    if (mode === 'rest') {
      port = parseInt(process.env.LDAP_REST_PORT || '8080', 10);
    } else {
      port = parseInt(process.env.LDAP_PORT || '389', 10);
    }
  }

  let spec;
  if (sub === 'ping') {
    spec = { op: 'ping', bindDn, bindPw };
  } else if (sub === 'bind') {
    const targetDn = dnOpt || positional[0] || bindDn;
    const targetPw = pwOpt || positional[1] || bindPw;
    if (!targetDn) return emitFail('USAGE', 'Usage: ldap bind --dn <DN> --password <PW>');
    spec = { op: 'bind', dn: targetDn, password: targetPw };
  } else if (sub === 'search') {
    spec = { op: 'search', base, filter, scope, bindDn, bindPw };
  } else if (sub === 'get') {
    if (positional.length !== 1) return emitFail('USAGE', 'Usage: ldap get <DN>');
    spec = { op: 'get', dn: positional[0], bindDn, bindPw };
  } else if (sub === 'add') {
    if (positional.length !== 2) return emitFail('USAGE', 'Usage: ldap add <DN> <JSON_ATTRS>');
    let attributes;
    try {
      attributes = JSON.parse(positional[1]);
    } catch (e) {
      return emitFail('USAGE', `Invalid JSON attributes: ${e.message}`);
    }
    spec = { op: 'add', dn: positional[0], attributes, bindDn, bindPw };
  } else if (sub === 'modify') {
    if (positional.length !== 2) return emitFail('USAGE', 'Usage: ldap modify <DN> <JSON_MODS>');
    let changes;
    try {
      changes = JSON.parse(positional[1]);
    } catch (e) {
      return emitFail('USAGE', `Invalid JSON changes: ${e.message}`);
    }
    spec = { op: 'modify', dn: positional[0], changes, bindDn, bindPw };
  } else if (sub === 'del' || sub === 'delete') {
    if (positional.length !== 1) return emitFail('USAGE', 'Usage: ldap del <DN>');
    spec = { op: 'del', dn: positional[0], bindDn, bindPw };
  } else {
    return emitFail('USAGE', `Unknown ldap subcommand: ${sub}`);
  }

  try {
    const result = mode === 'rest'
      ? await sendRest(host, port, spec, timeout)
      : await sendLdap(host, port, spec, timeout);
    emit(ok({ mode, host, port, result }));
    return 0;
  } catch (err) {
    return emitFail(err.code || 'LDAP_ERROR', err.message);
  }
}
