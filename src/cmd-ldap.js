// OpenLDAP / LDAPv3 client connector supporting both native LDAPv3 (ASN.1 BER over TCP,
// RFC 4511 / RFC 4515 / RFC 4516 / RFC 4532) and REST HTTP protocols. Zero external dependencies.
//
// Usage:
//   lmconn ldap ping [--host H] [--port P] [--url ldap://...] [--mode ldap|rest]
//   lmconn ldap bind --dn <DN> --password <PW> [--host H] [--port P] [--url ldap://...] [--mode ldap|rest]
//   lmconn ldap whoami [--bind-dn <DN>] [--bind-pw <PW>] [--host H] [--port P] [--url ldap://...] [--mode ldap|rest]
//   lmconn ldap search [<ldap://...>] [--base <DN>] [--filter <FILTER>] [--scope base|one|sub] [--attrs a,b] [--size-limit N] [--time-limit S] [--format json|ldif] [--host H] [--port P] [--url ldap://...] [--mode ldap|rest]
//   lmconn ldap get <DN|ldap://...> [--attrs a,b] [--format json|ldif] [--host H] [--port P] [--mode ldap|rest]
//   lmconn ldap add <DN> <JSON_ATTRS> [--host H] [--port P] [--mode ldap|rest] [--bind-dn DN] [--bind-pw PW]
//   lmconn ldap modify <DN> <JSON_MODS> [--host H] [--port P] [--mode ldap|rest] [--bind-dn DN] [--bind-pw PW]
//   lmconn ldap compare <DN> <ATTR> <VALUE> [--host H] [--port P] [--mode ldap|rest] [--bind-dn DN] [--bind-pw PW]
//   lmconn ldap del <DN> [--host H] [--port P] [--mode ldap|rest] [--bind-dn DN] [--bind-pw PW]

import net from 'node:net';
import { emit, ok, emitFail } from './result.js';

const COMMON_CONN_PARAMS = [
  { name: 'host', type: 'string', occurs: '?', default: '127.0.0.1', description: 'LDAP host' },
  { name: 'port', type: 'number', occurs: '?', description: 'LDAP port (default 389 for ldap, 8080 for rest)' },
  { name: 'url', type: 'string', occurs: '?', description: 'RFC 4516 ldap:// URL override' },
  { name: 'mode', type: 'string', occurs: '?', default: 'ldap', enum: ['ldap', 'rest'], description: 'Protocol mode: ldap or rest' },
  { name: 'timeout', type: 'number', occurs: '?', default: 5000, description: 'Timeout in milliseconds' },
];

export const ops = [
  { name: 'ldap ping', access: 'read', description: 'Ping LDAP server via native LDAPv3 RootDSE query or REST', params: [
    ...COMMON_CONN_PARAMS,
  ] },
  { name: 'ldap bind', access: 'read', description: 'Authenticate (Simple Bind) against LDAP server', params: [
    { name: 'dn', type: 'string', occurs: '1', description: 'Bind DN' },
    { name: 'password', type: 'string', occurs: '1', description: 'Bind password' },
    ...COMMON_CONN_PARAMS,
  ] },
  { name: 'ldap whoami', access: 'read', description: 'Return LDAP authorization identity (RFC 4532 Who Am I? extended operation)', params: [
    { name: 'bind-dn', type: 'string', occurs: '?', description: 'Optional Bind DN' },
    { name: 'bind-pw', type: 'string', occurs: '?', description: 'Optional Bind password' },
    ...COMMON_CONN_PARAMS,
  ] },
  { name: 'ldap search', access: 'read', description: 'Search LDAP entries by base DN, scope, RFC 4515 filter, and attribute projection', params: [
    { name: 'base', type: 'string', occurs: '?', default: '', description: 'Search base DN' },
    { name: 'filter', type: 'string', occurs: '?', default: '(objectClass=*)', description: 'Search filter' },
    { name: 'scope', type: 'string', occurs: '?', default: 'sub', enum: ['base', 'one', 'sub'], description: 'Search scope' },
    { name: 'attrs', type: 'string', occurs: '?', description: 'Comma-separated attribute list to return' },
    { name: 'size-limit', type: 'number', occurs: '?', default: 0, description: 'Maximum entries to return (0 = unlimited)' },
    { name: 'time-limit', type: 'number', occurs: '?', default: 0, description: 'Search time limit in seconds (0 = unlimited)' },
    { name: 'format', type: 'string', occurs: '?', default: 'json', enum: ['json', 'ldif'], description: 'Output format: json or ldif' },
    { name: 'bind-dn', type: 'string', occurs: '?', description: 'Optional Bind DN' },
    { name: 'bind-pw', type: 'string', occurs: '?', description: 'Optional Bind password' },
    ...COMMON_CONN_PARAMS,
  ] },
  { name: 'ldap get', access: 'read', description: 'Get a single LDAP entry by DN', params: [
    { name: 'dn', type: 'string', positional: true, occurs: '1', description: 'Distinguished Name (DN) or ldap:// URL' },
    { name: 'attrs', type: 'string', occurs: '?', description: 'Comma-separated attribute list to return' },
    { name: 'format', type: 'string', occurs: '?', default: 'json', enum: ['json', 'ldif'], description: 'Output format: json or ldif' },
    { name: 'bind-dn', type: 'string', occurs: '?', description: 'Optional Bind DN' },
    { name: 'bind-pw', type: 'string', occurs: '?', description: 'Optional Bind password' },
    ...COMMON_CONN_PARAMS,
  ] },
  { name: 'ldap add', access: 'write', description: 'Add a new LDAP entry with JSON attributes', params: [
    { name: 'dn', type: 'string', positional: true, occurs: '1', description: 'Distinguished Name (DN)' },
    { name: 'attributes', type: 'string', positional: true, occurs: '1', description: 'JSON object of attributes' },
    { name: 'bind-dn', type: 'string', occurs: '?', description: 'Bind DN' },
    { name: 'bind-pw', type: 'string', occurs: '?', description: 'Bind password' },
    ...COMMON_CONN_PARAMS,
  ] },
  { name: 'ldap modify', access: 'write', description: 'Modify attributes of an existing LDAP entry', params: [
    { name: 'dn', type: 'string', positional: true, occurs: '1', description: 'Distinguished Name (DN)' },
    { name: 'changes', type: 'string', positional: true, occurs: '1', description: 'JSON object of attribute modifications' },
    { name: 'bind-dn', type: 'string', occurs: '?', description: 'Bind DN' },
    { name: 'bind-pw', type: 'string', occurs: '?', description: 'Bind password' },
    ...COMMON_CONN_PARAMS,
  ] },
  { name: 'ldap compare', access: 'read', description: 'Compare an attribute value on an LDAP entry (RFC 4511 CompareRequest)', params: [
    { name: 'dn', type: 'string', positional: true, occurs: '1', description: 'Distinguished Name (DN)' },
    { name: 'attr', type: 'string', positional: true, occurs: '1', description: 'Attribute name' },
    { name: 'value', type: 'string', positional: true, occurs: '1', description: 'Assertion value' },
    { name: 'bind-dn', type: 'string', occurs: '?', description: 'Optional Bind DN' },
    { name: 'bind-pw', type: 'string', occurs: '?', description: 'Optional Bind password' },
    ...COMMON_CONN_PARAMS,
  ] },
  { name: 'ldap del', access: 'write', description: 'Delete an LDAP entry by DN', params: [
    { name: 'dn', type: 'string', positional: true, occurs: '1', description: 'Distinguished Name (DN)' },
    { name: 'bind-dn', type: 'string', occurs: '?', description: 'Bind DN' },
    { name: 'bind-pw', type: 'string', occurs: '?', description: 'Bind password' },
    ...COMMON_CONN_PARAMS,
  ] },
];

// ============================================================================
// RFC 4516 LDAP URL Parser & RFC 2849 LDIF Formatter
// ============================================================================

export function parseLdapUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || !/^ldaps?:\/\//i.test(rawUrl)) {
    throw Object.assign(new Error(`Invalid LDAP URL: ${rawUrl}`), { code: 'USAGE' });
  }
  const u = new URL(rawUrl);
  const host = u.hostname || '127.0.0.1';
  const port = u.port ? parseInt(u.port, 10) : (u.protocol.toLowerCase() === 'ldaps:' ? 636 : 389);
  const dn = u.pathname && u.pathname !== '/' ? decodeURIComponent(u.pathname.slice(1)) : '';
  let attrs = [];
  let scope = undefined;
  let filter = undefined;
  if (u.search && u.search.startsWith('?')) {
    const parts = u.search.slice(1).split('?');
    if (parts[0]) {
      attrs = parts[0].split(',').map((s) => decodeURIComponent(s.trim())).filter(Boolean);
    }
    if (parts[1]) {
      const sc = parts[1].toLowerCase();
      if (!['base', 'one', 'sub'].includes(sc)) {
        throw Object.assign(new Error(`Invalid LDAP URL scope: ${parts[1]}`), { code: 'USAGE' });
      }
      scope = sc;
    }
    if (parts[2]) {
      filter = decodeURIComponent(parts[2]);
    }
  }
  const bindDn = u.username ? decodeURIComponent(u.username) : undefined;
  const bindPw = u.password ? decodeURIComponent(u.password) : undefined;
  return { host, port, dn, attrs, scope, filter, bindDn, bindPw };
}

export function formatLdif(entriesOrEntry) {
  if (!entriesOrEntry) return '';
  const list = Array.isArray(entriesOrEntry) ? entriesOrEntry : [entriesOrEntry];
  const blocks = [];
  for (const item of list) {
    if (!item || typeof item !== 'object') continue;
    const lines = [`dn: ${item.dn || ''}`];
    for (const [k, v] of Object.entries(item.attributes || {})) {
      const vals = Array.isArray(v) ? v : [v];
      for (const val of vals) {
        lines.push(`${k}: ${val}`);
      }
    }
    blocks.push(lines.join('\n'));
  }
  return blocks.join('\n\n') + (blocks.length ? '\n' : '');
}

// ============================================================================
// ASN.1 BER Encoding / Decoding Helpers (RFC 4511 LDAPv3)
// ============================================================================

export function berLength(len) {
  if (len < 0x80) return Buffer.from([len]);
  const bytes = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export function berTlv(tag, valueBuf) {
  const buf = Buffer.isBuffer(valueBuf) ? valueBuf : Buffer.from(valueBuf || '');
  return Buffer.concat([Buffer.from([tag]), berLength(buf.length), buf]);
}

export function berInt(val, tag = 0x02) {
  let n = Number(val) | 0;
  const bytes = [];
  if (n === 0) {
    bytes.push(0);
  } else if (n > 0) {
    while (n > 0) {
      bytes.unshift(n & 0xff);
      n >>>= 8;
    }
    if (bytes[0] & 0x80) bytes.unshift(0x00);
  } else {
    let tmp = n;
    while (tmp < -1 || (tmp === -1 && bytes.length === 0)) {
      bytes.unshift(tmp & 0xff);
      tmp >>= 8;
    }
    if (!(bytes[0] & 0x80)) bytes.unshift(0xff);
  }
  return berTlv(tag, Buffer.from(bytes));
}

export function berEnum(val) {
  return berInt(val, 0x0a);
}

export function berBool(val) {
  return berTlv(0x01, Buffer.from([val ? 0xff : 0x00]));
}

export function berOctetString(str, tag = 0x04) {
  return berTlv(tag, Buffer.isBuffer(str) ? str : Buffer.from(String(str ?? ''), 'utf8'));
}

export function berSeq(items, tag = 0x30) {
  return berTlv(tag, Buffer.concat(items));
}

export function berSet(items, tag = 0x31) {
  return berTlv(tag, Buffer.concat(items));
}

export function readBerNode(buf, offset = 0) {
  if (offset + 2 > buf.length) return { needed: true };
  const tag = buf[offset];
  let lenByte = buf[offset + 1];
  let len = 0;
  let hdrLen = 2;
  if ((lenByte & 0x80) === 0) {
    len = lenByte;
  } else {
    const numOctets = lenByte & 0x7f;
    if (numOctets === 0 || numOctets > 4) {
      throw new Error(`Unsupported BER length octets: ${numOctets}`);
    }
    if (offset + 2 + numOctets > buf.length) return { needed: true };
    for (let i = 0; i < numOctets; i++) {
      len = (len * 256) + buf[offset + 2 + i];
    }
    hdrLen = 2 + numOctets;
  }
  if (offset + hdrLen + len > buf.length) return { needed: true };
  const value = buf.subarray(offset + hdrLen, offset + hdrLen + len);
  return {
    tag,
    headerLength: hdrLen,
    length: len,
    value,
    next: offset + hdrLen + len,
  };
}

export function readBerChildren(buf) {
  const out = [];
  let off = 0;
  while (off < buf.length) {
    const node = readBerNode(buf, off);
    if (node.needed) break;
    out.push(node);
    off = node.next;
  }
  return out;
}

export function decodeBerInt(buf) {
  if (!buf || buf.length === 0) return 0;
  let val = (buf[0] & 0x80) ? -1 : 0;
  for (let i = 0; i < buf.length; i++) {
    val = (val << 8) | buf[i];
  }
  return val;
}

function unescapeFilterValue(raw) {
  const bytes = [];
  for (let i = 0; i < raw.length; i++) {
    if (raw[i] === '\\' && i + 2 < raw.length && /^[0-9a-fA-F]{2}$/.test(raw.slice(i + 1, i + 3))) {
      bytes.push(parseInt(raw.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      const b = Buffer.from(raw[i], 'utf8');
      for (const byte of b) bytes.push(byte);
    }
  }
  return Buffer.from(bytes);
}

// Compile RFC 4515 filter string into LDAPv3 SearchRequest Filter BER
export function encodeLdapFilter(filterStr) {
  let s = (filterStr || '(objectClass=*)').trim();
  if (s.startsWith('(') && s.endsWith(')')) {
    let depth = 0;
    let wrapped = true;
    for (let i = 0; i < s.length - 1; i++) {
      if (s[i] === '(') depth++;
      else if (s[i] === ')') depth--;
      if (depth === 0) {
        wrapped = false;
        break;
      }
    }
    if (wrapped) s = s.slice(1, -1).trim();
  }

  if (s.startsWith('&') || s.startsWith('|')) {
    const tag = s[0] === '&' ? 0xa0 : 0xa1;
    const rest = s.slice(1).trim();
    const parts = splitFilterList(rest);
    return berSeq(parts.map(encodeLdapFilter), tag);
  }
  if (s.startsWith('!')) {
    const rest = s.slice(1).trim();
    return berTlv(0xa2, encodeLdapFilter(rest));
  }

  if (s.endsWith('=*') && !s.includes('>=') && !s.includes('<=') && !s.includes('~=')) {
    const attr = s.slice(0, -2).trim();
    return berOctetString(attr, 0x87); // present [7]
  }
  if (s.includes('>=')) {
    const idx = s.indexOf('>=');
    return berSeq([berOctetString(s.slice(0, idx).trim()), berOctetString(unescapeFilterValue(s.slice(idx + 2)))], 0xa5);
  }
  if (s.includes('<=')) {
    const idx = s.indexOf('<=');
    return berSeq([berOctetString(s.slice(0, idx).trim()), berOctetString(unescapeFilterValue(s.slice(idx + 2)))], 0xa6);
  }
  if (s.includes('~=')) {
    const idx = s.indexOf('~=');
    return berSeq([berOctetString(s.slice(0, idx).trim()), berOctetString(unescapeFilterValue(s.slice(idx + 2)))], 0xa8);
  }

  const eqIdx = s.indexOf('=');
  if (eqIdx === -1) {
    throw Object.assign(new Error(`Invalid LDAP search filter: (${s})`), { code: 'USAGE' });
  }
  const attr = s.slice(0, eqIdx).trim();
  const val = s.slice(eqIdx + 1);

  if (val.includes('*')) {
    const segs = val.split('*');
    const subItems = [];
    if (segs[0] !== '') {
      subItems.push(berOctetString(unescapeFilterValue(segs[0]), 0x80)); // initial [0]
    }
    for (let i = 1; i < segs.length - 1; i++) {
      if (segs[i] !== '') {
        subItems.push(berOctetString(unescapeFilterValue(segs[i]), 0x81)); // any [1]
      }
    }
    if (segs[segs.length - 1] !== '') {
      subItems.push(berOctetString(unescapeFilterValue(segs[segs.length - 1]), 0x82)); // final [2]
    }
    return berSeq([berOctetString(attr), berSeq(subItems)], 0xa4); // substrings [4]
  }

  return berSeq([berOctetString(attr), berOctetString(unescapeFilterValue(val))], 0xa3); // equalityMatch [3]
}

function splitFilterList(str) {
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
  return list;
}

// ============================================================================
// LDAPv3 Message Builders & Response Parsers
// ============================================================================

const WHOAMI_OID = '1.3.6.1.4.1.4203.1.11.3';

function buildBindRequest(msgId, dn = '', password = '') {
  const bindOp = berSeq([
    berInt(3),
    berOctetString(dn),
    berOctetString(password, 0x80),
  ], 0x60);
  return berSeq([berInt(msgId), bindOp]);
}

function buildUnbindRequest(msgId) {
  return berSeq([berInt(msgId), berTlv(0x42, Buffer.alloc(0))]);
}

function buildWhoamiRequest(msgId) {
  const extOp = berSeq([
    berOctetString(WHOAMI_OID, 0x80),
  ], 0x77);
  return berSeq([berInt(msgId), extOp]);
}

function buildSearchRequest(msgId, { base = '', scope = 'sub', filter = '(objectClass=*)', attributes = [], sizeLimit = 0, timeLimit = 0 }) {
  const scopeMap = { base: 0, one: 1, sub: 2 };
  const scopeVal = scopeMap[scope] ?? 2;
  const searchOp = berSeq([
    berOctetString(base),
    berEnum(scopeVal),
    berEnum(0), // derefAliases: neverDerefAliases (0)
    berInt(sizeLimit),
    berInt(timeLimit),
    berBool(false), // typesOnly: false
    encodeLdapFilter(filter),
    berSeq(attributes.map((a) => berOctetString(a))),
  ], 0x63);
  return berSeq([berInt(msgId), searchOp]);
}

function buildAddRequest(msgId, dn, attrsObj) {
  const attrList = [];
  for (const [k, v] of Object.entries(attrsObj || {})) {
    if (v === undefined || v === null) continue;
    const vals = Array.isArray(v) ? v : [v];
    attrList.push(berSeq([
      berOctetString(k),
      berSet(vals.map((item) => berOctetString(String(item)))),
    ]));
  }
  const addOp = berSeq([
    berOctetString(dn),
    berSeq(attrList),
  ], 0x68);
  return berSeq([berInt(msgId), addOp]);
}

function normalizeModifications(changesObj) {
  const mods = [];
  if (!changesObj || typeof changesObj !== 'object') return mods;
  const hasExplicitOps = ('add' in changesObj || 'replace' in changesObj || 'delete' in changesObj) &&
    Object.keys(changesObj).every((k) => ['add', 'replace', 'delete'].includes(k));
  if (hasExplicitOps) {
    if (changesObj.add && typeof changesObj.add === 'object') {
      for (const [k, v] of Object.entries(changesObj.add)) {
        const vals = Array.isArray(v) ? v.map(String) : [String(v)];
        mods.push({ op: 0, attr: k, vals });
      }
    }
    if (changesObj.replace && typeof changesObj.replace === 'object') {
      for (const [k, v] of Object.entries(changesObj.replace)) {
        const vals = v === null ? [] : (Array.isArray(v) ? v.map(String) : [String(v)]);
        mods.push({ op: 2, attr: k, vals });
      }
    }
    if (changesObj.delete) {
      if (Array.isArray(changesObj.delete)) {
        for (const k of changesObj.delete) mods.push({ op: 1, attr: String(k), vals: [] });
      } else if (typeof changesObj.delete === 'object') {
        for (const [k, v] of Object.entries(changesObj.delete)) {
          const vals = v === null || v === undefined ? [] : (Array.isArray(v) ? v.map(String) : [String(v)]);
          mods.push({ op: 1, attr: k, vals });
        }
      }
    }
    return mods;
  }
  for (const [k, v] of Object.entries(changesObj)) {
    if (v === null) {
      mods.push({ op: 1, attr: k, vals: [] });
    } else {
      const vals = Array.isArray(v) ? v.map(String) : [String(v)];
      mods.push({ op: 2, attr: k, vals });
    }
  }
  return mods;
}

function buildModifyRequest(msgId, dn, changesObj) {
  const mods = normalizeModifications(changesObj).map((m) => berSeq([
    berEnum(m.op),
    berSeq([
      berOctetString(m.attr),
      berSet(m.vals.map((val) => berOctetString(val))),
    ]),
  ]));
  const modOp = berSeq([
    berOctetString(dn),
    berSeq(mods),
  ], 0x66);
  return berSeq([berInt(msgId), modOp]);
}

function buildCompareRequest(msgId, dn, attr, value) {
  const cmpOp = berSeq([
    berOctetString(dn),
    berSeq([
      berOctetString(attr),
      berOctetString(value),
    ]),
  ], 0x6e);
  return berSeq([berInt(msgId), cmpOp]);
}

function buildDelRequest(msgId, dn) {
  return berSeq([berInt(msgId), berOctetString(dn, 0x4a)]);
}

function parseLdapResult(opValueBuf) {
  const children = readBerChildren(opValueBuf);
  const code = children.length > 0 ? decodeBerInt(children[0].value) : -1;
  const matchedDN = children.length > 1 ? children[1].value.toString('utf8') : '';
  const diagnosticMessage = children.length > 2 ? children[2].value.toString('utf8') : '';
  let extValue = '';
  for (let i = 3; i < children.length; i++) {
    if (children[i].tag === 0x8b) {
      extValue = children[i].value.toString('utf8');
    }
  }
  return { code, matchedDN, diagnosticMessage, extValue };
}

function parseSearchEntry(opValueBuf) {
  const children = readBerChildren(opValueBuf);
  const dn = children.length > 0 ? children[0].value.toString('utf8') : '';
  const attrs = {};
  if (children.length > 1) {
    const attrNodes = readBerChildren(children[1].value);
    for (const attrNode of attrNodes) {
      const kv = readBerChildren(attrNode.value);
      if (kv.length >= 2) {
        const type = kv[0].value.toString('utf8');
        const vals = readBerChildren(kv[1].value).map((v) => v.value.toString('utf8'));
        attrs[type] = vals.length === 1 ? vals[0] : vals;
      }
    }
  }
  return { dn, attributes: attrs };
}

function projectAttributes(entry, requestedAttrs) {
  if (!entry || !requestedAttrs || requestedAttrs.length === 0) return entry;
  const lowerMap = new Map();
  for (const [k, v] of Object.entries(entry.attributes || {})) {
    lowerMap.set(k.toLowerCase(), [k, v]);
  }
  const filtered = {};
  for (const reqAttr of requestedAttrs) {
    const match = lowerMap.get(reqAttr.toLowerCase());
    if (match) filtered[match[0]] = match[1];
  }
  return { dn: entry.dn, attributes: filtered };
}

// ============================================================================
// Native LDAPv3 Transport & REST Transport
// ============================================================================

export async function sendLdap(host, port, requestSpec, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    let buffer = Buffer.alloc(0);
    let resolved = false;
    const entries = [];
    let nextMsgId = 1;
    let stage = 'init';

    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        reject(Object.assign(new Error(`LDAP operation timed out after ${timeoutMs}ms`), { code: 'TIMEOUT' }));
      }
    }, timeoutMs);

    const finish = (err, data) => {
      if (resolved) return;
      resolved = true;
      clearTimeout(timer);
      try {
        socket.write(buildUnbindRequest(nextMsgId++));
      } catch {}
      socket.end();
      if (err) reject(err);
      else resolve(data);
    };

    const sendMainRequest = () => {
      const id = nextMsgId++;
      if (requestSpec.op === 'ping') {
        socket.write(buildSearchRequest(id, {
          base: '',
          scope: 'base',
          filter: '(objectClass=*)',
          attributes: ['namingContexts', 'supportedLDAPVersion'],
        }));
      } else if (requestSpec.op === 'bind') {
        socket.write(buildBindRequest(id, requestSpec.dn, requestSpec.password));
      } else if (requestSpec.op === 'whoami') {
        socket.write(buildWhoamiRequest(id));
      } else if (requestSpec.op === 'search') {
        socket.write(buildSearchRequest(id, {
          base: requestSpec.base || '',
          scope: requestSpec.scope || 'sub',
          filter: requestSpec.filter || '(objectClass=*)',
          attributes: requestSpec.attrs || [],
          sizeLimit: requestSpec.sizeLimit || 0,
          timeLimit: requestSpec.timeLimit || 0,
        }));
      } else if (requestSpec.op === 'get') {
        socket.write(buildSearchRequest(id, {
          base: requestSpec.dn,
          scope: 'base',
          filter: '(objectClass=*)',
          attributes: requestSpec.attrs || [],
        }));
      } else if (requestSpec.op === 'add') {
        socket.write(buildAddRequest(id, requestSpec.dn, requestSpec.attributes));
      } else if (requestSpec.op === 'modify') {
        socket.write(buildModifyRequest(id, requestSpec.dn, requestSpec.changes));
      } else if (requestSpec.op === 'compare') {
        socket.write(buildCompareRequest(id, requestSpec.dn, requestSpec.attr, requestSpec.value));
      } else if (requestSpec.op === 'del') {
        socket.write(buildDelRequest(id, requestSpec.dn));
      }
    };

    socket.on('connect', () => {
      if (requestSpec.op !== 'bind' && (requestSpec.bindDn || requestSpec.bindPw)) {
        stage = 'prebind';
        socket.write(buildBindRequest(nextMsgId++, requestSpec.bindDn || '', requestSpec.bindPw || ''));
      } else {
        stage = 'main';
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
            entries.push(projectAttributes(parseSearchEntry(protoOp.value), requestSpec.attrs));
            continue;
          }
          // SearchResultReference (0x73) -> ignore and wait for SearchResultDone
          if (protoOp.tag === 0x73) {
            continue;
          }

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
          if (requestSpec.op === 'whoami') {
            if (res.code !== 0) {
              return finish(Object.assign(new Error(`LDAP whoami failed (${res.code}): ${res.diagnosticMessage}`), { code: 'LDAP_ERROR' }));
            }
            const authzId = res.extValue || (requestSpec.bindDn ? `dn:${requestSpec.bindDn}` : 'anonymous');
            return finish(null, { authzId });
          }
          if (requestSpec.op === 'search') {
            // Code 4 is sizeLimitExceeded: still return collected entries
            if (res.code !== 0 && res.code !== 4) {
              return finish(Object.assign(new Error(`LDAP search failed (${res.code}): ${res.diagnosticMessage}`), { code: 'LDAP_ERROR' }));
            }
            const limited = requestSpec.sizeLimit > 0 ? entries.slice(0, requestSpec.sizeLimit) : entries;
            return finish(null, limited);
          }
          if (requestSpec.op === 'get') {
            if (res.code === 32) {
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
          if (requestSpec.op === 'compare') {
            // RFC 4511: compareTrue = 6, compareFalse = 5
            if (res.code === 6 || (res.code === 0 && res.diagnosticMessage === 'true')) {
              return finish(null, { match: true, dn: requestSpec.dn, attr: requestSpec.attr, value: requestSpec.value });
            }
            if (res.code === 5 || (res.code === 0 && res.diagnosticMessage === 'false')) {
              return finish(null, { match: false, dn: requestSpec.dn, attr: requestSpec.attr, value: requestSpec.value });
            }
            return finish(Object.assign(new Error(`LDAP compare failed (${res.code}): ${res.diagnosticMessage}`), { code: 'LDAP_ERROR' }));
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

  if (requestSpec.op === 'whoami') {
    if (requestSpec.bindDn) {
      await sendRest(host, port, { op: 'bind', dn: requestSpec.bindDn, password: requestSpec.bindPw || '' }, timeoutMs);
      return { authzId: `dn:${requestSpec.bindDn}` };
    }
    return { authzId: 'anonymous' };
  }

  if (requestSpec.op === 'compare') {
    const entry = await sendRest(host, port, { op: 'get', dn: requestSpec.dn }, timeoutMs);
    if (!entry) {
      throw Object.assign(new Error('No such object'), { code: 'LDAP_ERROR' });
    }
    const lowerAttr = requestSpec.attr.toLowerCase();
    let matched = false;
    for (const [k, v] of Object.entries(entry.attributes || {})) {
      if (k.toLowerCase() === lowerAttr) {
        const vals = Array.isArray(v) ? v : [v];
        matched = vals.some((item) => String(item).toLowerCase() === String(requestSpec.value).toLowerCase());
      }
    }
    return { match: matched, dn: requestSpec.dn, attr: requestSpec.attr, value: requestSpec.value };
  }

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
  let out = data ? data.result : null;
  if (requestSpec.op === 'get' && out && requestSpec.attrs?.length) {
    out = projectAttributes(out, requestSpec.attrs);
  } else if (requestSpec.op === 'search' && Array.isArray(out)) {
    if (requestSpec.attrs?.length) {
      out = out.map((e) => projectAttributes(e, requestSpec.attrs));
    }
    if (requestSpec.sizeLimit > 0) {
      out = out.slice(0, requestSpec.sizeLimit);
    }
  }
  return out;
}

export async function run(args) {
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    process.stderr.write(
      'Usage:\n' +
      '  lmconn ldap ping [--host H] [--port P] [--url ldap://...] [--mode ldap|rest]\n' +
      '  lmconn ldap bind --dn <DN> --password <PW> [--host H] [--port P] [--url ldap://...] [--mode ldap|rest]\n' +
      '  lmconn ldap whoami [--bind-dn DN] [--bind-pw PW] [--host H] [--port P] [--url ldap://...] [--mode ldap|rest]\n' +
      '  lmconn ldap search [<ldap://...>] [--base <DN>] [--filter <FILTER>] [--scope base|one|sub] [--attrs a,b] [--size-limit N] [--format json|ldif]\n' +
      '  lmconn ldap get <DN|ldap://...> [--attrs a,b] [--format json|ldif] [--host H] [--port P] [--mode ldap|rest]\n' +
      '  lmconn ldap add <DN> <JSON_ATTRS> [--host H] [--port P] [--mode ldap|rest] [--bind-dn DN] [--bind-pw PW]\n' +
      '  lmconn ldap modify <DN> <JSON_MODS> [--host H] [--port P] [--mode ldap|rest] [--bind-dn DN] [--bind-pw PW]\n' +
      '  lmconn ldap compare <DN> <ATTR> <VALUE> [--host H] [--port P] [--mode ldap|rest] [--bind-dn DN] [--bind-pw PW]\n' +
      '  lmconn ldap del <DN> [--host H] [--port P] [--mode ldap|rest] [--bind-dn DN] [--bind-pw PW]\n'
    );
    return args.length === 0 ? 2 : 0;
  }

  const sub = args[0];
  let host = process.env.LDAP_HOST || '127.0.0.1';
  let port = undefined;
  let urlOpt = '';
  let mode = 'ldap';
  let timeout = 5000;
  let base = process.env.LDAP_BASE_DN || '';
  let filter = '(objectClass=*)';
  let scope = 'sub';
  let attrs = [];
  let sizeLimit = 0;
  let timeLimit = 0;
  let format = 'json';
  let dnOpt = '';
  let pwOpt = '';
  let attrOpt = '';
  let valOpt = '';
  let bindDn = process.env.LDAP_BIND_DN || '';
  let bindPw = process.env.LDAP_BIND_PW || '';
  const positional = [];

  for (let i = 1; i < args.length; i++) {
    let a = args[i];
    let inlineVal;
    if (a.startsWith('--') && a.includes('=')) {
      const eq = a.indexOf('=');
      inlineVal = a.slice(eq + 1);
      a = a.slice(0, eq);
    }
    const nextVal = () => {
      if (inlineVal !== undefined) return inlineVal;
      if (i + 1 >= args.length) throw Object.assign(new Error(`Missing value for ${a}`), { code: 'USAGE' });
      return args[++i];
    };
    try {
      if (a === '--host') {
        host = nextVal();
      } else if (a === '--port') {
        port = parseInt(nextVal(), 10);
      } else if (a === '--url') {
        urlOpt = nextVal();
      } else if (a === '--mode') {
        mode = nextVal().toLowerCase();
        if (!['ldap', 'rest'].includes(mode)) return emitFail('USAGE', 'Mode must be ldap or rest');
      } else if (a === '--timeout') {
        timeout = parseInt(nextVal(), 10);
      } else if (a === '--base') {
        base = nextVal();
      } else if (a === '--filter') {
        filter = nextVal();
      } else if (a === '--scope') {
        scope = nextVal().toLowerCase();
        if (!['base', 'one', 'sub'].includes(scope)) return emitFail('USAGE', 'Scope must be base, one, or sub');
      } else if (a === '--attrs') {
        attrs = nextVal().split(',').map((s) => s.trim()).filter(Boolean);
      } else if (a === '--size-limit' || a === '--sizeLimit') {
        sizeLimit = parseInt(nextVal(), 10);
      } else if (a === '--time-limit' || a === '--timeLimit') {
        timeLimit = parseInt(nextVal(), 10);
      } else if (a === '--format') {
        format = nextVal().toLowerCase();
        if (!['json', 'ldif'].includes(format)) return emitFail('USAGE', 'Format must be json or ldif');
      } else if (a === '--dn') {
        dnOpt = nextVal();
      } else if (a === '--password') {
        pwOpt = nextVal();
      } else if (a === '--attr') {
        attrOpt = nextVal();
      } else if (a === '--value') {
        valOpt = nextVal();
      } else if (a === '--bind-dn' || a === '--bindDn') {
        bindDn = nextVal();
      } else if (a === '--bind-pw' || a === '--bindPw') {
        bindPw = nextVal();
      } else if (a === '--attributes' || a === '--changes') {
        positional.push(nextVal());
      } else if (a.startsWith('--')) {
        return emitFail('USAGE', `Unknown option: ${a}`);
      } else {
        positional.push(a);
      }
    } catch (e) {
      return emitFail(e.code || 'USAGE', e.message);
    }
  }

  // Apply RFC 4516 ldap:// URL if provided via --url or first positional argument
  const candidateUrl = urlOpt || (positional[0] && /^ldaps?:\/\//i.test(positional[0]) ? positional.shift() : '');
  if (candidateUrl) {
    try {
      const parsed = parseLdapUrl(candidateUrl);
      host = parsed.host;
      port = parsed.port;
      if (parsed.dn) {
        if (sub === 'search' && !base) base = parsed.dn;
        else if (!dnOpt && positional.length === 0) positional.unshift(parsed.dn);
      }
      if (parsed.attrs.length > 0 && attrs.length === 0) attrs = parsed.attrs;
      if (parsed.scope && scope === 'sub') scope = parsed.scope;
      if (parsed.filter && filter === '(objectClass=*)') filter = parsed.filter;
      if (parsed.bindDn && !bindDn) bindDn = parsed.bindDn;
      if (parsed.bindPw && !bindPw) bindPw = parsed.bindPw;
    } catch (e) {
      return emitFail(e.code || 'USAGE', e.message);
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
  } else if (sub === 'whoami') {
    spec = { op: 'whoami', bindDn: dnOpt || bindDn, bindPw: pwOpt || bindPw };
  } else if (sub === 'search') {
    spec = { op: 'search', base, filter, scope, attrs, sizeLimit, timeLimit, bindDn, bindPw };
  } else if (sub === 'get') {
    const targetDn = dnOpt || positional[0];
    if (!targetDn) return emitFail('USAGE', 'Usage: ldap get <DN>');
    spec = { op: 'get', dn: targetDn, attrs, bindDn, bindPw };
  } else if (sub === 'add') {
    const targetDn = dnOpt || positional[0];
    const rawAttrs = dnOpt ? positional[0] : positional[1];
    if (!targetDn || !rawAttrs) return emitFail('USAGE', 'Usage: ldap add <DN> <JSON_ATTRS>');
    let attributes;
    try {
      attributes = JSON.parse(rawAttrs);
    } catch (e) {
      return emitFail('USAGE', `Invalid JSON attributes: ${e.message}`);
    }
    spec = { op: 'add', dn: targetDn, attributes, bindDn, bindPw };
  } else if (sub === 'modify') {
    const targetDn = dnOpt || positional[0];
    const rawChanges = dnOpt ? positional[0] : positional[1];
    if (!targetDn || !rawChanges) return emitFail('USAGE', 'Usage: ldap modify <DN> <JSON_MODS>');
    let changes;
    try {
      changes = JSON.parse(rawChanges);
    } catch (e) {
      return emitFail('USAGE', `Invalid JSON changes: ${e.message}`);
    }
    spec = { op: 'modify', dn: targetDn, changes, bindDn, bindPw };
  } else if (sub === 'compare') {
    const targetDn = dnOpt || positional[0];
    const targetAttr = attrOpt || positional[1];
    const targetVal = valOpt || positional[2];
    if (!targetDn || !targetAttr || targetVal === undefined) {
      return emitFail('USAGE', 'Usage: ldap compare <DN> <ATTR> <VALUE>');
    }
    spec = { op: 'compare', dn: targetDn, attr: targetAttr, value: targetVal, bindDn, bindPw };
  } else if (sub === 'del' || sub === 'delete') {
    const targetDn = dnOpt || positional[0];
    if (!targetDn) return emitFail('USAGE', 'Usage: ldap del <DN>');
    spec = { op: 'del', dn: targetDn, bindDn, bindPw };
  } else {
    return emitFail('USAGE', `Unknown ldap subcommand: ${sub}`);
  }

  try {
    const result = mode === 'rest'
      ? await sendRest(host, port, spec, timeout)
      : await sendLdap(host, port, spec, timeout);
    const outPayload = { mode, host, port, result };
    if (format === 'ldif' && (sub === 'search' || sub === 'get')) {
      outPayload.ldif = formatLdif(result);
    }
    emit(ok(outPayload));
    return 0;
  } catch (err) {
    return emitFail(err.code || 'LDAP_ERROR', err.message);
  }
}
