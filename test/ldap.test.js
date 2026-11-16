import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import {
  run,
  sendLdap,
  sendRest,
  berInt,
  berEnum,
  berOctetString,
  berSeq,
  berSet,
  readBerNode,
  readBerChildren,
  decodeBerInt,
} from '../src/cmd-ldap.js';

function ldapResultOp(tag, code = 0, matchedDN = '', diag = '') {
  return berSeq([
    berEnum(code),
    berOctetString(matchedDN),
    berOctetString(diag),
  ], tag);
}

function searchEntryOp(dn, attributes) {
  const attrSeq = [];
  for (const [k, v] of Object.entries(attributes || {})) {
    const vals = Array.isArray(v) ? v : [v];
    attrSeq.push(berSeq([
      berOctetString(k),
      berSet(vals.map((item) => berOctetString(String(item)))),
    ]));
  }
  return berSeq([berOctetString(dn), berSeq(attrSeq)], 0x64);
}

function createMockLdapServer() {
  const store = new Map();
  store.set('dc=example,dc=com', { objectClass: ['top', 'dcObject', 'organization'], dc: 'example', o: 'Example' });

  const server = net.createServer((socket) => {
    let buf = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      while (buf.length > 0) {
        const msg = readBerNode(buf, 0);
        if (msg.needed) break;
        buf = buf.subarray(msg.next);
        const children = readBerChildren(msg.value);
        if (children.length < 2) continue;
        const msgId = decodeBerInt(children[0].value);
        const op = children[1];

        // UnbindRequest (0x42)
        if (op.tag === 0x42) {
          socket.end();
          return;
        }
        // BindRequest (0x60)
        if (op.tag === 0x60) {
          const bParts = readBerChildren(op.value);
          const bindDn = bParts.length > 1 ? bParts[1].value.toString('utf8') : '';
          const bindPw = bParts.length > 2 ? bParts[2].value.toString('utf8') : '';
          if (bindDn && bindPw === 'wrong') {
            socket.write(berSeq([berInt(msgId), ldapResultOp(0x61, 49, '', 'Invalid credentials')]));
          } else {
            socket.write(berSeq([berInt(msgId), ldapResultOp(0x61, 0)]));
          }
          continue;
        }
        // SearchRequest (0x63)
        if (op.tag === 0x63) {
          const sParts = readBerChildren(op.value);
          const baseDn = sParts[0].value.toString('utf8');
          const scope = decodeBerInt(sParts[1].value);
          if (baseDn === '' && scope === 0) {
            socket.write(berSeq([berInt(msgId), searchEntryOp('', { namingContexts: 'dc=example,dc=com', supportedLDAPVersion: '3' })]));
            socket.write(berSeq([berInt(msgId), ldapResultOp(0x65, 0)]));
            continue;
          }
          if (scope === 0) {
            const entry = store.get(baseDn);
            if (!entry) {
              socket.write(berSeq([berInt(msgId), ldapResultOp(0x65, 32, '', 'No such object')]));
            } else {
              socket.write(berSeq([berInt(msgId), searchEntryOp(baseDn, entry)]));
              socket.write(berSeq([berInt(msgId), ldapResultOp(0x65, 0)]));
            }
            continue;
          }
          for (const [dn, attrs] of store.entries()) {
            if (!baseDn || dn.endsWith(baseDn)) {
              socket.write(berSeq([berInt(msgId), searchEntryOp(dn, attrs)]));
            }
          }
          socket.write(berSeq([berInt(msgId), ldapResultOp(0x65, 0)]));
          continue;
        }
        // AddRequest (0x68)
        if (op.tag === 0x68) {
          const aParts = readBerChildren(op.value);
          const dn = aParts[0].value.toString('utf8');
          const attrs = {};
          for (const attrNode of readBerChildren(aParts[1].value)) {
            const kv = readBerChildren(attrNode.value);
            const name = kv[0].value.toString('utf8');
            const vals = readBerChildren(kv[1].value).map((v) => v.value.toString('utf8'));
            attrs[name] = vals.length === 1 ? vals[0] : vals;
          }
          store.set(dn, attrs);
          socket.write(berSeq([berInt(msgId), ldapResultOp(0x69, 0)]));
          continue;
        }
        // ModifyRequest (0x66)
        if (op.tag === 0x66) {
          const mParts = readBerChildren(op.value);
          const dn = mParts[0].value.toString('utf8');
          const entry = store.get(dn);
          if (!entry) {
            socket.write(berSeq([berInt(msgId), ldapResultOp(0x67, 32, '', 'No such object')]));
            continue;
          }
          for (const chg of readBerChildren(mParts[1].value)) {
            const chgParts = readBerChildren(chg.value);
            const modAttr = readBerChildren(chgParts[1].value);
            const name = modAttr[0].value.toString('utf8');
            const vals = readBerChildren(modAttr[1].value).map((v) => v.value.toString('utf8'));
            entry[name] = vals.length === 1 ? vals[0] : vals;
          }
          socket.write(berSeq([berInt(msgId), ldapResultOp(0x67, 0)]));
          continue;
        }
        // DelRequest (0x4a)
        if (op.tag === 0x4a) {
          const dn = op.value.toString('utf8');
          const existed = store.delete(dn);
          socket.write(berSeq([berInt(msgId), ldapResultOp(0x6b, existed ? 0 : 32)]));
        }
      }
    });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({
        port: server.address().port,
        close: () => new Promise((res) => {
          if (server.closeAllConnections) server.closeAllConnections();
          server.close(res);
        }),
      });
    });
  });
}

function createMockRestServer() {
  const store = new Map();
  store.set('dc=example,dc=com', { objectClass: ['top', 'dcObject', 'organization'], dc: 'example', o: 'Example' });

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      res.setHeader('Content-Type', 'application/json');
      if (req.method === 'GET' && url.pathname === '/ping') {
        res.end(JSON.stringify({ ok: true, result: 'PONG' }));
      } else if (req.method === 'POST' && url.pathname === '/bind') {
        const { dn, password } = JSON.parse(body || '{}');
        if (password === 'wrong') {
          res.statusCode = 401;
          res.end(JSON.stringify({ ok: false, error: 'Invalid credentials' }));
        } else {
          res.end(JSON.stringify({ ok: true, result: { bound: true, dn } }));
        }
      } else if (req.method === 'GET' && url.pathname === '/search') {
        const base = url.searchParams.get('base') || '';
        const list = [];
        for (const [dn, attributes] of store.entries()) {
          if (!base || dn.endsWith(base)) list.push({ dn, attributes });
        }
        res.end(JSON.stringify({ ok: true, result: list }));
      } else if (url.pathname.startsWith('/entry/')) {
        const dn = decodeURIComponent(url.pathname.slice(7));
        if (req.method === 'GET') {
          const attributes = store.get(dn);
          if (!attributes) {
            res.statusCode = 404;
            res.end(JSON.stringify({ ok: false, error: 'No such object' }));
          } else {
            res.end(JSON.stringify({ ok: true, result: { dn, attributes } }));
          }
        } else if (req.method === 'PUT') {
          store.set(dn, JSON.parse(body || '{}'));
          res.end(JSON.stringify({ ok: true, result: 'OK' }));
        } else if (req.method === 'POST') {
          const existing = store.get(dn) || {};
          Object.assign(existing, JSON.parse(body || '{}'));
          store.set(dn, existing);
          res.end(JSON.stringify({ ok: true, result: 'OK' }));
        } else if (req.method === 'DELETE') {
          const existed = store.delete(dn) ? 1 : 0;
          res.end(JSON.stringify({ ok: true, result: existed }));
        }
      } else {
        res.statusCode = 404;
        res.end(JSON.stringify({ ok: false, error: 'Not found' }));
      }
    });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({
        port: server.address().port,
        close: () => new Promise((res) => {
          if (server.closeAllConnections) server.closeAllConnections();
          server.close(res);
        }),
      });
    });
  });
}

test('ldap client via native LDAPv3 BER protocol', async () => {
  const mock = await createMockLdapServer();
  try {
    const ping = await sendLdap('127.0.0.1', mock.port, { op: 'ping' });
    assert.equal(ping, 'PONG');

    const bindRes = await sendLdap('127.0.0.1', mock.port, { op: 'bind', dn: 'cn=admin,dc=example,dc=com', password: 'secret' });
    assert.deepEqual(bindRes, { bound: true, dn: 'cn=admin,dc=example,dc=com' });

    const dn = 'cn=Alice,dc=example,dc=com';
    const addRes = await sendLdap('127.0.0.1', mock.port, {
      op: 'add',
      dn,
      attributes: { objectClass: ['inetOrgPerson', 'top'], cn: 'Alice', sn: 'Smith', mail: 'alice@example.com' },
      bindDn: 'cn=admin,dc=example,dc=com',
      bindPw: 'secret',
    });
    assert.equal(addRes, 'OK');

    const getRes = await sendLdap('127.0.0.1', mock.port, { op: 'get', dn });
    assert.equal(getRes.dn, dn);
    assert.equal(getRes.attributes.cn, 'Alice');
    assert.equal(getRes.attributes.mail, 'alice@example.com');

    const modRes = await sendLdap('127.0.0.1', mock.port, {
      op: 'modify',
      dn,
      changes: { mail: 'alice.smith@example.com' },
    });
    assert.equal(modRes, 'OK');

    const searchRes = await sendLdap('127.0.0.1', mock.port, { op: 'search', base: 'dc=example,dc=com', filter: '(cn=Alice)', scope: 'sub' });
    assert.equal(searchRes.length, 2);

    const delRes = await sendLdap('127.0.0.1', mock.port, { op: 'del', dn });
    assert.equal(delRes, 1);

    const getAfter = await sendLdap('127.0.0.1', mock.port, { op: 'get', dn });
    assert.equal(getAfter, null);
  } finally {
    await mock.close();
  }
});

test('ldap client via REST protocol', async () => {
  const mock = await createMockRestServer();
  try {
    const ping = await sendRest('127.0.0.1', mock.port, { op: 'ping' });
    assert.equal(ping, 'PONG');

    const dn = 'cn=Bob,dc=example,dc=com';
    const addRes = await sendRest('127.0.0.1', mock.port, {
      op: 'add',
      dn,
      attributes: { objectClass: 'person', cn: 'Bob', sn: 'Jones' },
    });
    assert.equal(addRes, 'OK');

    const getRes = await sendRest('127.0.0.1', mock.port, { op: 'get', dn });
    assert.equal(getRes.dn, dn);
    assert.equal(getRes.attributes.cn, 'Bob');

    const delRes = await sendRest('127.0.0.1', mock.port, { op: 'del', dn });
    assert.equal(delRes, 1);
  } finally {
    await mock.close();
  }
});

test('ldap CLI run() commands in both modes', async () => {
  const ldapMock = await createMockLdapServer();
  const restMock = await createMockRestServer();
  try {
    let captured = null;
    const origStdout = process.stdout.write;
    process.stdout.write = (str) => {
      try { captured = JSON.parse(str); } catch {}
      return true;
    };

    try {
      const exit0 = await run(['ping', '--port', String(ldapMock.port), '--mode', 'ldap']);
      assert.equal(exit0, 0);
      assert.equal(captured.ok, true);
      assert.equal(captured.result.result, 'PONG');
      assert.equal(captured.result.mode, 'ldap');

      const exit1 = await run(['ping', '--port', String(restMock.port), '--mode', 'rest']);
      assert.equal(exit1, 0);
      assert.equal(captured.ok, true);
      assert.equal(captured.result.result, 'PONG');
      assert.equal(captured.result.mode, 'rest');
    } finally {
      process.stdout.write = origStdout;
    }
  } finally {
    await ldapMock.close();
    await restMock.close();
  }
});
