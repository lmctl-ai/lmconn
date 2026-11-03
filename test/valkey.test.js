import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import { run, sendResp, sendRest, ops } from '../src/cmd-valkey.js';

function createMockRespServer() {
  const store = new Map();
  const server = net.createServer((socket) => {
    let buf = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      // Parse multibulk *<count>\r\n
      while (buf.length > 0) {
        if (buf[0] !== 42) break; // '*'
        const crlf = buf.indexOf('\r\n');
        if (crlf === -1) break;
        const count = parseInt(buf.toString('utf8', 1, crlf), 10);
        let curr = crlf + 2;
        const args = [];
        let complete = true;
        for (let i = 0; i < count; i++) {
          if (curr >= buf.length || buf[curr] !== 36) { complete = false; break; } // '$'
          const argCrlf = buf.indexOf('\r\n', curr);
          if (argCrlf === -1) { complete = false; break; }
          const len = parseInt(buf.toString('utf8', curr + 1, argCrlf), 10);
          const strStart = argCrlf + 2;
          const strEnd = strStart + len;
          if (buf.length < strEnd + 2) { complete = false; break; }
          args.push(buf.toString('utf8', strStart, strEnd));
          curr = strEnd + 2;
        }
        if (!complete) break;
        buf = buf.subarray(curr);

        // Process command
        const cmd = args[0].toUpperCase();
        if (cmd === 'PING') {
          socket.write('+PONG\r\n');
        } else if (cmd === 'SET') {
          store.set(args[1], args[2]);
          socket.write('+OK\r\n');
        } else if (cmd === 'GET') {
          const val = store.get(args[1]);
          if (val === undefined) socket.write('$-1\r\n');
          else socket.write(`$${Buffer.byteLength(val)}\r\n${val}\r\n`);
        } else if (cmd === 'DEL') {
          const existed = store.delete(args[1]) ? 1 : 0;
          socket.write(`:${existed}\r\n`);
        } else if (cmd === 'MGET') {
          let out = `*${args.length - 1}\r\n`;
          for (let i = 1; i < args.length; i++) {
            const v = store.get(args[i]);
            if (v === undefined) out += '$-1\r\n';
            else out += `$${Buffer.byteLength(v)}\r\n${v}\r\n`;
          }
          socket.write(out);
        } else {
          socket.write(`-ERR unknown command '${cmd}'\r\n`);
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
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      res.setHeader('Content-Type', 'application/json');
      if (req.method === 'GET' && url.pathname === '/ping') {
        res.end(JSON.stringify({ ok: true, result: 'PONG' }));
      } else if (req.method === 'GET' && url.pathname.startsWith('/get/')) {
        const key = decodeURIComponent(url.pathname.slice(5));
        const val = store.get(key) ?? null;
        res.end(JSON.stringify({ ok: true, result: val }));
      } else if (req.method === 'POST' && url.pathname.startsWith('/set/')) {
        const key = decodeURIComponent(url.pathname.slice(5));
        store.set(key, body);
        res.end(JSON.stringify({ ok: true, result: 'OK' }));
      } else if (req.method === 'DELETE' && url.pathname.startsWith('/keys/')) {
        const key = decodeURIComponent(url.pathname.slice(6));
        const existed = store.delete(key) ? 1 : 0;
        res.end(JSON.stringify({ ok: true, result: existed }));
      } else if (req.method === 'POST' && url.pathname === '/cmd') {
        const cmdArgs = JSON.parse(body);
        const cmd = cmdArgs[0].toUpperCase();
        if (cmd === 'PING') res.end(JSON.stringify({ ok: true, result: 'PONG' }));
        else if (cmd === 'MGET') {
          const results = cmdArgs.slice(1).map((k) => store.get(k) ?? null);
          res.end(JSON.stringify({ ok: true, result: results }));
        } else {
          res.end(JSON.stringify({ ok: false, error: `unknown command '${cmd}'` }));
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

test('valkey client via native RESP protocol', async () => {
  const mock = await createMockRespServer();
  try {
    const ping = await sendResp('127.0.0.1', mock.port, ['PING']);
    assert.equal(ping, 'PONG');

    const setRes = await sendResp('127.0.0.1', mock.port, ['SET', 'user:1', 'Alice']);
    assert.equal(setRes, 'OK');

    const getRes = await sendResp('127.0.0.1', mock.port, ['GET', 'user:1']);
    assert.equal(getRes, 'Alice');

    const delRes = await sendResp('127.0.0.1', mock.port, ['DEL', 'user:1']);
    assert.equal(delRes, 1);

    const getAfter = await sendResp('127.0.0.1', mock.port, ['GET', 'user:1']);
    assert.equal(getAfter, null);
  } finally {
    await mock.close();
  }
});

test('valkey client via REST protocol', async () => {
  const mock = await createMockRestServer();
  try {
    const ping = await sendRest('127.0.0.1', mock.port, ['PING']);
    assert.equal(ping, 'PONG');

    const setRes = await sendRest('127.0.0.1', mock.port, ['SET', 'msg', 'hello rest']);
    assert.equal(setRes, 'OK');

    const getRes = await sendRest('127.0.0.1', mock.port, ['GET', 'msg']);
    assert.equal(getRes, 'hello rest');

    const delRes = await sendRest('127.0.0.1', mock.port, ['DEL', 'msg']);
    assert.equal(delRes, 1);

    const getAfter = await sendRest('127.0.0.1', mock.port, ['GET', 'msg']);
    assert.equal(getAfter, null);
  } finally {
    await mock.close();
  }
});

test('valkey CLI run() commands in both modes', async () => {
  const respMock = await createMockRespServer();
  const restMock = await createMockRestServer();
  try {
    let captured = null;
    const origStdout = process.stdout.write;
    process.stdout.write = (str) => {
      try { captured = JSON.parse(str); } catch {}
      return true;
    };

    try {
      // RESP mode
      const exit0 = await run(['ping', '--port', String(respMock.port), '--mode', 'resp']);
      assert.equal(exit0, 0);
      assert.equal(captured.ok, true);
      assert.equal(captured.result.result, 'PONG');
      assert.equal(captured.result.mode, 'resp');

      // REST mode
      const exit1 = await run(['ping', '--port', String(restMock.port), '--mode', 'rest']);
      assert.equal(exit1, 0);
      assert.equal(captured.ok, true);
      assert.equal(captured.result.result, 'PONG');
      assert.equal(captured.result.mode, 'rest');
    } finally {
      process.stdout.write = origStdout;
    }
  } finally {
    await respMock.close();
    await restMock.close();
  }
});
