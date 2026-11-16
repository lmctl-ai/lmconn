// End-to-end integration test for `lmconn ldap` against a live `lmldap` server.
// Skips cleanly when `lmldap` is not installed unless LMCONN_REQUIRE_LMLDAP=1 is set (as in CI).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const cli = fileURLToPath(new URL('../bin/lmconn.js', import.meta.url));

function findLmldapBin() {
  if (process.env.LMLDAP_BIN && fs.existsSync(process.env.LMLDAP_BIN)) {
    return process.env.LMLDAP_BIN;
  }
  const sibling = fileURLToPath(new URL('../../lmldap/lmldap', import.meta.url));
  if (fs.existsSync(sibling)) return sibling;
  const which = spawnSync(process.platform === 'win32' ? 'where' : 'which', ['lmldap'], { encoding: 'utf8' });
  if (which.status === 0 && which.stdout.trim()) return which.stdout.trim().split(/\r?\n/)[0];
  return null;
}

function runCli(args, env = {}) {
  const r = spawnSync(process.execPath, [cli, ...args], {
    env: { ...process.env, ...env },
    encoding: 'utf8',
  });
  let json = null;
  try { json = JSON.parse(r.stdout.trim()); } catch {}
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, json };
}

const lmldapBin = findLmldapBin();
const requireLmldap = process.env.LMCONN_REQUIRE_LMLDAP === '1';

test('lmconn ldap live integration against lmldap (LDAPv3 wire + REST + URL + compare + whoami + LDIF)', { skip: !lmldapBin && !requireLmldap ? 'lmldap binary not found' : false }, async () => {
  assert.ok(lmldapBin, 'LMLDAP_BIN required when LMCONN_REQUIRE_LMLDAP=1');
  const ldapPort = 24389 + Math.floor(Math.random() * 1000);
  const restPort = ldapPort + 1000;
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lmconn-lmldap-'));
  const adminDn = 'cn=admin,dc=example,dc=com';
  const adminPw = 'secret';

  const srv = spawn(lmldapBin, [
    '--port', String(ldapPort),
    '--rest-port', String(restPort),
    '--base-dn', 'dc=example,dc=com',
    '--admin-dn', adminDn,
    '--admin-pw', adminPw,
    '--data-dir', dataDir,
  ], { stdio: ['ignore', 'pipe', 'pipe'] });

  try {
    // Wait for lmldap to become ready
    let ready = false;
    for (let i = 0; i < 60; i++) {
      const p = runCli(['ldap', 'ping', '--port', String(ldapPort), '--mode', 'ldap']);
      if (p.status === 0 && p.json?.result?.result === 'PONG') {
        ready = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(ready, 'lmldap server failed to start within timeout');

    // 1. Ping in both modes
    let r = runCli(['ldap', 'ping', '--port', String(restPort), '--mode', 'rest']);
    assert.equal(r.status, 0);
    assert.equal(r.json.result.result, 'PONG');

    // 2. Bind & WhoAmI
    r = runCli(['ldap', 'bind', '--port', String(ldapPort), '--dn', adminDn, '--password', adminPw]);
    assert.equal(r.status, 0);
    assert.equal(r.json.result.result.bound, true);

    r = runCli(['ldap', 'whoami', '--port', String(ldapPort), '--bind-dn', adminDn, '--bind-pw', adminPw]);
    assert.equal(r.status, 0);
    assert.match(r.json.result.result.authzId, /cn=admin,dc=example,dc=com/i);

    // 3. Add entries via native LDAPv3 & REST
    const aliceDn = 'cn=Alice,dc=example,dc=com';
    r = runCli([
      'ldap', 'add', aliceDn,
      JSON.stringify({ objectClass: ['top', 'person', 'inetOrgPerson'], cn: 'Alice', sn: 'Wonderland', mail: 'alice@example.com' }),
      '--port', String(ldapPort), '--bind-dn', adminDn, '--bind-pw', adminPw,
    ]);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.equal(r.json.result.result, 'OK');

    // 4. Compare attribute value via native LDAPv3 CompareRequest
    r = runCli(['ldap', 'compare', aliceDn, 'sn', 'Wonderland', '--port', String(ldapPort)]);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.equal(r.json.result.result.match, true);

    r = runCli(['ldap', 'compare', aliceDn, 'sn', 'WrongName', '--port', String(ldapPort)]);
    assert.equal(r.status, 0);
    assert.equal(r.json.result.result.match, false);

    // 5. Search via RFC 4516 ldap:// URL with attribute projection & LDIF output
    r = runCli([
      'ldap', 'search',
      `ldap://127.0.0.1:${ldapPort}/dc=example,dc=com?cn,mail?sub?(cn=Alice)`,
      '--format', 'ldif',
    ]);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.equal(r.json.result.result.length, 1);
    assert.equal(r.json.result.result[0].attributes.mail, 'alice@example.com');
    assert.match(r.json.result.ldif, /mail: alice@example\.com/);

    // 6. Modify entry & verify via REST
    r = runCli([
      'ldap', 'modify', aliceDn,
      JSON.stringify({ replace: { mail: 'alice.new@example.com' } }),
      '--port', String(ldapPort), '--bind-dn', adminDn, '--bind-pw', adminPw,
    ]);
    assert.equal(r.status, 0);

    r = runCli(['ldap', 'get', aliceDn, '--port', String(restPort), '--mode', 'rest']);
    assert.equal(r.status, 0);
    assert.equal(r.json.result.result.attributes.mail, 'alice.new@example.com');

    // 7. Delete entry
    r = runCli(['ldap', 'del', aliceDn, '--port', String(ldapPort), '--bind-dn', adminDn, '--bind-pw', adminPw]);
    assert.equal(r.status, 0);
    assert.equal(r.json.result.result, 1);
  } finally {
    srv.kill('SIGTERM');
    await new Promise((res) => srv.once('exit', res));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});
