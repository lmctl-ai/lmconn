#!/usr/bin/env node
import { consumeEnvKey } from '../src/keystore.js';
import { main } from '../src/main.js';

// Capture LMCONN_KEY before any command (mcp, acp, ...) can spawn a child with the full environment.
consumeEnvKey();

// A consumer that closes the pipe early (head, jq -e) must not crash the CLI.
process.stdout.on('error', (err) => {
  if (err.code === 'EPIPE') process.exit(0);
  throw err;
});

main(process.argv.slice(2)).then(
  (code) => { process.exitCode = code; },
  (err) => {
    process.stdout.write(JSON.stringify({ ok: false, error: { code: 'CRASH', message: String(err?.message || err) } }) + '\n');
    process.exitCode = 1;
  },
);
