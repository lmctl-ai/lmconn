#!/usr/bin/env node
import { main } from '../src/main.js';

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
