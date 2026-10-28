#!/usr/bin/env node
import { main } from '../src/main.js';

main(process.argv.slice(2)).then(
  (code) => { process.exitCode = code; },
  (err) => {
    process.stdout.write(JSON.stringify({ ok: false, error: { code: 'CRASH', message: String(err?.message || err) } }) + '\n');
    process.exitCode = 1;
  },
);
