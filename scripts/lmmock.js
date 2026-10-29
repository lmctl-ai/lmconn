import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, renameSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
export async function startMock(name, config = {}, port = 0) {
  const dir = mkdtempSync(join(tmpdir(), 'lmconn-lmmock-'));
  const ready = join(dir, 'ready.json'), settings = join(dir, 'config.json'), logFile = join(dir, 'audit.jsonl');
  writeFileSync(logFile, '', {mode:0o600});
  let savedLog = [];
  let current = {...config, logFile};
  const configure = patch => {
    current = {...current, ...patch};
    writeFileSync(settings + '.tmp', JSON.stringify(current), {mode:0o600});
    renameSync(settings + '.tmp', settings);
  };
  configure({});
  const server = spawn(process.env.LMMOCK_BIN || 'lmmock', ['exec', '--script', fileURLToPath(new URL(`../test/mocks/${name}.lms`, import.meta.url)), '--config', settings, '--listen', `127.0.0.1:${port}`, '--ready-file', ready, '--', process.execPath, fileURLToPath(new URL('./lmmock-keepalive.mjs', import.meta.url))], {stdio:['pipe','ignore','pipe']});
  let failure;
  server.on('error', error => {failure = error;});
  // Compiler/host diagnostics are held locally; never print fixture credentials.
  server.stderr.resume();
  let exited = false;
  const finished = new Promise(resolve => server.once('close', code => {exited = true;resolve(code);}));
  try {
    for (let i=0;i<400&&!existsSync(ready);i++) {
      if (failure) throw failure;
      if (exited) throw new Error(`lmmock ${name} failed to start; check the fixture with lmscript`);
      await wait(25);
    }
    if (!existsSync(ready)) throw new Error('lmmock startup timeout');
    const {url:origin} = JSON.parse(readFileSync(ready,'utf8'));
    return {origin, configure,
      get log() {return existsSync(logFile) ? readFileSync(logFile,'utf8').split('\n').filter(Boolean).map(JSON.parse) : savedLog;},
      async inspect() {return (await fetch(origin+'/__inspect')).json();},
      async close() {
        savedLog = readFileSync(logFile,'utf8').split('\n').filter(Boolean).map(JSON.parse);
        server.stdin.end();
        const timer = setTimeout(()=>{if(!exited)server.kill();},5000);
        try {await finished;} finally {clearTimeout(timer);rmSync(dir,{recursive:true,force:true});}
      },
    };
  } catch(error) {server.kill();await finished;rmSync(dir,{recursive:true,force:true});throw error;}
}
