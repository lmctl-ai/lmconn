// Drive the real lmconn CLI over loopback through each vendor's contract suite.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
import {startMock} from '../scripts/lmmock.js';
const exec = promisify(execFile);
const cli = fileURLToPath(new URL('../bin/lmconn.js', import.meta.url));
const at = (value, path) => path.split('.').reduce((v, key) => v?.[key], value);
for (const service of ['slack','discord','telegram','jira','stripe','notion','airtable','hubspot','gitlab','asana','trello','pagerduty','datadog','linear','twilio','sendgrid','mailchimp']) {
 test(`${service}: real HTTP connector success, authentication and fault contracts`, async t => {
  const dir = mkdtempSync(join(tmpdir(), 'lmconn-service-'));
  t.after(() => rmSync(dir, {recursive:true, force:true}));
  const mock = await startMock(service);
  t.after(() => mock.close());
  const suite = JSON.parse(readFileSync(new URL(`./mocks/${service}-client.json`, import.meta.url)));
  const vars = {};
  function expand(value) {
   if (typeof value === 'string') return value.replace(/\$\{([^}]+)\}/g, (_, key) => {
    assert.ok(Object.hasOwn(vars, key), `missing capture ${key}`); return vars[key];
   });
   if (Array.isArray(value)) return value.map(expand);
   if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,expand(v)]));
   return value;
  }
  for (const raw of suite.steps) await t.test(raw.name, async () => {
   const step = expand(raw);
   const args = [cli,'http','request',mock.origin+step.path,'--method',step.method || 'GET'];
   for (const [key,value] of Object.entries(step.headers || {})) args.push('--header',`${key}: ${value}`);
   if (step.body !== undefined) args.push('--data',typeof step.body === 'string' ? step.body : JSON.stringify(step.body));
   const {stdout} = await exec(process.execPath,args,{env:{...process.env,LMCONN_DB:join(dir,'creds.db')},timeout:15000});
   const envelope = JSON.parse(stdout);
   assert.equal(envelope.ok,true);
   const result = envelope.result;
   assert.equal(result.status,step.status || 200);
   assert.equal(result.ok,result.status >= 200 && result.status < 300);
   if (step.contains) assert.ok((result.bodyText ?? JSON.stringify(result.bodyJson)).includes(step.contains));
   for (const [path,expected] of Object.entries(step.json || {})) assert.deepEqual(at(result.bodyJson,path),expected,path);
   for (const [key,path] of Object.entries(step.capture || {})) {
    vars[key] = at(result.bodyJson,path); assert.notEqual(vars[key],undefined,path);
   }
  });
 });
}
