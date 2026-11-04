import{test,after}from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import{join}from'node:path';import{tmpdir}from'node:os';import{spawnSync}from'node:child_process';import{createServer}from'node:http';import{openDb,closeDb,setCred,getCred}from'../src/creds.js';import{request,parseArgs}from'../src/cmd-http.js';
const dir=fs.mkdtempSync(join(tmpdir(),'cred-security-'));process.env.LMCONN_DB=join(dir,'main.db');after(()=>{closeDb();fs.rmSync(dir,{recursive:true,force:true});});
const access='CANARY_BROKER_ACCESS_&+/',refresh='CANARY_BROKER_REFRESH';const cli=new URL('../bin/lmconn.js',import.meta.url).pathname;
function invoke(args,input,env={}){const r=spawnSync(process.execPath,[cli,...args],{env:{...process.env,...env},input:typeof input==='object'?JSON.stringify(input):input,encoding:'utf8',maxBuffer:Infinity});assert.ifError(r.error);return{code:r.status,json:JSON.parse(r.stdout),out:r.stdout,err:r.stderr};}
const grant=(extra={})=>({kind:'oauth2',accessToken:access,refreshToken:refresh,scopes:['read'],owner:'review',source:'lmauth',...extra});const bound=(extra={})=>grant({issuer:'https://issuer.invalid',allowedOrigins:['https://api.invalid'],...extra});
test('legacy import clears stale issuer/client/API-key config instead of sending fresh grants there',()=>{
 for(const[field,value]of [['oauth_token_url','https://old.invalid/token'],['oauth_client_id','old'],['oauth_client_secret','OLD_SECRET'],['api_key','OLD_KEY']])setCred('replace',field,value);
 const r=invoke(['cred','oauth-store','replace','--stdin'],grant());assert.equal(r.code,0);for(const field of ['oauth_token_url','oauth_client_id','oauth_client_secret','api_key'])assert.equal(getCred('replace',field),null);
});
test('broker store binds issuer/origins, never reveals, and cannot be downgraded through legacy writes',{skip:process.platform==='win32'},async()=>{
 const r=invoke(['cred','store','broker','--stdin'],bound());assert.equal(r.code,0,r.out);assert.equal(r.json.result.handle,'broker');assert.ok(!r.out.includes(access));
 for(const args of [['cred','get','broker','oauth_access_token','--reveal'],['cred','set','broker','oauth_token_url','--stdin'],['cred','oauth-store','broker','--stdin']]){const x=invoke(args,args.includes('oauth-store')?grant():'https://evil.invalid/token');assert.equal(x.code,1);assert.equal(x.json.error.code,'CREDENTIAL_POLICY');assert.ok(!x.out.includes(access));}
 assert.equal(invoke(['cred','store','broker','--stdin'],bound({issuer:'https://other.invalid'})).code,1);assert.equal(invoke(['cred','store','broker','--stdin'],bound({allowedOrigins:['https://other.invalid']})).code,1);assert.equal(getCred('broker','oauth_access_token'),access);
 let requests=0;await assert.rejects(request(parseArgs(['request','https://other.invalid','--auth','broker']),async()=>{requests++;return Response.json({})}),/origin|binding|policy/i);assert.equal(requests,0);
 const response=await request(parseArgs(['request','https://api.invalid/resource','--auth','broker']),async(u,o)=>{assert.equal(o.headers.get('authorization'),'Bearer '+access);return new Response(JSON.stringify({echo:Buffer.from(access).toString('base64')}),{headers:{'content-type':access}});});assert.equal(response.bodyOmitted,true);assert.ok(!JSON.stringify(response).includes(access)&&!JSON.stringify(response).includes(Buffer.from(access).toString('base64')));
});
test('PAT broker path is nonexportable and broker mode refuses legacy stores/reveal',{skip:process.platform==='win32'},()=>{
 const env={LMCONN_STORE_MODE:'broker'};assert.equal(invoke(['cred','store','pat','--stdin'],bound({kind:'bearer',refreshToken:undefined}),env).code,0);assert.equal(invoke(['cred','get','pat','api_key','--reveal'],undefined,env).code,1);assert.equal(invoke(['cred','set','unprotected','api_key','--stdin'],access,env).code,1);assert.equal(invoke(['cred','oauth-store','unprotected','--stdin'],grant(),env).code,1);
 assert.equal(invoke(['cred','set','legacy','api_key','--stdin'],access).code,0);assert.equal(invoke(['cred','get','legacy','api_key','--reveal']).json.result.value,access);assert.equal(invoke(['cred','get','legacy','api_key','--reveal'],undefined,env).code,1);
});
test('Windows broker path fails closed before creating a store',{skip:process.platform!=='win32'},()=>{const db=join(dir,'windows','db');const r=invoke(['cred','store','win','--stdin'],bound(),{LMCONN_DB:db,LMCONN_STORE_MODE:'broker'});assert.equal(r.code,1);assert.equal(r.json.error.code,'STORE_SECURITY');assert.equal(fs.existsSync(db),false);});
test('legacy auth pins first origin and cross-origin redirect strips auth even with an injected transport',async()=>{
 setCred('first-use','api_key',access);const seen=[];
 const r=await request(parseArgs(['request','https://one.invalid','--auth','first-use']),async(u,o)=>{seen.push({url:u,mode:o.redirect,auth:o.headers.get('authorization')});if(seen.length===1)return new Response(null,{status:302,headers:{location:'https://two.invalid/end'}});return Response.json({ok:true});});
 assert.equal(r.status,200);assert.equal(seen.length,2);assert.ok(seen.every(x=>x.mode==='manual'));assert.equal(seen[0].auth,'Bearer '+access);assert.equal(seen[1].auth,null);
 await assert.rejects(request(parseArgs(['request','https://two.invalid','--auth','first-use']),async()=>{throw Error('must not call')}),/origin|binding|policy/i);
});
test('store repairs owned loose directory modes and rejects DB and sidecar symlinks',{skip:process.platform==='win32'},()=>{
 const loose=join(dir,'loose');fs.mkdirSync(loose,{mode:0o777});fs.chmodSync(loose,0o777);const db=join(loose,'db');openDb(db);assert.equal(fs.statSync(loose).mode&0o777,0o700);assert.equal(fs.statSync(db).mode&0o777,0o600);closeDb(db);
 for(const suffix of ['','-journal','-wal','-shm']){const folder=fs.mkdtempSync(join(dir,'symlink-')),file=join(folder,'db'),target=join(folder,'victim');fs.writeFileSync(target,'untouched',{mode:0o600});fs.symlinkSync(target,file+suffix);assert.throws(()=>openDb(file),/store|symlink|regular|security/i);assert.equal(fs.readFileSync(target,'utf8'),'untouched');}
});
test('SQL failure after several writes and crash mid-write cannot expose mixed bundles',()=>{
 const db=openDb();setCred('atomic','oauth_access_token','OLD');setCred('atomic','oauth_refresh_token','OLD_REFRESH');setCred('atomic','oauth_owner','old');db.function('fault',()=>{throw Error('CANARY_ERROR')});db.exec("CREATE TEMP TRIGGER fail_late AFTER UPDATE ON creds WHEN NEW.service='atomic' AND NEW.field='oauth_owner' BEGIN SELECT fault(); END");
 // CLI subprocess cannot see the TEMP trigger; use a persistent trigger + process-local function in a separate controlled child.
 db.exec('DROP TRIGGER fail_late');const program=`import {openDb,setCred,getCred} from ${JSON.stringify(new URL('../src/creds.js',import.meta.url).href)};import {run} from ${JSON.stringify(new URL('../src/cmd-cred.js',import.meta.url).href)};const db=openDb();db.function('fault',()=>{if(process.argv[1]==='crash')process.exit(71);throw Error('CANARY_ERROR')});db.exec("CREATE TEMP TRIGGER fail_late AFTER UPDATE ON creds WHEN NEW.service='atomic' AND NEW.field='oauth_owner' BEGIN SELECT fault(); END");process.stdin.push(${JSON.stringify(JSON.stringify(grant()))});process.stdin.push(null);process.exitCode=await run(['oauth-store','atomic','--stdin']);`;
 for(const mode of ['fault','crash']){const r=spawnSync(process.execPath,['--input-type=module','-e',program,mode],{env:process.env,encoding:'utf8',maxBuffer:Infinity});assert.equal(r.status,mode==='crash'?71:1);assert.equal(getCred('atomic','oauth_access_token'),'OLD');assert.equal(getCred('atomic','oauth_refresh_token'),'OLD_REFRESH');assert.ok(!r.stdout.includes('CANARY_ERROR'));}
});

test('protected keys cannot escape through generic GitHub/LLM adapters',{skip:process.platform==='win32'},async t=>{
 const {main}=await import('../src/main.js');for(const service of ['github','deepseek'])assert.equal(invoke(['cred','store',service,'--stdin'],bound({kind:'bearer',refreshToken:undefined})).code,0);
 let calls=0;t.mock.method(globalThis,'fetch',async()=>{calls++;return Response.json({login:access,choices:[{message:{content:access}}]})});
 const w=process.stdout.write;let out='';process.stdout.write=function(x,...rest){if(typeof x!=='string')return w.call(this,x,...rest);out+=x;return true;};
 try{for(const args of [['github','user'],['llm','chat','deepseek','--prompt','hello'],['llm','probe','deepseek']]){out='';assert.equal(await main(args),1);assert.equal(JSON.parse(out).error.code,'CREDENTIAL_POLICY');assert.ok(!out.includes(access));}assert.equal(calls,0);}finally{process.stdout.write=w;}
});

test('protected refresh configuration is explicit, mismatch-refused, and nonexportability persists without broker env',{skip:process.platform==='win32'},async()=>{
 const config={tokenUrl:'https://token.invalid/rotate',clientId:'verified-client',clientSecret:'CLIENT_CANARY',authStyle:'body'};
 assert.equal(invoke(['cred','store','rotate','--stdin'],bound({refresh:config,expiresAt:'2000-01-01'})).code,0);
 assert.equal(invoke(['cred','store','rotate','--stdin'],bound({refresh:{...config,tokenUrl:'https://other.invalid/token'}})).code,1);
 let calls=0;const result=await request(parseArgs(['request','https://api.invalid/use','--auth','rotate']),async(u,o)=>{calls++;if(calls===1){assert.equal(u,'https://token.invalid/rotate');assert.equal(new URLSearchParams(o.body).get('refresh_token'),refresh);return Response.json({access_token:'ROTATED_SAFE',scope:'read'});}assert.equal(o.headers.get('authorization'),'Bearer ROTATED_SAFE');return Response.json({})});assert.equal(calls,2);assert.equal(result.bodyOmitted,true);assert.equal(invoke(['cred','get','rotate','oauth_access_token','--reveal']).code,1);
 const simulated=`Object.defineProperty(process,'platform',{value:'win32'});const{openDb}=await import(${JSON.stringify(new URL('../src/creds.js',import.meta.url).href)});try{openDb();process.exitCode=7}catch(e){if(e.code!=='STORE_SECURITY')throw e}`;
 const win=spawnSync(process.execPath,['--input-type=module','-e',simulated],{env:process.env,encoding:'utf8'});assert.equal(win.status,0,win.stderr);
});

test('secure deletion clears live SQLite freelist fragments and sidecars remain private',{skip:process.platform==='win32'},()=>{
 const file=join(dir,'delete.db'),db=openDb(file),marker='DELETION_CANARY_';setCred('remove','oauth_access_token',marker.repeat(2000),db);db.prepare('DELETE FROM creds WHERE service=?').run('remove');closeDb(file);assert.ok(!fs.readFileSync(file).includes(Buffer.from(marker)));
 const db2=openDb(file);db2.exec('PRAGMA journal_mode=WAL');setCred('wal','oauth_access_token',access,db2);for(const suffix of ['-wal','-shm'])assert.equal(fs.statSync(file+suffix).mode&0o777,0o600);closeDb(file);
});

test('legacy HTTP redacts known encoded echoes while protected HTTP never exposes response strings',async()=>{
 setCred('legacy-echo','api_key',access);const encoded=Buffer.from(access).toString('base64'),percent=encodeURIComponent(access);
 const r=await request(parseArgs(['request','https://echo.invalid','--auth','legacy-echo']),async()=>Response.json({raw:access,encoded,percent}));
 assert.ok(!JSON.stringify(r).includes(access)&&!JSON.stringify(r).includes(encoded)&&!JSON.stringify(r).includes(percent));
});
