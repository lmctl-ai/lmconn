import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {PassThrough} from 'node:stream';
import {run} from '../src/cmd-oauth.js';
import {closeDb,getCred,setCred} from '../src/creds.js';
const dir=mkdtempSync(join(tmpdir(),'oauth-security-'));process.env.LMCONN_DB=join(dir,'db');
after(()=>{closeDb();rmSync(dir,{recursive:true,force:true});});
const access='CANARY_ACCESS_&+/',refresh='CANARY_REFRESH_&+/';
const nativeFetch=globalThis.fetch;
async function capture(fn){const w=process.stdout.write,e=process.stderr.write;let out='',err='';process.stdout.write=function(x,...rest){if(typeof x!=='string')return w.call(this,x,...rest);out+=x;return true;};process.stderr.write=function(x,...rest){if(typeof x!=='string')return e.call(this,x,...rest);err+=x;return true;};try{return {code:await fn(),get out(){return out},get err(){return err},get json(){return JSON.parse(out)}};}finally{process.stdout.write=w;process.stderr.write=e;}}
const args=s=>['device',s,'--client-id','public','--device-url','http://127.0.0.1/device','--token-url','http://127.0.0.1/token','--scope','read'];
const grant={device_code:'DEVICE',user_code:'HUMAN',verification_uri:'https://example.invalid/verify',expires_in:60,interval:1};
function clock(){let now=1000,id=0;const timers=new Map();return{now:()=>now,setTimer:(f,ms)=>{timers.set(++id,{f,at:now+ms});return id;},clearTimer:i=>timers.delete(i),advance(ms){now+=ms;for(const[i,t]of [...timers])if(t.at<=now){timers.delete(i);t.f();}},get count(){return timers.size}};}
async function device(t,name,replies,g=grant,extra={}){const c=clock(),waits=[];let n=0;t.mock.restoreAll();t.mock.method(globalThis,'fetch',async(u,o)=>++n===1?Response.json(g):replies(n,o,c));const r=await capture(()=>run(args(name),{...c,wait:async ms=>{waits.push(ms);c.advance(ms);},...extra}));return{r,c,waits,calls:n};}

test('device healthy control, pending, slow_down +5 and denial/expiry mappings are enforced',async t=>{
 let x=await device(t,'healthy',n=>Response.json(n===2?{error:'authorization_pending'}:n===3?{error:'slow_down'}:{access_token:access,refresh_token:refresh,scope:'read'}));assert.equal(x.r.code,0);assert.deepEqual(x.waits,[1000,1000,6000]);assert.equal(x.c.count,0);
 for(const[provider,code]of [['access_denied','DENIED'],['expired_token','RECONNECT'],['garbage','OAUTH_ERROR']]){x=await device(t,provider,()=>Response.json({error:provider,error_description:access}));assert.equal(x.r.json.error.code,code);assert.ok(!x.r.out.includes(access));}
});
test('device rejects token echoes in scope before storing and scrubs old metadata',async t=>{
 const x=await device(t,'scope-echo',()=>Response.json({access_token:access,refresh_token:refresh,scope:access+' '+refresh}));assert.equal(x.r.code,1);assert.ok(!x.r.out.includes(access)&&!x.r.out.includes(refresh));assert.equal(getCred('scope-echo','oauth_access_token'),null);
 setCred('old-echo','oauth_access_token',access);setCred('old-echo','oauth_refresh_token',refresh);setCred('old-echo','oauth_scope',access+' '+refresh);for(const cmd of [['status','old-echo'],['list']]){const r=await capture(()=>run(cmd));assert.ok(!r.out.includes(access)&&!r.out.includes(refresh));}
});
test('device rejects non-loopback HTTP before sending, and rejects terminal controls in human instructions',async t=>{
 let requests=0;t.mock.method(globalThis,'fetch',async()=>{requests++;return Response.json(grant)});let r=await capture(()=>run(args('plain').map(x=>x.replace('127.0.0.1','not-loopback.invalid'))));assert.notEqual(r.code,0);assert.equal(r.json.error.code,'USAGE');assert.equal(requests,0);
 for(const bad of ['HUMAN\x1b]52;c;AAAA\x07','HUMAN\u202eBAD']){const x=await device(t,'controls',()=>Response.json({error:'access_denied'}),{...grant,user_code:bad});assert.equal(x.calls,1);assert.ok(!x.r.err.includes('\x1b')&&!x.r.err.includes('\u202e'));}
});
test('device provider expiry bounds waits and refuses late fetch/body results',async t=>{
 let x=await device(t,'wait-expired',()=>{throw Error('no token call allowed')},{...grant,expires_in:2,interval:60});assert.deepEqual(x.waits,[2000]);assert.equal(x.r.json.error.code,'EXPIRED');
 for(const phase of ['fetch','body']){x=await device(t,'late-'+phase,async(n,o,c)=>{assert.ok(o.signal);if(phase==='fetch'){c.advance(5000);return Response.json({access_token:access});}return{json:async()=>{c.advance(5000);return{access_token:access}}};},{...grant,expires_in:2});assert.equal(x.r.json.error.code,'EXPIRED');assert.equal(getCred('late-'+phase,'oauth_access_token'),null);}
});
test('provider expiry aborts in-flight fetch AND body promises which never answer',async t=>{
 for(const phase of ['fetch','body']){let aborted=false;const x=await device(t,'stall-'+phase,async(n,o,c)=>{assert.ok(o.signal);o.signal.addEventListener('abort',()=>aborted=true,{once:true});if(phase==='fetch'){queueMicrotask(()=>c.advance(5000));return new Promise(()=>{});}return{json:()=>{queueMicrotask(()=>c.advance(5000));return new Promise(()=>{})}};},{...grant,expires_in:2});assert.equal(x.r.json.error.code,'EXPIRED');assert.ok(aborted);assert.equal(x.c.count,0);}
});
test('provider long waits are chunked into representable Node timers without a work cap',async t=>{
 const c=clock();let first=true;t.mock.method(globalThis,'fetch',async()=>Response.json(first?(first=false,{...grant,interval:2147484,expires_in:3000000}):{access_token:access,scope:'read'}));const delays=[];const r=await capture(()=>run(args('long'),{now:c.now,setTimer:(fn,ms)=>{delays.push(ms);queueMicrotask(()=>{c.advance(ms);fn();});return 1;},clearTimer(){}}));assert.equal(r.code,1);assert.ok(delays.length>0);assert.ok(delays.every(ms=>ms<=2147483647));
});
const authArgs=name=>['authorize',name,'--client-id','public','--auth-url','https://example.invalid/auth','--token-url','https://example.invalid/token'];
const goodUrl=auth=>{const a=new URL(auth),u=new URL(a.searchParams.get('redirect_uri'));u.searchParams.set('code','GOOD');u.searchParams.set('state',a.searchParams.get('state'));return u;};
test('invalid callbacks do not consume a valid attempt; duplicates, escapes, fragments, ambiguous errors are grammar errors',async t=>{
 const network=nativeFetch;let exchanges=0;t.mock.method(globalThis,'fetch',async()=>{exchanges++;return Response.json({access_token:access,scope:'read'})});const code=await capture(()=>run(authArgs('callback'),{onListening:async(port,auth)=>{const good=goodUrl(auth);for(const change of [u=>u.searchParams.set('state','wrong'),u=>u.searchParams.append('state','duplicate'),u=>u.search+='&code=two',u=>u.search+='&bad=%ZZ',u=>u.searchParams.set('error','denied'),u=>u.search+='&co%64e=duplicate']){const bad=new URL(good);change(bad);const r=await network(bad);assert.equal(r.status,400);await r.text();}const r=await network(good);assert.equal(r.status,200);await r.text();}}));assert.equal(code.code,0,code.out+code.err);assert.equal(exchanges,1);
 const input=new PassThrough();const r=await capture(()=>run([...authArgs('manual-grammar'),'--manual'],{stdin:input,onListening:async(port,auth)=>{const good=goodUrl(auth);input.write(good.href+'#fragment\n');input.write(good.href.replace('GOOD','%ZZ')+'\n');input.end(good.href+'\n');}}));assert.equal(r.code,0);assert.equal(exchanges,2);
});

test('manual callback grammar accepts large opaque codes without an invented size cap',async t=>{
 const input=new PassThrough(),large='X'.repeat(128*1024);let observed;
 t.mock.method(globalThis,'fetch',async(u,o)=>{observed=new URLSearchParams(o.body).get('code');return Response.json({access_token:access})});
 const r=await capture(()=>run([...authArgs('large-manual'),'--manual'],{stdin:input,onListening:async(port,auth)=>{const url=goodUrl(auth);url.searchParams.set('code',large);input.end(url.href+'\n');}}));assert.equal(r.code,0,r.out);assert.equal(observed,large);
});
