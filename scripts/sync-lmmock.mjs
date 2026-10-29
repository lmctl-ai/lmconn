// Copy only committed, reviewed lmcode fixtures from lmmock and verify their hashes.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('..',import.meta.url));
const files=['schema.json','oauth.lms','connector-http.lms','llm.lms','github.lms', ...['slack','discord','telegram','jira','stripe','notion','airtable','hubspot','gitlab','asana','trello','pagerduty','datadog','linear','twilio','sendgrid','mailchimp'].flatMap(name=>[name+'.lms',name+'-client.json'])];
const hash=data=>crypto.createHash('sha256').update(data).digest('hex');
const lockPath=path.join(root,'test/mocks/lmmock.lock.json');
if(process.argv[2]==='--check') {
 const lock=JSON.parse(fs.readFileSync(lockPath));
 for(const file of files)if(hash(fs.readFileSync(path.join(root,'test/mocks',file)))!==lock.sha256[file])throw Error('lmmock fixture drift: '+file);
 console.log('PASS lmmock fixture lock');
} else {
 const source=path.resolve(process.argv[2] || path.join(root,'../lmmock'));
 const commit=execFileSync('git',['-C',source,'rev-parse','HEAD'],{encoding:'utf8'}).trim();
 const sha256={};
 for(const file of files){const data=execFileSync('git',['-C',source,'show',commit+':examples/'+file]);fs.writeFileSync(path.join(root,'test/mocks',file),data);sha256[file]=hash(data);}
 fs.writeFileSync(lockPath,JSON.stringify({repo:'lmctl-ai/lmmock',commit,sha256},null,2)+'\n');
 console.log('Pinned lmmock fixtures at '+commit);
}
