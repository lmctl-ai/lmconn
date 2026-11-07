// Tiny hermetic ACP agent for unit tests. Behaviour is picked by argv[2]:
//   echo        replies "echo:<n>:<prompt text>" in two chunks, tracks turn count
//   permission  asks session/request_permission before replying with the outcome
//   fs          calls fs/read_text_file and reports the error code it got back
//   exit        dies right after initialize
//   garbage     writes a non-JSON line
import readline from 'node:readline';
const mode = process.argv[2] ?? 'echo';
const send = m => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', ...m }) + '\n');
const waiting = new Map();
let turns = 0, nextId = 1000;
const ask = (method, params) => new Promise(res => { const id = nextId++; waiting.set(id, res); send({ id, method, params }); });
const update = (sessionId, text) => send({ method: 'session/update', params: { sessionId, update: { sessionUpdate: 'agent_message_chunk', content: { type: 'text', text } } } });

readline.createInterface({ input: process.stdin }).on('line', async line => {
  const m = JSON.parse(line);
  if (m.method === undefined) { waiting.get(m.id)?.(m); waiting.delete(m.id); return; }
  if (m.method === 'initialize') {
    if (mode === 'garbage') { process.stdout.write('not json\n'); return; }
    send({ id: m.id, result: { protocolVersion: m.params.protocolVersion, agentCapabilities: {}, authMethods: [] } });
    if (mode === 'exit') process.exit(3);
  } else if (m.method === 'session/new') send({ id: m.id, result: { sessionId: 'fake-session' } });
  else if (m.method === 'session/prompt') {
    const text = m.params.prompt.map(b => b.text).join('');
    turns++;
    if (mode === 'permission') {
      const r = await ask('session/request_permission', { sessionId: 'fake-session', toolCall: { toolCallId: 't1' },
        options: [{ optionId: 'no', name: 'Reject', kind: 'reject_once' }, { optionId: 'yes', name: 'Allow', kind: 'allow_once' }] });
      update('fake-session', `outcome:${JSON.stringify(r.result.outcome)}`);
    } else if (mode === 'fs') {
      const r = await ask('fs/read_text_file', { sessionId: 'fake-session', path: '/etc/passwd' });
      update('fake-session', `fs:${r.error?.code}`);
    } else { update('fake-session', `echo:${turns}:`); update('fake-session', text); }
    send({ id: m.id, result: { stopReason: 'end_turn' } });
  } else if (m.id !== undefined) send({ id: m.id, error: { code: -32601, message: 'unknown' } });
});
