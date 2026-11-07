// Tiny hermetic stdio MCP server for unit tests. argv[2] picks the behaviour:
//   basic     tools echo/add, a resource, a prompt, log notification per call
//   probing   like basic, but before each tool result it pings the client and
//             sends a sampling/createMessage request (client must refuse it)
//   exit      dies right after initialize
//   oldproto  answers initialize with an unsupported protocol version
import readline from 'node:readline';
const mode = process.argv[2] ?? 'basic';
const send = m => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', ...m }) + '\n');
const waiting = new Map();
let nextId = 5000;
const ask = (method, params) => new Promise(res => { const id = nextId++; waiting.set(id, res); send({ id, method, params }); });

readline.createInterface({ input: process.stdin }).on('line', async line => {
  const m = JSON.parse(line);
  if (m.method === undefined) { waiting.get(m.id)?.(m); waiting.delete(m.id); return; }
  const reply = result => send({ id: m.id, result });
  const fail = (code, message) => send({ id: m.id, error: { code, message } });
  switch (m.method) {
    case 'initialize':
      reply({ protocolVersion: mode === 'oldproto' ? '2024-11-05' : m.params.protocolVersion, capabilities: { tools: {}, resources: {}, prompts: {} }, serverInfo: { name: 'fake', version: '1' } });
      if (mode === 'exit') process.exit(4);
      break;
    case 'notifications/initialized': break;
    case 'ping': reply({}); break;
    case 'tools/list': reply({ tools: [{ name: 'echo', inputSchema: { type: 'object' } }, { name: 'add', inputSchema: { type: 'object' } }] }); break;
    case 'tools/call': {
      const { name, arguments: a } = m.params;
      send({ method: 'notifications/message', params: { level: 'info', data: `called ${name}` } });
      let extra = '';
      if (mode === 'probing') {
        const pong = await ask('ping', {});
        const sampling = await ask('sampling/createMessage', { messages: [], maxTokens: 1 });
        extra = `|ping:${JSON.stringify(pong.result)}|sampling:${sampling.error?.code}`;
      }
      if (name === 'echo') reply({ content: [{ type: 'text', text: String(a.text) + extra }], isError: false });
      else if (name === 'add') reply({ content: [{ type: 'text', text: String(a.a + a.b) + extra }], isError: false });
      else reply({ content: [{ type: 'text', text: `unknown tool ${name}` }], isError: true });
      break;
    }
    case 'resources/list': reply({ resources: [{ uri: 'fake:///r', name: 'r' }] }); break;
    case 'resources/read': m.params.uri === 'fake:///r' ? reply({ contents: [{ uri: 'fake:///r', text: 'resource body' }] }) : fail(-32602, 'unknown resource'); break;
    case 'prompts/list': reply({ prompts: [{ name: 'greet' }] }); break;
    case 'prompts/get': reply({ messages: [{ role: 'user', content: { type: 'text', text: `hello ${m.params.arguments?.who ?? 'world'}` } }] }); break;
    default: fail(-32601, 'unknown');
  }
});
