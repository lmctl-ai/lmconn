// Small RFC 8628 device-flow stub used only by local lmconn examples/tests.
// It auto-approves after one authorization_pending reply and uses synthetic values.
import { createServer } from 'node:http';

export async function createMockDeviceIdP({ port = 0, missingInstructions = false } = {}) {
  const state = { approved: false, polls: [], deviceRequests: [] };
  const server = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
    response.setHeader('Content-Type', 'application/json');
    if (request.url === '/device' && request.method === 'POST') {
      state.deviceRequests.push(Object.fromEntries(body));
      response.end(JSON.stringify(missingInstructions
        ? { device_code: 'synthetic-device-code', expires_in: 60 }
        : { device_code: 'synthetic-device-code', user_code: 'MOCK-CODE', verification_uri: 'http://127.0.0.1/mock/verify', expires_in: 60, interval: 1 }));
      return;
    }
    if (request.url === '/token' && request.method === 'POST') {
      state.polls.push(Object.fromEntries(body));
      if (!state.approved) {
        response.end(JSON.stringify({ error: 'authorization_pending' }));
        state.approved = true;
        return;
      }
      response.end(JSON.stringify({ access_token: 'synthetic-access-secret', refresh_token: 'synthetic-refresh-secret', token_type: 'Bearer', scope: 'repo read:user', expires_in: 3600 }));
      return;
    }
    response.writeHead(404).end('{}');
  });
  await new Promise(resolve => server.listen(port, '127.0.0.1', resolve));
  const address = server.address();
  return {
    state,
    deviceUrl: `http://127.0.0.1:${address.port}/device`,
    tokenUrl: `http://127.0.0.1:${address.port}/token`,
    close() { return new Promise(resolve => server.close(resolve)); },
  };
}
