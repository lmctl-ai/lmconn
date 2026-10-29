// The strict OAuth2 handlers live in test/mocks/oauth.lms and run in lmmock.
import { startMock } from './lmmock.js';
export async function createMockIdP(options = {}) {
  const clean = Object.fromEntries(Object.entries(options).filter(([,value]) => value != null));
  const server = await startMock('oauth', {clients:{}, ...clean}, options.port || 0);
  const clients = {};
  return {
    origin:server.origin, authUrl:server.origin+'/authorize', tokenUrl:server.origin+'/token', userinfoUrl:server.origin+'/api/userinfo',
    get log() {return server.log;},
    registerClient({clientId,clientSecret='',redirectUris,authStyle='both'}) {
      clients[clientId] = {clientSecret,redirectUris,authStyle};server.configure({clients});
    },
    configure:server.configure,
    close:server.close,
  };
}

// Standalone server for external clients (n8n): node scripts/mock-idp.js [--port 5556] [--once]
// --once exits 3 s after the first token grant (runnable end-to-end demos).
if (import.meta.url === `file://${process.argv[1]}`) {
  const flag = (name) => process.argv.includes(name);
  const port = Number(process.argv[process.argv.indexOf('--port') + 1] || 5556);
  const idp = await createMockIdP({ port });
  idp.registerClient({
    clientId: 'demo-client',
    clientSecret: 'demo-secret',
    redirectUris: [
      `http://127.0.0.1:${port === 0 ? 5556 : port}/callback`,
      'http://127.0.0.1:5558/callback',
      'http://localhost:5678/rest/oauth2-credential/callback',
      'http://127.0.0.1:5678/rest/oauth2-credential/callback',
    ],
    authStyle: 'both',
  });
  console.log(JSON.stringify({ authUrl: idp.authUrl, tokenUrl: idp.tokenUrl, userinfoUrl: idp.userinfoUrl, clientId: 'demo-client' }));
  if (flag('--once')) {
    const poll = setInterval(() => {
      if (idp.log.some((e) => e.path === '/token')) {
        clearInterval(poll);
        setTimeout(() => idp.close().then(() => process.exit(0)), 3000);
      }
    }, 100);
  }
}
