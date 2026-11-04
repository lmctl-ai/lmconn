// Run: node examples/oauth-pkce.mjs
// Local lmmock authorization-code + PKCE flow only.
import { run } from '../src/cmd-oauth.js';
import { getCred } from '../src/creds.js';
import { createMockIdP } from '../scripts/mock-idp.js';
import { followAuthorization, withPrivateStore } from './oauth-demo-support.mjs';

await withPrivateStore(async () => {
  const idp = await createMockIdP({ requirePkce: true });
  try {
    const code = await run(['authorize', 'demo-account', '--client-id', 'demo-client', '--client-secret', 'synthetic-client-secret',
      '--auth-url', idp.authUrl, '--token-url', idp.tokenUrl, '--scope', 'repo read:user', '--owner', 'mock-user', '--source', 'lmmock'], {
      onListening: (port, url) => followAuthorization(idp, port, url),
    });
    if (code !== 0 || !getCred('demo-account', 'oauth_access_token')) throw new Error('PKCE example did not store the mock grant');
  } finally { await idp.close(); }
});
