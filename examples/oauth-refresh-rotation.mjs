// Run: node examples/oauth-refresh-rotation.mjs
// Local lmmock flow only; checks that a rotated refresh token replaces the prior one.
import { run } from '../src/cmd-oauth.js';
import { getCred } from '../src/creds.js';
import { createMockIdP } from '../scripts/mock-idp.js';
import { followAuthorization, withPrivateStore } from './oauth-demo-support.mjs';

await withPrivateStore(async () => {
  const idp = await createMockIdP({ requirePkce: true, rotateRefreshTokens: true });
  try {
    const options = ['demo-account', '--client-id', 'demo-client', '--client-secret', 'synthetic-client-secret',
      '--auth-url', idp.authUrl, '--token-url', idp.tokenUrl, '--scope', 'repo read:user', '--owner', 'mock-user', '--source', 'lmmock'];
    const authorized = await run(['authorize', ...options], { onListening: (port, url) => followAuthorization(idp, port, url) });
    const previous = getCred('demo-account', 'oauth_refresh_token');
    const refreshed = await run(['refresh', 'demo-account']);
    const current = getCred('demo-account', 'oauth_refresh_token');
    if (authorized !== 0 || refreshed !== 0 || !current || current === previous) throw new Error('refresh example did not rotate its mock refresh token');
  } finally { await idp.close(); }
});
