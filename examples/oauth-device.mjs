// Run: node examples/oauth-device.mjs
// Local RFC 8628 stub only; no provider account or real credentials.
import { run } from '../src/cmd-oauth.js';
import { getCred } from '../src/creds.js';
import { createMockDeviceIdP } from '../scripts/mock-device-idp.js';
import { withPrivateStore } from './oauth-demo-support.mjs';

await withPrivateStore(async () => {
  const idp = await createMockDeviceIdP();
  try {
    const code = await run(['device', 'demo-account', '--client-id', 'demo-client', '--device-url', idp.deviceUrl,
      '--token-url', idp.tokenUrl, '--scope', 'repo read:user', '--owner', 'mock-user', '--source', 'lmmock']);
    if (code !== 0 || !getCred('demo-account', 'oauth_access_token')) throw new Error('device example did not store the mock grant');
  } finally { await idp.close(); }
});
