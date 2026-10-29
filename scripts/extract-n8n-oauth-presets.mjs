// Generates src/oauth-presets.json from n8n's installed OAuth2 credential
// definitions. n8n's implementers read each vendor's OAuth2 docs; we reuse
// their endpoints, scopes and quirks as data. Our oauth area has a fixed
// number of shapes (authorization-code ± PKCE, client-credentials, refresh);
// everything vendor-specific lives in this table, and any value can be
// overridden by flags or the cred store.
//
// Usage:  node scripts/extract-n8n-oauth-presets.mjs [path-to-n8n-package]
// Default n8n path: the globally installed package (`npm root -g`/n8n).
import { readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execSync } from 'node:child_process';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const n8nRoot = process.argv[2] || join(execSync('npm root -g').toString().trim(), 'n8n');
const credDir = join(n8nRoot, 'node_modules', 'n8n-nodes-base', 'dist', 'credentials');

const GRANTS = new Set(['authorizationCode', 'pkce', 'clientCredentials']);

// n8n expresses a few endpoints as runtime expressions; pin the well-known values.
const FIXUPS = {
  github: { auth_url: 'https://github.com/login/oauth/authorize', token_url: 'https://github.com/login/oauth/access_token' },
};

const presets = {};
let skipped = 0;

for (const file of readdirSync(credDir)) {
  if (!file.endsWith('OAuth2Api.credentials.js')) continue;
  let inst;
  try {
    const mod = require(join(credDir, file));
    const cls = Object.values(mod).find((v) => typeof v === 'function');
    inst = new cls();
  } catch { skipped++; continue; }
  const defaults = {};
  for (const p of inst.properties || []) {
    if (p.name && typeof p.default === 'string') defaults[p.name] = p.default;
  }
  const { authUrl, accessTokenUrl, scope, authQueryParameters, grantType, authentication } = defaults;
  if (!authUrl || !accessTokenUrl) { skipped++; continue; }
  if (grantType && !GRANTS.has(grantType)) { skipped++; continue; }
  // n8n expressions (={{...}}) resolve at runtime in their editor; keep literals only.
  const literal = (v) => (typeof v === 'string' && !v.startsWith('={{') && v !== '' ? v : undefined);
  const key = inst.name.replace(/OAuth2Api$/, '').replace(/[A-Z]/g, (c, i) => (i ? '-' : '') + c.toLowerCase());
  const fixup = FIXUPS[key] || {};
  const tokenUrl = fixup.token_url || literal(accessTokenUrl);
  if (!tokenUrl) { skipped++; continue; }
  presets[key] = {
    ...(fixup.auth_url || literal(authUrl) ? { auth_url: fixup.auth_url || authUrl } : {}),
    token_url: tokenUrl,
    ...(literal(scope) && { scope }),
    ...(literal(authQueryParameters) && { auth_query: authQueryParameters }),
    ...(grantType && { grant_type: grantType }),
    ...(authentication && { auth_style: authentication }),
    display_name: inst.displayName,
  };
}

const sorted = Object.fromEntries(Object.entries(presets).sort(([a], [b]) => a.localeCompare(b)));
writeFileSync(new URL('../src/oauth-presets.json', import.meta.url), JSON.stringify(sorted, null, 2) + '\n');
console.log(`wrote ${Object.keys(sorted).length} presets (skipped ${skipped}); n8n source: ${credDir}`);
