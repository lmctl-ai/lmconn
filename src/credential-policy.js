import { openDb, getCred } from './creds.js';
import { endpoint, origins, securityError } from './oauth-security.js';
export function brokerMode() {
  const mode = process.env.LMCONN_STORE_MODE;
  if (mode && !['legacy', 'broker'].includes(mode)) throw securityError('Unknown credential store mode');
  return mode === 'broker';
}
export function policy(service, db = openDb()) {
  const row = db.prepare('SELECT document FROM credential_policy WHERE service=?').get(service);
  if (!row) return null;
  try {
    const value = JSON.parse(row.document);
    if (!value || !Array.isArray(value.origins) || typeof value.noReveal !== 'boolean') throw Error();
    if (value.origins.length && JSON.stringify(origins(value.origins)) !== JSON.stringify(value.origins)) throw Error();
    return value;
  } catch { throw securityError('Credential binding is invalid'); }
}
export function putPolicy(service, document, db = openDb()) {
  db.prepare('INSERT INTO credential_policy(service,document) VALUES (?,?) ON CONFLICT(service) DO UPDATE SET document=excluded.document').run(service, JSON.stringify(document));
}
export function refuseLegacyWrite(service, db = openDb()) {
  if (brokerMode() || policy(service, db)?.noReveal) throw securityError('Protected credentials require cred store; legacy writes cannot change them');
}
export function refuseReveal(service, db = openDb()) {
  if (brokerMode() || policy(service, db)?.noReveal) throw securityError('This credential cannot be revealed');
}
export function checkRefresh(service, cfg, db = openDb()) {
  const p = policy(service, db);
  const tokenUrl = endpoint(cfg['token-url'], 'OAuth token endpoint').href;
  if (brokerMode() && !p?.noReveal) throw securityError('Broker mode requires a protected credential');
  if (p?.refresh && (p.refresh.tokenUrl !== tokenUrl || p.refresh.clientId !== cfg['client-id'] || p.refresh.authStyle !== cfg['auth-style'])) throw securityError('OAuth issuer/client binding mismatch');
  if (p?.noReveal && !p.refresh) throw securityError('This handle has no bound refresh configuration');
  endpoint(cfg['token-url'], 'OAuth token endpoint');
}
export function authorizeOrigin(service, value, db = openDb()) {
  const origin = endpoint(value, 'Authenticated destination').origin;
  db.exec('BEGIN IMMEDIATE');
  try {
    let p = policy(service, db);
    if (brokerMode() && !p?.noReveal) throw securityError('Broker mode requires a protected credential');
    if (!p) p = { noReveal: false, kind: 'legacy', issuer: null, owner: null, origins: [], refresh: null };
    if (p.origins.length === 0 && !p.noReveal) {
      p.origins = [origin];
      const tokenUrl = getCred(service, 'oauth_token_url', db);
      if (tokenUrl) p.refresh = { tokenUrl: endpoint(tokenUrl).href, clientId: getCred(service, 'oauth_client_id', db), authStyle: getCred(service, 'oauth_auth_style', db) || 'header' };
      putPolicy(service, p, db);
    }
    if (!p.origins.includes(origin)) throw securityError('Authenticated origin is outside the credential binding');
    db.exec('COMMIT'); return p;
  } catch (err) { db.exec('ROLLBACK'); throw err; }
}
