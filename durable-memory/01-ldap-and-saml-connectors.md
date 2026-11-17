# LDAPv3 & SAML 2.0 Connectors (`lmconn` v0.2.0)

## Summary

1. **LDAPv3 Connector (`src/cmd-ldap.js`)**:
   - Operations: `ping`, `bind`, `whoami` (RFC 4532), `search`, `get`, `add`, `modify` (`{add, replace, delete}`), `compare` (RFC 4511), `del`.
   - Supports RFC 4516 `--url ldap://[user:pass@]host[:port][/dn[?attrs[?scope[?filter]]]]]`, `--attrs`, `--size-limit`, `--time-limit`, and `--format json|ldif` (RFC 2849).
2. **SAML 2.0 Connector (`src/cmd-saml.js`)**:
   - Operations: `ping`, `idp-metadata`, `sp-metadata`, `put-user`, `get-user`, `list-users`, `delete-user`, `authn-request`, `issue-assertion`, `validate-assertion`, `sso-login`.
3. **CI & Verification (`.github/workflows/ci.yml`)**:
   - Live `lmldap` integration test (`test/ldap-lmldap.test.js`), `smoke.js` dynamic schema count validation, and 5-platform binary releases (`v0.2.0` & rolling `latest`).
