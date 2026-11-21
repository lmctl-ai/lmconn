# Durable Memory — `lmconn`

- [01-ldap-and-saml-connectors.md](01-ldap-and-saml-connectors.md): Zero-dependency LDAPv3 (`src/cmd-ldap.js`) and SAML 2.0 (`src/cmd-saml.js`) connectors, RFC 4516 `ldap://` URLs, `whoami`, `compare`, LDIF output, and live `lmldap` CI integration (`test/ldap-lmldap.test.js`).
- [npm-missing-key-2026-11-21.md](npm-missing-key-2026-11-21.md): `npm whoami` on a never-stored handle returns `MISSING_KEY` in broker mode (lmauth `--login` depends on it); fixed ordering in `tokenFor` (4f5b14e).
