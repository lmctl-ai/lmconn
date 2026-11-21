# Durable Memory — `lmconn`

- [01-ldap-and-saml-connectors.md](01-ldap-and-saml-connectors.md): Zero-dependency LDAPv3 (`src/cmd-ldap.js`) and SAML 2.0 (`src/cmd-saml.js`) connectors, RFC 4516 `ldap://` URLs, `whoami`, `compare`, LDIF output, and live `lmldap` CI integration (`test/ldap-lmldap.test.js`).
- [npm-missing-key-2026-11-21.md](npm-missing-key-2026-11-21.md): `npm whoami` on a never-stored handle returns `MISSING_KEY` in broker mode (lmauth `--login` depends on it); fixed ordering in `tokenFor` (4f5b14e).
- [v1-design.md](v1-design.md): v1 design decisions (2026-10-28): the first connector wave, built by four agents in parallel.
- [bun-binaries-ci.md](bun-binaries-ci.md): one single-file Bun executable per OS and how CI builds them (2026-10-28).
- [free-connectors-2026-10-28.md](free-connectors-2026-10-28.md): the free-API example wave, nineteen `examples/free-*.lms` workflows.
- [oauth2-2026-10-28.md](oauth2-2026-10-28.md): OAuth2 for lmconn, closing the gap named in `docs/n8n-coverage.md`.
- [oauth2-mock-idp-2026-10-28.md](oauth2-mock-idp-2026-10-28.md): `scripts/mock-idp.js`, the strict mock identity provider used as the OAuth2 test oracle.
- [lmmock-migration-2026-10-29.md](lmmock-migration-2026-10-29.md): HTTP, LLM and strict OAuth providers moved to lmmock fixtures.
- [encryption-at-rest-2026-11-18.md](encryption-at-rest-2026-11-18.md): encryption at rest (v0.3.0): the store key, decisions and review rounds.
