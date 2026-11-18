# Encryption at rest (v0.3.0, 18 Nov 2026)

Owner asked for a lightweight secret storage like n8n's. lmconn already was the credential store (plaintext SQLite, 0700/0600 only), so the work
added encryption to it; lmauth shares it through the broker import (`cred store`) and never reads the key.
User-facing description: `docs/encryption-at-rest.md`. This note keeps the why.

## Decisions
- AES-256-GCM through node:crypto (zero deps), instance key plus wrapped data keys, AAD binds service, field and key id.
- Key outside the store directory (default `~/.config/lmconn/instance.key`), or `LMCONN_KEY_FILE`, or `LMCONN_KEY`. A missing key with ciphertext
  present fails closed; a read never creates a key.
- Sealed state cannot live only in the database (a file writer could strip it): an external `sealed.<sha256 of db path>` record with a MAC sits in the
  key directory, written only AFTER the sealing transaction commits (a record written inside it survived a rollback and locked the store).
- Rollback of rows, policy documents or the whole file by someone who can write the database is undetectable (needs an external counter). Documented.
- `LMCONN_KEY`-only mode cannot prove a store was ever sealed; recommend a key file for long-lived stores.
- Windows: file keys fail closed until native ACL support; use `LMCONN_KEY` (breaking change for Windows `cred set` users).

## Process
Two fresh-eyes security reviews (design, then code with real attacks). Round 1 found: plaintext downgrade by a DB writer, no-op rotation, silent plaintext
fallbacks, unenforced GCM tag length, key in the environment, key next to the database. Round 2 found the record-before-commit lockout. All fixed or
documented. Tests: `test/encryption.test.js` (real SQLite, real processes for the key race and crashes).

## Gotchas
- `npm test` runs with `--import ./test/setup-env.mjs` (temp XDG dir; on Windows a fixed test `LMCONN_KEY`). Running one test file without it creates a key in the real `~/.config/lmconn`.
- On the t4g2 dev host the installed lmmock and lmscript do not match, so about 68 mock-based tests fail locally; CI is the judge.
