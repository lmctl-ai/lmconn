# lmmock integration fixtures

The HTTP, LLM and strict OAuth providers now run in lmmock. Their lmcode handlers
are reviewed copies from lmctl-ai/lmmock, pinned by test/mocks/lmmock.lock.json.
Go owns the network and general host primitives. Scripts own OAuth validation,
response variants and fault injection. Node owns test assertions and lifecycle.

scripts/lmmock.js uses lmmock exec around a keepalive child. Closing stdin ends
the child and shuts down the server on every platform, including Windows. Client
registration writes private configuration synchronously, so the existing n8n and
lmconn callback hooks keep their contract. Sanitized audit lines remain available
after close. Request inspection is in memory and is never printed or logged.

The former adversarial token proxy is replaced by named lmcode fault modes.
All 71 connector tests pass locally. The independently installed n8n harness tests
real OAuth credential creation, callback validation and persistence using fresh
state. The local n8n source remains unmodified and supplies the reference for
header/body authentication and PKCE request construction.

CI installs checksum-verified lmmock v0.1.3 and current npm lmscript before tests.
The production connector binary does not gain any runtime dependency on lmmock.

Verified on 2026-10-29 with n8n 2.45.4: header authentication, body authentication
and PKCE each completed the real n8n callback and persisted credentials. The
lmmock audit confirmed three authorization-code exchanges with the expected
header/body/header authentication styles. No production n8n account was used.
