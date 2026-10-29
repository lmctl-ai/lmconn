# lmconnectors durable memory

Wiki-style notes that record why lmconn is built the way it is. Amend a
chapter together with the code it describes; the README documents what the
commands do, these pages record the decisions behind them.

| Chapter | Covers |
|---|---|
| [v1 design decisions](v1-design.md) | SQLite credential store, the JSON envelope and exit codes, the provider registry, the cli.schema.v1 module and the `--input-json` bridge, the legacy connectors |
| [Free-API example wave](free-connectors-2026-10-28.md) | why the `examples/free-*.lms` series uses credential-less public APIs, the conventions it fixed, what the parallel fan-out demonstrates |
| [OAuth2 for lmconn](oauth2-2026-10-28.md) | why n8n's source was the reference, the `oauth_*` storage contract, the `--auth` fallback order, mock-IdP testing, bun compile constraints |
| [Strict mock identity provider](oauth2-mock-idp-2026-10-28.md) | why a strict mock beats a permissive one, the misbehave-mode pattern, why the demo can follow the authorize redirect without a browser |

Conventions for new chapters: one h1, concise prose or tables, no emoji,
dates written out (2026-10-28), link related pages by relative path.

- [lmmock fixture migration](lmmock-migration-2026-10-29.md): scripted HTTP/LLM/OAuth mocks, failure cases, portable lifecycle and fixture pins.
- [lmmock coverage review](../docs/lmmock-coverage.md): connector inventory, service contract tests, remaining gaps, and lmscript Actions runner.
