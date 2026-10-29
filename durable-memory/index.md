# lmconnectors durable memory

Wiki-style notes that record why lmconn is built the way it is. Amend a
chapter together with the code it describes; the README documents what the
commands do, these pages record the decisions behind them.

| Chapter | Covers |
|---|---|
| [v1 design decisions](v1-design.md) | SQLite credential store, the JSON envelope and exit codes, the provider registry, the cli.schema.v1 module and the `--input-json` bridge, the legacy connectors |
| [Free-API example wave](free-connectors-2026-10-28.md) | why the `examples/free-*.lms` series uses credential-less public APIs, the conventions it fixed, what the parallel fan-out demonstrates |
| [OAuth2 for lmconn](oauth2-2026-10-28.md) | why n8n's source was the reference, the `oauth_*` storage contract, the `--auth` fallback order, mock-IdP testing, bun compile constraints |

Conventions for new chapters: one h1, concise prose or tables, no emoji,
dates written out (2026-10-28), link related pages by relative path.
