# v1 design decisions (2026-10-28)

The first wave of lmconnectors was built by four agents in parallel on one
repository (AGENTS.md lists the ownership table). These are the decisions
that shaped v1 and the reasons behind them.

## One CLI, one JSON envelope

lmscript drives tools as processes, so every lmconn run prints exactly one
JSON object on stdout: `{ok: true, result}` or `{ok: false, error: {code,
message}}`. Human text goes to stderr. Exit codes carry the coarse outcome
(0 ok, 1 runtime failure, 2 usage) so shell callers can branch without
parsing, while scripts read the envelope for the error code. Helpers live in
`src/result.js`; a module never writes to stdout directly.

The one exception is `lmconn --cli-schema --json`, which prints the bare
cli.schema.v1 document. The lmapi contract (and lmscript's pinned-binary
import) expects the document itself there, not an envelope.

## Credentials in SQLite, never on stdout

The store is one `node:sqlite` database (`~/.lmconnectors/creds.db`,
`LMCONN_DB` overrides it, mode 0600) with rows `(service, field, value)`.
This mirrors n8n's credential store without a server: a connector asks for
`getCred(service, field)` and the user manages rows with `lmconn cred`.
`cred list` prints names and timestamps only; `cred get --reveal` is the one
command that prints a value, for piping. Tests always point `LMCONN_DB` at a
temporary file.

Resolution order is store first, environment second, everywhere: LLM keys
through `resolveKey(name)` in `src/providers/index.js`, `http --auth SERVICE`
through `<SERVICE>_API_KEY`, GitHub through `GITHUB_TOKEN`/`GH_TOKEN` and
then `gh auth token`. Results report the source (`store`, `env:NAME`, `gh`,
`anonymous`), never the value.

## Provider registry

`src/providers/index.js` is the single table of LLM providers. Each entry
has a `kind`: `api` (OpenAI-compatible HTTPS, `src/providers/api.js`) or
`cli` (an agent CLI such as `claude -p` that answers one prompt on stdout,
`src/providers/cli.js`). Adding a provider is one table row plus, at most,
one adapter. `lmconn llm chat` and `lmconn llm probe` are generic over the
table.

## Legacy connectors

`http request` is the n8n "HTTP Request" node as a command: method, repeatable
headers, body from a string or a file, Bearer auth from the credential store,
a timeout. An HTTP error status is a successful run (`result.ok == false`,
exit 0) because the caller asked for the request and got an answer; only
usage, missing keys, timeouts and connection failures are envelope errors.
The body is returned parsed (`bodyJson`) when it is JSON, otherwise as text.

`github` is deliberately read-only (`user`, `repos`). It is the first
service-specific connector and sets the pattern: a dependency object
(`fetch`, `exec`) is injectable so tests never touch the network or `gh`.

## cli.schema.v1 module and the argv bridge

Each `src/cmd-<area>.js` exports `ops`, its cli.schema.v1 operation fragments,
next to `run(args)`. `src/schema.js` imports every area with a per-module
`import().catch`, so an area that does not exist yet, or fails to load,
is skipped and the document stays valid while agents work concurrently.

lmscript's validator (`@lmctl-ai/lmts`) requires operation names matching
`^[a-z][a-z0-9_]*$` and param names matching `^[A-Za-z_]\w*$`, and rejects
unknown param keys. The generator normalises rather than trusting each
author: `cred.set` and `llm chat` become `cred_set` and `llm_chat`,
`prompt-file` becomes `promptFile`, unknown keys are dropped. The convention
is therefore `<area>_<sub>` with camelCase params; authors should also mark
positional CLI arguments with `positional: true` so the bridge below can
place them.

lmscript calls an imported operation as `lmconn <op> --input-json
'{"op","params"}' [--readonly] [--confirm]`. Rather than teach every area a
second input form, `argvFromSchemaCall` in `src/schema.js` translates the
call back into the ordinary argv (`lmconn http request URL --data-file F`)
and `src/main.js` dispatches as usual. Positional params lead, booleans
become bare flags, arrays repeat the flag, camelCase maps back to kebab-case.
`--readonly` refuses operations whose access is not `read`.

The globals list is copied from lmscript's `git2` example minus
`input-graphql` (lmconn has no GraphQL input). `policy` is
`{dryrun: false, readonly: false}`: lmconn does not simulate writes itself;
lmscript's dry pass already returns `{status: "simulated"}` without spawning.

`npm run schema` regenerates `schema/lmconn.cli.schema.v1.json`, which is
committed so `import "../schema/lmconn.cli.schema.v1.json";` works from a
checkout without running anything. Regenerate it whenever an `ops` export
changes.

## Verified against lmscript 0.2.38

`examples/schema-import.lms` checks, dry-runs and runs with the lmscript in
`~/lmctl-mono/lmscript/bin/lmscript` (0.2.38): `--check` and `--dry-run` need
neither lmconn nor network; a real run lists repositories through
`lmconn.github_repos`. `examples/llm-chat.lms` drives `lmconn llm chat`
through `system()` and parses the envelope with `json_parse`.
