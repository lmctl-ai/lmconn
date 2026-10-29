# AGENTS.md — lmconn

One CLI, `lmconn`, gives lmscript access to LLM providers and legacy
services. Plain ESM Node (>= 22.5), zero npm dependencies. The credential
store uses `node:sqlite`. Tests use `node --test`.

## Contracts

- stdout carries exactly one JSON envelope per run:
  `{"ok": true, "result": ...}` or `{"ok": false, "error": {code, message}}`.
  Use `emit/ok/fail/emitFail` from `src/result.js`. Human text goes to stderr.
- Exit codes: 0 ok, 1 runtime failure, 2 usage.
- Each command area is `src/cmd-<area>.js` exporting
  `async run(args) -> exitCode` and optionally `ops`, a list of
  cli.schema.v1 operation fragments (see
  `~/lmctl-mono/lmscript/examples/git2.cli.schema.v1.json` for the format;
  fields: name, access read|write, description, params[{name, type, occurs,
  description, ...}]).
- Secrets: never printed, never logged, never committed. `cred list` shows
  names only. Tests point `LMCONN_DB` at a temp file. Keys resolve through
  `resolveKey(name)` in `src/providers/index.js` (store first, env second).
- `src/providers/index.js` owns the provider table. Add a provider there,
  then implement its adapter: `src/providers/api.js` (kind 'api',
  OpenAI-compatible) or `src/providers/cli.js` (kind 'cli', agent CLIs).
- Operation naming for the schema: write ops as `<area> <sub>` (schema.js
  normalises to `<area>_<sub>`) with camelCase or kebab params. Params that
  arrive as positional CLI arguments must say `positional: true`, or
  lmscript's `--input-json` bridge cannot reach them.

## Ownership (initial wave)

| Who | Files |
|---|---|
| Astra1 | `src/cmd-cred.js`, `test/cred.test.js` |
| Astra2 | `src/providers/api.js`, `src/cmd-llm.js`, `test/llm-api.test.js` |
| Astra3 | `src/providers/cli.js`, `src/llm-probe.js`, `test/llm-cli.test.js` |
| Fable | `src/cmd-http.js`, `src/cmd-github.js`, `src/schema.js`, `examples/`, docs |

Shared files (`src/main.js`, `src/result.js`, `src/creds.js`,
`src/providers/index.js`, this file): change only when needed, say so in the
commit message.

## Git rules

Wiki-style: commit early, `git pull --rebase` before every push, push often.
One commit touches your own files unless the change is the point.

## Build & CI

- `.github/workflows/ci.yml` runs on every push to master and every `v*` tag:
  node test matrix (ubuntu/macos/windows) → bun cross-compile
  (`bun build --compile --minify --target=bun-<target>` for linux-x64,
  linux-arm64, darwin-x64, darwin-arm64, windows-x64) → native smoke test of
  the binary (`bun scripts/smoke.js <binary>`) → GitHub Release. Master pushes
  update the rolling `latest` prerelease; `v*` tags get a versioned release.
- The binary must stay bun-compilable: no template-literal dynamic imports
  (use `AREA_LOADERS` in `src/schema.js`), no runtime reads of
  `../package.json` (use the JSON import attribute), and stick to Node
  built-ins that Bun implements (`node:sqlite` works).
- Add a check to `scripts/smoke.js` whenever you add an operation.
