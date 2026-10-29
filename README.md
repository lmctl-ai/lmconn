# lmconn

`lmconn`: connectors for AI-agent workflows. One CLI, scriptable from
lmscript through `system()` or as a cli.schema.v1 module. Credentials live
in one SQLite database (`node:sqlite`), like n8n's credential store, minus
the server. Plain ESM Node >= 22.5, zero npm dependencies.

## Install

Prebuilt single-file binaries (Bun-compiled, no Node needed) are attached to
every release — the rolling `latest` prerelease tracks master, `v*` tags are
stable:

```sh
curl -L https://github.com/lmctl-ai/lmconn/releases/latest/download/lmconn-linux-x64.tar.gz | tar xz
./lmconn-linux-x64 --version
```

Targets: linux-x64, linux-arm64, darwin-x64, darwin-arm64, windows-x64.

From source:

```sh
npm link        # puts lmconn on PATH
npm test        # node --test
```

## Quickstart

```sh
lmconn cred set deepseek api_key --env DEEPSEEK_API_KEY   # store without echoing
lmconn cred list                                          # names only
lmconn llm providers                                      # who is configured
lmconn llm chat deepseek --prompt "say ok"
lmconn llm chat claude --prompt "say ok"                  # agent CLI adapter
lmconn llm probe                                          # one live call per provider
lmconn http request https://api.github.com/zen
lmconn github repos lmctl-ai --limit 5
lmconn --cli-schema --json                                # cli.schema.v1 document
```

## Contracts

- stdout carries exactly one JSON envelope per run: `{"ok": true, "result": ...}`
  or `{"ok": false, "error": {"code", "message"}}`. Human text goes to stderr.
- Exit codes: 0 success, 1 runtime failure (network, HTTP, missing key), 2 usage.
- Secrets are never printed or logged. `cred list` shows names only; only
  `cred get --reveal` prints a value, for piping.
- `lmconn --cli-schema --json` prints the bare cli.schema.v1 document (no envelope).

## Command reference

### cred

| Command | Does |
|---|---|
| `cred set <service> <field> (--value V \| --env VAR \| --stdin)` | store one credential; prefer `--env` or `--stdin` so the secret stays out of argv |
| `cred get <service> <field> [--reveal]` | presence check; `--reveal` returns the value |
| `cred list` | services, fields and timestamps, never values |
| `cred delete <service> <field>` | remove one credential |
| `cred path` | the database path (`LMCONN_DB` overrides `~/.lmconn/creds.db`) |

LLM providers read `<provider> api_key`; `http --auth SERVICE` reads
`<SERVICE> api_key`; `github` reads `github api_key`.

### OAuth2

| Command | Does |
|---|---|
| `oauth authorize <service>` | authorization code + PKCE + state via a loopback callback; `--manual` accepts the redirect URL on stdin |
| `oauth refresh <service>` | refresh stored tokens; `RECONNECT` means authorize again |
| `oauth status <service>` | read-only authorization, expiry, and refresh-token presence; never token values |

Create a GitHub OAuth App with callback `http://127.0.0.1:15847/callback`,
and set `GITHUB_OAUTH_CLIENT_ID` and `GITHUB_OAUTH_CLIENT_SECRET` in your environment.
Endpoints, scope and auth style come from the built-in vendor preset
(`src/oauth-presets.json`, mined from n8n's credential definitions — 69 services),
so only the app credentials are needed:

```sh
lmconn cred set github oauth_client_id --env GITHUB_OAUTH_CLIENT_ID
lmconn cred set github oauth_client_secret --env GITHUB_OAUTH_CLIENT_SECRET
lmconn oauth authorize github --scope read:user --port 15847
lmconn http request https://api.github.com/user --auth github
```

For a service without a preset, pass `--auth-url` and `--token-url` (plus
`--scope`, `--auth-query`, `--auth-style body`, `--no-pkce`) once; they are
stored and reused on refresh. Resolution order: flag > cred store > preset.
`http request --auth SERVICE` prefers a stored `api_key`, then
`<SERVICE>_API_KEY`, then the stored OAuth token, refreshing it when expired
and a refresh token exists. Configuration and tokens live in `oauth_*`
fields in the credential store. See [OAuth2 in lmconn](docs/oauth2.md) for
all options, headless setup, storage details, and testing scope.

### llm

| Command | Does |
|---|---|
| `llm providers` | every provider with kind (`api` or `cli`), default model and key source (`store`, `env:NAME`, `none`, `missing`) |
| `llm chat <provider> [--model M] [--system S] [--max-tokens N] (--prompt P \| --prompt-file F \| --stdin)` | one completion; result `{text, model, usage, provider}` |
| `llm probe [provider...]` | one live call per provider, reports reachability |

Providers (`src/providers/index.js`): `deepseek`, `openrouter`, `ollama-cloud`
(OpenAI-compatible HTTPS) and `claude`, `codex`, `agy`, `kimi` (agent CLIs on
PATH). Keys resolve from the store first, then the provider's environment
variable (`DEEPSEEK_API_KEY`, `OPENROUTER_API_KEY`, `OLLAMA_API_KEY`).

### http

```
lmconn http request <url> [--method GET|POST|...] [--header "K: V"]...
                    [--data STRING | --data-file PATH] [--auth SERVICE] [--timeout MS]
```

- `--method` defaults to GET, or POST when a body is given.
- `--header` repeats. A body without an explicit Content-Type is sent as
  `application/json` when it parses as JSON, else `text/plain`.
- `--auth SERVICE` sends `Authorization: Bearer <key>`, where the key is
  `cred get SERVICE api_key`, falling back to the environment variable
  `<SERVICE>_API_KEY` (upper-cased, non-alphanumerics become `_`:
  `ollama-cloud` reads `OLLAMA_CLOUD_API_KEY`). No key is `MISSING_KEY`, exit 1.
- `--timeout` defaults to 30000 ms; a timeout is `TIMEOUT`, a connection
  failure `NETWORK`, both exit 1.
- Result: `{status, ok, contentType, latencyMs, url, bodyJson | bodyText}`.
  `ok` is `status < 400`. An HTTP error status is still a successful run
  (exit 0, envelope `ok: true`); inspect `result.ok` and `result.status`.

### github

| Command | Does |
|---|---|
| `github user` | the authenticated user: `{login, name, id, publicRepos, auth}`; needs a token |
| `github repos <org> [--limit N]` | repository names of an organisation (falls back to a user): `{org, count, names, auth}`; `--limit` 1..1000, default 30, pages through `Link` headers |

Token resolution, reported as `auth`: `store` (`cred set github api_key`),
`env:GITHUB_TOKEN` or `env:GH_TOKEN`, `gh` (`gh auth token`), else
`anonymous` (rate limited). Read-only: no write endpoint is exposed.

## Schema module (lmscript)

`schema/lmconn.cli.schema.v1.json` is generated by `npm run schema` and
committed. lmscript imports it and calls operations as functions:

```
import "../schema/lmconn.cli.schema.v1.json";
r = lmconn.github_repos("lmctl-ai", {limit: 5});   # {status:"ok", result:<lmconn envelope>}
```

- Operation names are `<area>_<sub>`: `cred_set`, `cred_get`, `cred_list`,
  `cred_delete`, `cred_path`, `llm_providers`, `llm_chat`, `llm_probe`,
  `http_request`, `github_user`, `github_repos`.
- Params marked `positional` lead (`url`, `org`); the rest go in one options
  map with camelCase keys (`dataFile`, `maxTokens`, `promptFile`).
- lmscript spawns `lmconn <op> --input-json '{"op","params"}'`; `src/schema.js`
  translates that back into the ordinary argv (`lmconn http request URL
  --data-file F`). `--readonly` refuses write operations.
- `r.result` is lmconn's envelope, so a connector failure is
  `r.result.ok == false` with `r.result.error.code`, while a launch problem
  (lmconn not on PATH) is `r.status == "error"` with `r.error.code == "launch"`.
- `lmscript help schema/lmconn.cli.schema.v1.json` prints every operation.

For a command area to appear in the schema it exports `ops`, a list of
cli.schema.v1 operation fragments. Names are normalised (`cred.set` or
`llm chat` become `cred_set`, `llm_chat`; `prompt-file` becomes
`promptFile`), unknown param keys are dropped, and a missing or broken
module is skipped so the document is always valid.

## Examples

`examples/` holds lmscript scripts; run them with `lmscript` (>= 0.2.38)
after `npm link`:

| Script | Shows |
|---|---|
| `examples/llm-chat.lms [provider] [prompt]` | `system(["lmconn","llm","chat",...])` and parsing the envelope with `json_parse` |
| `examples/schema-import.lms [org]` | importing the schema document and calling `lmconn.github_repos`; `--check` and `--dry-run` need neither lmconn nor network |

### Free APIs, no credentials

Each `free-*.lms` script drives a public API through `lmconn http request`,
reads `result.bodyJson`, retries once on 429/5xx and prints a short summary.
Swapping in an authenticated API is one `--auth SERVICE` flag. The coverage
map against n8n's connector categories is in
[docs/n8n-coverage.md](docs/n8n-coverage.md).

| Script | API | Shows |
|---|---|---|
| `free-pokeapi.lms [name]` | pokeapi.co | one GET, nested maps and lists: types, abilities, move count |
| `free-animal-facts.lms` | catfact.ninja, dog.ceo | two independent calls merged into one summary |
| `free-people-data.lms [name]` | agify, genderize, nationalize | one input enriched by three services, top-2 selection |
| `free-fanout.lms` | catfact, ipwho.is, open.er-api, coingecko | four calls in `parallel([...])`, per-call latency against total wall time |
| `free-weather-openmeteo.lms` | api.open-meteo.com | current temperature, wind speed and weather code for coordinates |
| `free-weather-wttr.lms` | wttr.in | URL-encoded city name, current condition as JSON |
| `free-countries.lms [ISO2]` | countries.trevorblades.com | GraphQL POST through `--data`: capital, currency, languages |
| `free-geocode.lms` | nominatim.openstreetmap.org | place name to up to three hits, with the descriptive User-Agent the service requires |
| `free-time.lms` | timeapi.io | encoded timezone query param, datetime and day of week |
| `free-hackernews.lms` | hn.algolia.com | story search with an encoded query, five hits |
| `free-jsonplaceholder.lms` | jsonplaceholder.typicode.com | GET a post, then POST a JSON body (writes are simulated by the API) |
| `free-httpbin.lms` | httpbin.org | custom header sent, echoed method, URL, headers and query inspected |
| `free-dns.lms` | dns.google | DNS over HTTPS, every answer record printed |
| `free-ip.lms` | ipwho.is | this machine's public IP and location |
| `free-coingecko.lms` | api.coingecko.com | USD and EUR prices for a coin |
| `free-fxrates.lms` | open.er-api.com | base currency, update date and four exchange rates |
| `free-arxiv.lms` | export.arxiv.org | non-JSON response: titles and IDs extracted from Atom XML in bodyText |
| `free-openlibrary.lms` | openlibrary.org | three books with first author and first publication year |
| `free-wikipedia.lms` | en.wikipedia.org REST | URL-encoded title, short article extract |

## Testing

`npm test` runs the full OAuth2 flow against `scripts/mock-idp.js`, a
strict mock authorization server (RFC 6749 plus PKCE): exact redirect URI,
one-time codes, S256 verification, header and body client authentication,
RFC error codes, optional refresh-token rotation, and adversarial modes for
a misbehaving provider. No network and no credentials are involved.
`scripts/verify-n8n-oauth.mjs` runs n8n's own OAuth2 client against the
same mock for manual cross-validation, and `examples/oauth-mock-demo.lms`
is an end-to-end demo that needs no credentials. Details in
[docs/oauth2.md](docs/oauth2.md#testing).

## Layout

- `src/main.js` — argument router, `--cli-schema`, schema-call bridge
- `src/result.js` — envelope helpers (`emit`, `ok`, `fail`, `emitFail`)
- `src/creds.js` — SQLite credential store
- `src/providers/` — LLM provider registry and adapters (API + agent CLI)
- `src/cmd-*.js` — command areas (`cred`, `llm`, `http`, `github`), each exporting `run(args)` and `ops`
- `src/schema.js` — cli.schema.v1 generator and `--input-json` bridge
- `schema/` — generated cli.schema.v1 for lmscript import
- `examples/` — lmscript scripts that drive lmconn
- `docs/` — `n8n-coverage.md`, the coverage map against n8n connector categories
- `durable-memory/` — design decisions (start at `durable-memory/index.md`)

See AGENTS.md for the engineering contracts.
