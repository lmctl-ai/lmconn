# n8n coverage map

n8n ships 400+ connector nodes. lmconn is one CLI with five command areas.
This page states honestly what is covered today, what the generic path
covers, and what is missing. Status as of 2026-10-28. For the per-service
denominator mined from the installed n8n package, see
[n8n-connector-matrix.md](n8n-connector-matrix.md) (regenerate with
`node scripts/n8n-coverage-matrix.mjs`).

## Categories

| n8n connector category | Typical nodes | lmconn today | How |
|---|---|---|---|
| AI / LLM | OpenAI, Anthropic, Ollama, OpenRouter, DeepSeek | Covered: 7 providers (claude, codex, agy, kimi via agent CLIs; deepseek, openrouter, ollama-cloud via OpenAI-compatible HTTPS) | `lmconn llm chat`, `llm providers`, `llm probe` |
| Developer tools | GitHub, GitLab, Jira, Bitbucket | GitHub read-only (`user`, `repos`); the rest through the generic path | `lmconn github`, `lmconn http request --auth` |
| Communication | Slack, Discord, Telegram, Email | Generic path only (REST calls with a stored token) | `http request --auth slack --data ...` |
| CRM | HubSpot, Salesforce, Pipedrive | Generic path only | `http request --auth hubspot` |
| Databases | Postgres, MySQL, MongoDB, Redis | Not covered (not HTTP; needs drivers) | planned `src/cmd-<db>.js` or an HTTP gateway |
| Files / storage | S3, Dropbox, Google Drive | Generic path for REST storage APIs; no multipart upload helper | `lmconn oauth authorize` handles the flow; `http request --auth` uses the token |
| Marketing | Mailchimp, SendGrid, Brevo | Generic path only | `http request --auth sendgrid --data` |
| Productivity | Notion, Airtable, Google Sheets, Trello | Generic path for token-based and OAuth2 APIs | `lmconn oauth authorize` handles the flow; `http request --auth` uses the token |
| Social | Twitter/X, LinkedIn, Reddit | Generic path where a bearer token works; OAuth 1.0a signing not supported | `http request --auth` |
| Finance | Stripe, PayPal, exchange rates, crypto | Generic path; see `free-fxrates.lms`, `free-coingecko.lms` | `http request` |
| Weather / geo | OpenWeather, Open-Meteo, geocoding | Generic path; see `free-weather-openmeteo.lms`, `free-weather-wttr.lms`, `free-geocode.lms`, `free-countries.lms` | `http request` |
| Misc / utility | HTTP Request, Set, Merge, Code, Wait, Cron, Webhook | HTTP Request = `lmconn http request`; Set/Merge/Code = lmscript itself; Wait = `sleep_ms`; parallel branches = `parallel([...])`; Cron and Webhook: not in lmconn (see gaps) | lmscript + `http request` |

Shared across every row: the SQLite credential store (`lmconn cred`), the
one-line JSON envelope, exit codes 0/1/2, and the cli.schema.v1 module that
lets lmscript call any operation as a function.

## The architectural claim

About 90% of n8n connector nodes are authenticated HTTPS calls to a REST
API, followed by a little field mapping. lmconn covers that class
generically today:

- `lmconn http request <url> --method --header --data --auth SERVICE`
  performs the call; `--auth` injects `Authorization: Bearer <key>` from
  a stored `api_key`, then `<SERVICE>_API_KEY`, then a stored OAuth2 token
  with automatic refresh when expired and renewable, so the secret never
  appears in the script or on stdout.
- lmscript does the mapping, branching and merging that n8n spreads across
  Set, IF, Merge and Code nodes, and `parallel([...])` runs branches
  concurrently rather than one node after another.

The `examples/free-*.lms` series demonstrates this with public APIs that
need no credentials: one call (`free-pokeapi.lms`), two or three merged
calls (`free-animal-facts.lms`, `free-people-data.lms`) and a four-way
parallel fan-out (`free-fanout.lms`, which prints per-call latency against
total wall time). Swapping a free API for an authenticated one adds exactly
one flag, `--auth SERVICE`, after storing an API key or completing
`lmconn oauth authorize SERVICE`. See [OAuth2 in lmconn](oauth2.md).

## Honest gaps

- OAuth2 authorization-code/PKCE and refresh are covered, but there is no
  automatic client registration or OAuth 1.0a support. Token refresh is
  single-process CLI work, with no single-flight lease across processes;
  concurrent refreshes of a rotating token can race. Client-credentials
  grants are not implemented.
- No dedicated per-service operations beyond GitHub. Convenience ops such
  as "post a Slack message" or "create a Notion page" are a URL and a JSON
  body in the script today, not a named operation with validated params.
- No webhook or trigger server. n8n starts workflows from incoming HTTP
  calls; lmconn is a CLI. Schedules and polling belong to lmscript (or
  system cron running an lmscript), and an inbound webhook needs a separate
  receiver that invokes the script.
- Non-HTTP protocols (SQL databases, SMTP/IMAP, FTP, message queues) are
  not covered by the generic path.
- Signed request schemes (AWS SigV4, OAuth 1.0a, HMAC webhooks) are not
  implemented; only bearer tokens and arbitrary static headers are.

## Where to add a dedicated connector

Per AGENTS.md: one file `src/cmd-<area>.js` exporting `async run(args)` and
`ops` (cli.schema.v1 operation fragments, names `<area>_<sub>`, params with
`positional: true` where the CLI takes a positional argument), credentials
through `getCred(service, field)` in `src/creds.js`, tests in
`test/<area>.test.js` with network stubbed, then `npm run schema` to
regenerate `schema/lmconn.cli.schema.v1.json`. `src/cmd-github.js` is the
template: injectable `fetch` and `exec`, read-only first, token source
reported but never the token.
