# lmconn integration coverage (2026-10-29)

Reviewed lmconn master 9ee5adf and lmmock main 989a4c5. The lmconn checkout
is historically named `lmconnectors`; its executable and public repo are `lmconn`.

| lmconn area | Integration coverage |
| --- | --- |
| cred | Temporary SQLite store: set/get/list/delete and secret handling; no server needed |
| http | lmmock connector-http: methods, headers, bodies, stored bearer auth, refresh, timeouts, disconnects, invalid JSON, HTTP errors |
| oauth | lmmock OAuth: authorization code, header/body client authentication, PKCE, refresh rotation, replay, state mismatch and failure modes |
| github | Added real loopback requests through the existing injected fetch dependency: strict headers, user, anonymous repos, pagination, organization-to-user fallback, 401/403/404/500 and invalid lists |
| llm | lmmock OpenAI-compatible adapter: requests, response parsing, deadlines, credential redaction, 401/429/503, malformed JSON and disconnects; CLI providers use fake executables |

The added service-mocks tests run the actual lmconn HTTP CLI against all 131
steps in the Slack, Discord, Telegram, Jira, Stripe, Notion, Airtable, HubSpot,
GitLab, Asana and Trello contract suites. These
include vendor-specific auth shapes, stateful operations and error responses.
A successful HTTP command envelope does not imply a successful vendor operation:
assertions also check HTTP status and response JSON (e.g. Slack HTTP 200 with
`ok:false`). Only synthetic credentials and loopback endpoints are used.

## Functionality still absent from lmconn

The actual command router exposes only cred, http, oauth, github and llm.
Redis, MQTT, SMTP, IMAP, Postgres, MongoDB, AMQP and Kafka mocks now exist in
lmmock, but lmconn itself has no client command areas for these protocols.
Their Go protocol-driver tests run in lmmock Actions; those are not lmconn
connector tests. Sibling tools may supply these clients independently.

Other gaps: OAuth 1.0a signing; OAuth2 client-credentials grant; webhook/trigger
receivers and HMAC verification; named per-service operations other than GitHub.
HTTP `--auth` automatically injects Bearer only: Basic, custom header, query
and path tokens must be explicitly assembled by the caller. The n8n matrix's
“covered generically” must not be interpreted as automatic credential injection
for all 277 non-OAuth credentials or tested compatibility with all services.

The three API LLM providers (deepseek, openrouter, ollama-cloud) share the tested
OpenAI-compatible adapter. Provider-specific live behavior is not verified by
local mocks. The four CLI providers (claude, codex, agy, kimi) are subprocess
adapters, not HTTP clients. The 69 OAuth presets are endpoint configuration;
local OAuth tests verify the shared grant implementation, not each live vendor.

## Running in Actions or locally

In lmconn, install `npm i -g @lmctl-ai/lmctl`, put the checksum-verified lmmock
release on PATH (or set LMMOCK_BIN), then run `lmscript --no-preflight test.lms`.
`lmctl test.lms` is also supported. Actions executes this on Linux, macOS and
Windows before building/publishing. No external service credentials are needed.
Fixtures are vendored from a committed lmmock revision with SHA-256 hashes;
`scripts/sync-lmmock.mjs --check` rejects local drift before tests run.
