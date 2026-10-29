# OAuth2 in lmconn

OAuth2 configuration is data attached to a service in the existing SQLite
credential store. `lmconn oauth authorize` obtains tokens, `oauth refresh`
renews them, and `http request --auth SERVICE` uses them without putting
secrets in scripts or output.

## What we learned from n8n

The n8n source models an OAuth2 credential with `authUrl`, `accessTokenUrl`,
`scope`, `grantType` (`authorizationCode`, `clientCredentials`, or `pkce`),
`authQueryParameters`, and `authentication` (`header` or `body`). For example,
Google's extra authorization parameters can be
`access_type=offline&prompt=consent`. Provider differences belong in these
values rather than a separate connector implementation for every service.

n8n stores the token response and computes `n8n_expires_at` as
`Date.now() + expires_in * 1000`. Refresh preserves the previous
`refresh_token` if the provider omits a replacement. `invalid_grant` means
that the user must reconnect. PKCE uses a verifier from 32 random bytes,
base64url encoded, and an S256 challenge: base64url of the verifier's SHA-256
hash. A random `state` binds the redirect to the initiating request and
protects against CSRF.

lmconn implements authorization-code exchange with PKCE by default and the
refresh-token grant. This does not implement every n8n grant: automatic
client registration, client-credentials grants, and OAuth 1.0a are outside
this flow. Refresh runs in the calling CLI process; there is no single-flight
lease across concurrent processes.

## Authorize a service

```sh
lmconn oauth authorize SERVICE [--client-id ID] [--client-secret SECRET] \
  [--auth-url URL] [--token-url URL] [--scope SCOPE] \
  [--auth-query QUERY] [--auth-style header|body] \
  [--port N] [--timeout MS] [--no-pkce] [--manual]
```

Flags override stored configuration, which overrides the built-in vendor
preset. `src/oauth-presets.json` holds the endpoints, scopes and quirks of
69 services, mined from n8n's credential definitions by
`scripts/extract-n8n-oauth-presets.mjs`; with a preset service only
`oauth_client_id` and `oauth_client_secret` must be supplied. Store secrets
through `cred set --env` or `--stdin` so they do not appear in command
arguments. The configuration fields are:

| Flag | Stored field | Default |
|---|---|---|
| `--client-id` | `oauth_client_id` | preset, else stored value |
| `--client-secret` | `oauth_client_secret` | stored value |
| `--auth-url` | `oauth_auth_url` | preset, else stored value |
| `--token-url` | `oauth_token_url` | preset, else stored value |
| `--scope` | `oauth_scope` | preset, else stored value |
| `--auth-query` | `oauth_auth_query` | preset, else stored value |
| `--auth-style` | `oauth_auth_style` | preset, else `header` |

`--auth-query` is an extra URL query string, for example
`--auth-query 'access_type=offline&prompt=consent'`. `header` authenticates
the token request with HTTP Basic (base64 of `client_id:client_secret`);
`body` puts the client fields in the form body.

The command listens on `127.0.0.1`, at `/callback`. `--port` defaults to `0`
(an ephemeral port); use a fixed port when registering a fixed callback URL.
The redirect URI is `http://127.0.0.1:<port>/callback`. The timeout defaults
to 300000 ms. Open the authorization URL printed to **stderr**, sign in, and
approve the requested scope. The callback checks `state` before exchanging
the code at the token URL with `grant_type=authorization_code`, the code,
redirect URI, and PKCE verifier. `--no-pkce` disables PKCE for a provider that
requires that compatibility option; state validation still applies.

For a headless machine, add `--manual`. Open the printed authorization URL
in a browser and paste the full redirect URL into the waiting command's
stdin. If the browser is on another machine, its loopback redirect may fail
to load; copy the complete URL from its address bar. Keep the CLI running
while doing this so its state and verifier remain available.

On success, stdout contains one JSON envelope whose result is
`{service, expiresAt, hasRefreshToken, scope}`. Tokens are never printed.
Usage failures exit 2, runtime failures exit 1, and success exits 0.

## Storage, status, and refresh

All configuration and token state uses `oauth_*` fields on the service in
the existing SQLite credential table. Alongside the configuration above,
authorization stores `oauth_access_token`, `oauth_refresh_token` if returned,
`oauth_expires_at` (an ISO timestamp computed from `expires_in`), and
`oauth_token_type`. The database defaults to `~/.lmconnectors/creds.db`;
`LMCONN_DB` overrides it. `cred list` shows names and timestamps, not values.

```sh
lmconn oauth status SERVICE
lmconn oauth refresh SERVICE
```

Status is read-only and returns
`{service, authorized, expiresAt, expired, hasRefreshToken, scope, tokenUrl}`.
It never returns a token. Authorization presence does not itself prove that
the provider still accepts the token. A provider may omit expiry or refresh
information; inspect status instead of assuming every token is renewable.

Refresh posts `grant_type=refresh_token` using the stored client auth style,
updates the access token and expiry, and retains the old refresh token when
the response omits a new one. An `invalid_grant` response maps to error code
`RECONNECT`: run `oauth authorize` again.

For `lmconn http request URL --auth SERVICE`, resolution is:

1. Stored `api_key`.
2. Environment `<SERVICE>_API_KEY` (uppercase, non-alphanumerics become `_`).
3. Stored `oauth_access_token`, refreshed first when expired and a refresh
   token exists.

The selected token is sent as a Bearer token. Existing API keys take
precedence over OAuth; this does not change LLM provider key resolution.
HTTP results keep the same envelope and `result.status`, `result.ok`, and
`bodyJson` or `bodyText` fields.

## GitHub walkthrough

Create an **OAuth App** in GitHub Settings → Developer settings → OAuth Apps.
Set its authorization callback URL to `http://127.0.0.1:15847/callback` and
copy its client ID and client secret. This walkthrough uses GitHub's
[OAuth App authorization flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
with PKCE and client credentials in the token request body.

In Bash, read the values without writing the secret into shell history:

```sh
read -r -p 'GitHub OAuth client ID: ' GITHUB_OAUTH_CLIENT_ID
read -r -s -p 'GitHub OAuth client secret: ' GITHUB_OAUTH_CLIENT_SECRET
printf '\n'
export GITHUB_OAUTH_CLIENT_ID GITHUB_OAUTH_CLIENT_SECRET

lmconn cred set github oauth_client_id --env GITHUB_OAUTH_CLIENT_ID
lmconn cred set github oauth_client_secret --env GITHUB_OAUTH_CLIENT_SECRET
lmconn oauth authorize github --scope read:user --port 15847

lmconn oauth status github
lmconn http request https://api.github.com/user --auth github \
  --header 'Accept: application/vnd.github+json'
unset GITHUB_OAUTH_CLIENT_ID GITHUB_OAUTH_CLIENT_SECRET
```

Open the URL printed by `authorize`, then approve access. Successful
authorization persists the supplied configuration for subsequent runs.
For headless use, add `--manual` to the authorization command. The HTTP
response's `result.bodyJson.login` identifies the authenticated user;
check both envelope `ok` and `result.ok`. A pre-existing `github api_key`
or `GITHUB_API_KEY` takes precedence, so use a store/environment without
those entries when verifying the OAuth path.

Run `lmscript examples/oauth-github.lms` for the example. It skips cleanly
until GitHub OAuth authorization is available.

## Testing

OAuth2 clients are easy to test wrongly: a permissive fake server accepts
whatever the client sends, so client and fake agree with each other and prove
nothing. lmconn tests against `scripts/mock-idp.js`, a strict mock
authorization server (RFC 6749 plus PKCE, RFC 7636) that is strict enough
for n8n's own OAuth2 client to be run against it as a second implementation.
It uses Node built-ins only and is not shipped in the compiled binary.

### What the mock validates

- `redirect_uri` must match one of the registered URIs exactly, both at
  `/authorize` and again at `/token`.
- Authorization codes are one-time and expire after 60 seconds; a reused or
  expired code is `invalid_grant`.
- The code is bound to the client that requested it; another client
  exchanging it gets `invalid_grant`.
- PKCE: `code_challenge_method` must be `S256` (`plain` only with
  `allowPlainPkce`); the verifier must be 43 to 128 characters and hash to
  the stored challenge; `requirePkce` turns a missing challenge into
  `invalid_request`.
- Client authentication per registration: `header` (HTTP Basic),
  `body` (form fields) or `both`; the wrong style, an unknown client or a
  bad secret is `invalid_client` with HTTP 401. Secrets compare in constant
  time.
- RFC 6749 error bodies: `invalid_request`, `invalid_client`,
  `invalid_grant`, `unsupported_grant_type`, `unsupported_response_type`
  (the last one bounced to the redirect URI with the original `state`).
- Refresh: `grant_type=refresh_token` with the stored client; with
  `rotateRefreshTokens` the old refresh token is revoked and a new one
  issued, otherwise the response repeats the old one, which is what most
  providers do and what the client must handle in both forms.
- Token responses are JSON by default or form-encoded with
  `formEncodedTokenResponse` (GitHub's default).
- `/api/userinfo` requires a valid Bearer token and answers 401 with a
  `WWW-Authenticate` header otherwise, so `http request --auth` can be
  exercised end to end.
- `idp.log` records every request as `{method, path, params, authStyle}`
  with codes, refresh tokens and secrets redacted, so tests can assert on
  what the client sent without ever holding a secret.

There is no consent page: `/authorize` validates and redirects at once.
That is what makes the flow runnable without a browser.

### Three roles

1. **Unit-test oracle**: `test/oauth.test.js` starts one mock per test on an
   ephemeral port, registers a client with the loopback redirect URI, runs
   `oauth authorize`, `refresh` and `status` through `run()` and asserts on
   the stored `oauth_*` fields, the envelopes and `idp.log`. It covers S256
   verification, state mismatch, body-style client auth, form-encoded token
   responses, retained refresh tokens, `invalid_grant` to `RECONNECT`,
   `--manual`, `--no-pkce`, timeouts and secret-free error messages.
2. **Adversarial oracle**: `test/oauth-adversarial.test.js` checks that
   lmconn fails safely, or degrades correctly, when the provider deviates:
   `expires_in` as a numeric string (real providers send this) still gives
   a finite future expiry; an omitted `expires_in` clears stale expiry and
   `status` reports `null`; unknown token-response fields are tolerated and
   never leak into metadata; HTTP 500 from the token endpoint becomes a
   sanitized `OAUTH_ERROR`; an empty scope is preserved; and the mock's
   `misbehave` modes `bad-state` (tampered `state` on the redirect) and
   `bad-json` (truncated token body) each produce `OAUTH_ERROR` with no
   token stored and no secret in the message. Every scenario runs with
   `requirePkce`. The remaining knobs (`string-expires`,
   `rotateRefreshTokens`, `formEncodedTokenResponse`, `allowPlainPkce`)
   are where this suite grows.
3. **Cross-validation target for n8n**: `scripts/verify-n8n-oauth.mjs`
   drives a headless n8n (2.45.4, `n8n` on PATH) against the same mock
   through n8n's REST API: owner setup, create an `oAuth2Api` credential,
   fetch n8n's authorization URL, GET `/authorize` without following
   redirects, then GET n8n's callback with the session cookie. Success
   requires n8n's success page and exactly one authorize and one token
   request with header client auth and HTTP 200 from the strict token
   endpoint. If n8n's client completes the flow and lmconn's client
   completes the flow against the same server, the two implementations
   agree with the mock independently, which is the evidence a self-written
   fake cannot give. It is a manual script, not part of `npm test`: n8n is
   a separately installed prerequisite, it needs free loopback ports 5556,
   5678 and 5679, uses a fresh `N8N_USER_FOLDER`, and never prints cookies,
   URLs, codes or tokens. The mock runs as a child process so only redacted
   observations cross the IPC boundary.

### Zero-credential demo

`examples/oauth-mock-demo.lms` runs the whole thing from lmscript with no
real credentials: it starts the mock on port 5557 in parallel with the
client flow, authorizes with `--auto-follow`, inspects `status`, calls
`/api/userinfo` through `http request --auth`, and exits 0. Run it from the
repo root with ports 5557 and 5558 free.

`--auto-follow` makes `oauth authorize` fetch the authorization URL itself,
following redirects, so the mock's immediate 302 lands on lmconn's own
loopback callback with no browser involved. It is mutually exclusive with
`--manual` and exists for demos and mock tests only: `state` and PKCE are
still generated and verified, and a real provider would answer the fetch
with a login page, never the callback, so the command reports
`OAUTH_ERROR` instead of a token.

```sh
node scripts/mock-idp.js --port 5556 --once   # demo-client / demo-secret, exits 3 s after the first grant
lmconn oauth authorize mockdemo --client-id demo-client --client-secret demo-secret \
  --auth-url http://127.0.0.1:5556/authorize --token-url http://127.0.0.1:5556/token \
  --scope demo --port 5558 --auto-follow
lmconn http request http://127.0.0.1:5556/api/userinfo --auth mockdemo
```

### What stays manual

Real providers need a browser login, a per-person client registration and
account state that CI cannot own. The GitHub walkthrough above is therefore
a documented procedure, not an automated claim. The mock covers the
protocol; the presets in `src/oauth-presets.json` carry the per-provider
endpoints and quirks; the remaining risk is a provider deviating from both,
which only a manual run against that provider reveals.
