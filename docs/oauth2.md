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

Flags override stored configuration. Store secrets through `cred set --env`
or `--stdin` so they do not appear in command arguments. The configuration
fields are:

| Flag | Stored field | Default |
|---|---|---|
| `--client-id` | `oauth_client_id` | stored value |
| `--client-secret` | `oauth_client_secret` | stored value |
| `--auth-url` | `oauth_auth_url` | stored value |
| `--token-url` | `oauth_token_url` | stored value |
| `--scope` | `oauth_scope` | stored value |
| `--auth-query` | `oauth_auth_query` | stored value |
| `--auth-style` | `oauth_auth_style` | `header` |

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
lmconn oauth authorize github \
  --auth-url https://github.com/login/oauth/authorize \
  --token-url https://github.com/login/oauth/access_token \
  --scope read:user --auth-style body --port 15847

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

## Verification

Tested end-to-end against a mock IdP in `test/oauth.test.js`; real-provider
testing is manual. The GitHub walkthrough requires a user-created OAuth App
and interactive consent and is not a claim of automated GitHub validation.
