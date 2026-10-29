# Strict mock identity provider (2026-10-28)

`scripts/mock-idp.js` is the shared test oracle for lmconn's OAuth2 client.
This page records why it is strict, how the misbehave modes work, and why
the demo follows the authorize redirect itself.

## Why strict beats permissive

A mock that accepts whatever the client sends falls into the
self-consistency trap: the client is written by us, the fake is written by
us, and the two agreeing proves only that we were consistent with ourselves.
Every real OAuth2 bug lives in the gap between what a client sends and what
a provider demands: a redirect URI that differs by a trailing slash, a code
replayed after a retry, a PKCE verifier that was base64 instead of
base64url, client credentials put in the body when the provider wants
HTTP Basic. A permissive fake hides all of these.

The mock therefore enforces the specification as a provider would: exact
`redirect_uri` match at both endpoints, one-time codes with a 60 second
life bound to the requesting client, S256 verification with the verifier
length rule, the registered client-authentication style and nothing else,
constant-time secret comparison, and the RFC 6749 error vocabulary with
the right HTTP status codes.

Strictness buys a second implementation for free. n8n's OAuth2 client is
mature, widely used, and not ours. If it completes the flow against the
mock (`scripts/verify-n8n-oauth.mjs`) and lmconn completes the flow against
the mock, both agree with an independent reading of the specification. A
lenient mock could not be used this way, because n8n passing against it
would say nothing.

## The misbehave-mode pattern

Providers are not always right either, and a client must fail safely when
they are wrong. Rather than a second mock, `createMockIdP` takes a
`misbehave` option that turns one deviation on at a time:

| Mode | Deviation | What the client must do |
|---|---|---|
| `bad-state` | the redirect carries a tampered `state` | refuse to exchange the code; no token request may appear in `idp.log` |
| `bad-json` | truncated token body | a clean envelope error, no crash, no partial state stored |
| `string-expires` | `expires_in` as a string (real providers do this) | still compute a valid `oauth_expires_at` |

Alongside these, ordinary options model legitimate provider variation:
`rotateRefreshTokens`, `formEncodedTokenResponse`, `requirePkce`,
`allowPlainPkce`, `expiresIn`. One server, one deviation per test, named
in the test title, is easier to read and extend than a family of fakes.
`test/oauth-adversarial.test.js` is the suite built on this pattern.

`idp.log` keeps the pattern honest: every request is recorded with codes,
refresh tokens and secrets redacted, so a test can assert "no `/token`
call happened" without the log ever holding a secret.

## Auto-follow: why the demo needs no browser

The mock has no consent page. `/authorize` validates the request and
answers 302 immediately. That makes the authorization-code flow runnable
end to end by a program: fetch the authorize URL that `lmconn oauth
authorize` prints to stderr, do not follow the redirect blindly, read its
`Location`, and GET that URL, which is lmconn's own loopback callback. The
runnable demo `examples/oauth-mock-demo.lms` does this, and the standalone
`node scripts/mock-idp.js --once` exits a few seconds after the first grant
so the demo cleans up after itself.

This is a property of the mock, not a shortcut in the client: lmconn's
`authorize` still generates `state` and the PKCE verifier, still checks
`state` on the callback, and still exchanges the code at the token endpoint
with the registered client-authentication style. The only thing automated
is the human click. Against a real provider the same command prints the
same URL and waits for a browser.

## Status at writing

`scripts/mock-idp.js` and `test/oauth.test.js` are on master.
`test/oauth-adversarial.test.js`, `scripts/verify-n8n-oauth.mjs` and
`examples/oauth-mock-demo.lms` were being written in parallel against the
pinned interface above; this page describes their intent, and the files
themselves are authoritative once landed.
