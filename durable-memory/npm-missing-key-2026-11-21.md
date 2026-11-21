# npm: a handle with no token is MISSING_KEY, also in broker mode (2026-11-21)

Contract with lmauth: `lmauth publish --login` runs `lmconn npm whoami --credential lmauth:NAME` first and starts npm's web login only when the error code is `MISSING_KEY` or `NPM_FAILED`. Any other code stops it with `login_check_failed`, before any page is shown.

Bug (fixed in 4f5b14e): `tokenFor` in src/cmd-npm.js called `authorizeOrigin` before looking for a token. In broker mode a handle that was never stored has no credential policy, so `authorizeOrigin` threw `CREDENTIAL_POLICY` ("Broker mode requires a protected credential"). Every first-time `lmauth publish --login` therefore failed. Found while publishing @lmctl-ai/lmwebtest 0.1.73.

Rule now: no token stored for the handle gives `MISSING_KEY`; a stored token whose policy does not allow the registry origin still gives `CREDENTIAL_POLICY` (the "ancestor project config" test keeps that). Test: "whoami on a handle with no token is MISSING_KEY in broker mode" in test/npm.test.js.

Operators run lmauth against a private copy of lmconn (~/.lmauth-trusted/lmconn); after a fix here, refresh that copy, or lmauth keeps the old behaviour.
