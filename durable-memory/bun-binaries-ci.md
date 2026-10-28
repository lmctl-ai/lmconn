# Bun-compiled binaries and CI (2026-10-28)

lmconn ships as a single-file executable per OS, built with
`bun build --compile`, so users do not need Node installed. The pipeline
(`.github/workflows/ci.yml`) is: push -> `node --test` on
ubuntu/macos/windows -> bun cross-compile for linux-x64, linux-arm64,
darwin-x64, darwin-arm64, windows-x64 -> smoke test of each binary on a
native runner -> GitHub Release. Master pushes refresh the rolling `latest`
prerelease (the `latest` tag is force-moved); `v*` tags produce versioned
releases.

## Why the source had to change for `bun build --compile`

A compiled binary bundles the modules the bundler can see statically and
runs them from a virtual filesystem (`/$bunfs`). Two idioms that are fine
under Node break inside the binary:

- `readFileSync(new URL('../package.json', import.meta.url))` fails with
  ENOENT. The fix is a JSON import attribute
  (`import pkg from '../package.json' with { type: 'json' }`), which Node
  >= 22.5 supports and the bundler embeds, so `--version` is baked in
  correctly at compile time.
- ``await import(`./cmd-${area}.js`)`` is invisible to the bundler, so the
  binary shipped zero command areas (every area reported NOT_IMPLEMENTED
  and `--cli-schema` listed no operations). The fix is `AREA_LOADERS` in
  `src/schema.js`: literal-path `import()` arrows per area, which the
  bundler includes. `collectOps` still accepts a custom `resolve` for
  tests; that path stays dynamic and only runs under Node.

`node:sqlite` (the credential store) works inside the compiled binary
unmodified — verified in the smoke test's cred set/get/list/delete
round-trip.

## Cross-platform process spawning

The CLI provider adapter (`src/providers/cli.js`) used to spawn providers
with `cwd: '/tmp'`, which does not exist on Windows and resolves to
`/private/tmp` on macOS; it now uses `os.tmpdir()`. Tests spawn their
fixtures through `process.execPath` because a bare `.cjs` file is not
executable on Windows, and compare `process.cwd()` against
`realpathSync(tmpdir())` because macOS tmp paths contain symlinked
segments (`/var` -> `/private/var`).

## The smoke test is the binary's contract check

`scripts/smoke.js` runs under bun on each native runner and asserts the
same contracts as the node test suite, end to end through the compiled
binary: one JSON envelope on stdout, exit codes, the sqlite cred
round-trip without leaking the secret, all 11 cli.schema.v1 operations,
and the version matching `package.json`. Add a check there when adding an
operation.
