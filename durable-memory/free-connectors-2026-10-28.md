# Free-API example wave (2026-10-28)

The second wave added `examples/free-*.lms`: nineteen lmscript workflows
that drive public APIs through `lmconn http request`, plus
`docs/n8n-coverage.md`, the coverage map against n8n's connector categories.

## Why free, credential-less APIs

- Anyone can run them from a checkout: `npm link`, then
  `lmscript examples/free-pokeapi.lms`. No signup, no key, nothing to leak.
- They exercise the generic path, which is the architectural claim of the
  project: most n8n connector nodes are HTTPS calls plus field mapping, and
  lmscript plus `lmconn http request` covers that class without a
  per-service node. An authenticated API differs by one flag, `--auth
  SERVICE`, after `lmconn cred set SERVICE api_key`.
- They double as live smoke tests of the http connector (JSON parsing,
  latency, status handling, retries) against real servers with real quirks.

## Conventions the wave fixed

- Header block copied from `llm-chat.lms`: `# Chapter`, `# Shows`, `# Run`,
  `# Needs` (saying "no credentials"), `# exit: 0`.
- `ARGV.get(i, default)` for parameters; `system([...], timeoutMs)` with an
  argv list, never a shell string; `json_parse(r.stdout)`; check `env.ok`
  and print `error.code: message` then `exit(1)`.
- `which("lmconn") == null` prints SKIPPED and exits 0, so docs tests pass
  on machines without the CLI.
- Public APIs rate-limit and fail: on 429 or 5xx the scripts retry once
  after `sleep_ms(3000)`.
- Lists are appended with `push(list, item)`; `list + [x]` coerces to a
  string in lmscript 0.2.x, a trap found while writing `free-people-data`.

## What the fan-out demonstrates

`free-fanout.lms` calls four services (catfact.ninja, ipwho.is,
open.er-api.com, api.coingecko.com) inside `parallel([...])`, the idiom from
`lmscript/24-cli-fanout.lms`. Results come back in input order; each carries
the envelope's `latencyMs`, and the script prints the total wall time next
to the sum of latencies. A typical run shows about 1.3 s wall time for
roughly 2 s of summed latency. In n8n the same workflow is four HTTP
Request branches and a Merge node executed sequentially. The helper in that
script never calls `exit`, so every branch is reported even when one fails;
the script exits 1 only after printing all four.

## Free APIs die; pick replacements with the same shape

Integration testing the same day found three of the chosen services already
unusable from our egress IP or entirely retired, and the fixes set the
replacement policy: same example, same shape, different provider.

- WorldTimeAPI returns ECONNRESET on every request (dead service);
  `free-time.lms` moved to timeapi.io, same no-key model, JSON body.
- restcountries.com retired its keyless v3.1 (HTTP 200 with a deprecation
  payload, then a 301 to a legacy stub); `free-countries.lms` moved to the
  countries.trevorblades.com GraphQL endpoint, which also turned the example
  into the GraphQL-via-`--data` demo n8n needs a dedicated node for. Build
  the JSON body with `json_stringify({query: ...})`, never string
  concatenation — inner quotes break hand-built JSON.
- ipapi.co and the agify/genderize/nationalize family enforce small per-IP
  daily quotas; a shared egress IP burns them before noon. `free-ip.lms`
  moved to ipwho.is. `free-fanout.lms` also dropped agify for ipwho.is: the
  flagship demo should be green on any egress IP. `free-people-data.lms`
  keeps the quota'd services on purpose: it demonstrates the retry path and
  fails with a clear 429 message when the quota is spent.
