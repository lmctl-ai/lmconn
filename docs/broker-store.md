# Operator-only broker credential storage

`cred store SERVICE --stdin` is the write-only import for lmauth. It accepts a verified/approved grant and returns the existing envelope with `{provider, handle, kind, stored}`. It does not verify grants or convert human attestation into provider evidence. The caller chooses a unique, broker-owned service name, such as `lmauth:SESSION_HANDLE`; the service string is a reference, not caller authentication.

Run the trusted binary under the operator principal with a dedicated absolute `LMCONN_DB` and `LMCONN_STORE_MODE=broker`. Write the JSON from private process memory over stdin, never argv/environment, a shell heredoc/history entry, logs or a model-facing JSON request. No token appears in the receipt. Examples below contain placeholders, not a command to paste live credentials into a shell.

PAT / other Bearer grant:

```json
{
  "kind": "bearer",
  "accessToken": "PRIVATE_BYTES_FROM_THE_BROKER",
  "scopes": ["repo:requested-scope"],
  "owner": "verified-or-explicitly-attested-account",
  "source": "lmauth/wp318",
  "issuer": "https://github.com",
  "allowedOrigins": ["https://api.github.com"]
}
```

OAuth2 uses `kind: "oauth2"` and may additionally include `refreshToken`, `expiresAt` (a real known timestamp, otherwise omit/null), and an explicitly bound refresh configuration:

```json
{
  "tokenUrl": "https://issuer.example/oauth/token",
  "clientId": "registered-client-id",
  "clientSecret": "PRIVATE_IF_REQUIRED",
  "authStyle": "body"
}
```

That object is the optional `refresh` member of the grant. `authStyle` is `header` or `body` (default `header`). A grant without it has no refresh authority, even if the same service once had OAuth configuration. Issuer is an HTTPS URI without userinfo/query/fragment; allowedOrigins is a nonempty array of origins without paths/query/userinfo/fragments. Literal `127.0.0.1` / `[::1]` HTTP is accepted for local fixtures. Public cleartext HTTP and numeric/DNS aliases for loopback are rejected. Bindings are canonicalized; rotation of an existing protected handle must preserve issuer, account, kind, origins and refresh client/endpoint identity. Use a new service for a different identity or authority.

No-reveal is persistent in an internal policy table, separate from the compatible `creds` table. Unsetting broker mode does not unlock a protected entry. `cred get SERVICE FIELD --reveal`, including `cred_get --input-json ...` and `--readonly` routes, refuses protected entries. Legacy `cred set` / `cred oauth-store` and interactive OAuth authorization cannot overwrite/downgrade them. Deleting token fields does not delete the protection policy. There is no CLI unprotect/export command. A matching `cred store` can rotate a grant atomically.

In broker mode, legacy imports/writes and reveal of ANY entry are refused; only protected handles may authenticate HTTP requests. Generic GitHub and LLM adapters cannot consume protected handles in either mode. Unknown mode names fail closed. Metadata is available via `oauth status SERVICE`, `oauth list`, credential presence and listing. PAT/Bearer imports appear in status/list too.

`http request URL --auth SERVICE` checks the exact destination origin before credential resolution or refresh. A protected request returns receipt metadata only: status, ok, latencyMs, the original origin, contentType=null, bodyOmitted=true. It cancels the response body; it never returns arbitrary server strings, echoed bodies or final redirect URLs. Redirects are followed manually; Authorization/Proxy-Authorization/Cookie are removed on a cross-origin hop and never restored implicitly, even if a later hop returns to an allowed origin. A separate explicit request is needed to authenticate another allowed origin. Redirect cycles fail. This is not a general provider-result API: add reviewed typed adapters/allowlisted results for additional broker operations rather than returning arbitrary authenticated HTTP bodies.

## Legacy compatibility and its explicit limits

Existing commands and schema operations remain. The new operation is additive. `cred oauth-store SERVICE --stdin` still accepts its old OAuth2 input and returns the same receipt. It now clears stale client/issuer configuration and api_key atomically; refresh requires newly configured identity. It creates a legacy entry. Legacy authenticated HTTP pins its first explicitly requested origin (TOFU); later HTTP calls to another origin fail. Existing API-key precedence remains for legacy entries. Use `cred store` for explicit pre-bound authority; broker mode never uses TOFU/environment-key fallback.

Outside broker mode, **`cred get SERVICE FIELD --reveal` (or its schema-call equivalent) still reveals fields of LEGACY entries**. `cred set --value`, `cred set --env`, and `oauth authorize --client-secret` remain legacy compatibility inputs: argv/environment/history exposure is not private intake. Use private stdin/configuration instead. Legacy HTTP still returns bodies with known raw/percent/Base64 credential redaction; arbitrary custom encodings cannot be promised secret-free. None of those compatibility paths is the lmauth broker interface.

## Storage boundary and platforms

On Unix, the dedicated store directory must belong to the effective uid; owned loose modes are repaired to 0700. Ancestors must be trusted and non-writable by other principals, except sticky shared ancestors such as /tmp. Root-owned system symlinks used by macOS are accepted; user-controlled directory links, database symlinks/hardlinks, and journal/WAL/SHM symlinks are refused. Files are opened no-follow, checked for owner/type/inode identity and set to 0600. The owner-only directory protects check/open intervals against other users. Cached connections recheck identity. Errors fail closed rather than treating chmod as best effort.

Windows **protected/broker stores fail closed with STORE_SECURITY**, including a protected database copied from Unix, until native owner/DACL enforcement is implemented and tested. Legacy Windows commands remain compatible and depend on the caller's OS ACLs; they are not a certified private broker store. Do not substitute legacy mode to bypass this refusal.

SQLite uses secure_delete=ON and DELETE journaling for future operations. Private sidecars may contain credentials while a transaction is active; permissions apply to them too. This is plaintext storage, not encryption or guaranteed physical erasure. Old freelist pages, backups, prior WAL files, SSD blocks and process memory are not retroactively erased. Migration/retention policy remains an operator responsibility.

No same-user API flag protects against arbitrary direct SQLite/file/debugger access. The lmauth operator/broker process and DB/browser must be outside the agent principal, with a restricted caller protocol. Do not expose arbitrary CLI arguments, file paths, store selection, grant rebinding, or generic HTTP bodies to an agent. Broker dry mode validates the proposed input without invoking a real write/network operation; lmconn has no simulated store command.

## Switching wp318's adapter

Keep wp318's write-only Go `Store.Put` abstraction and its consent/verification rules. Replace its legacy `cred set lmauth:HANDLE api_key --stdin` invocation with trusted `lmconn cred store lmauth:HANDLE --stdin`, setting broker mode and the operator-private DB path explicitly. For the GitHub PAT slice, send kind=bearer, credential bytes, owner from the verified `/user` result, source=lmauth/wp318, issuer=https://github.com and allowedOrigins=[https://api.github.com]. Supply only known expiry; do not turn a human-attested seven-day choice or successful public GET into strict evidence. The adapter needs the recipe/verified summary alongside the credential (extend its Put input or bind them in the adapter), not a new getter.

Pass only the nonsecret service handle and validated receipt back to the session. Discard child stderr and unknown output fields; validate the receipt's handle/kind/stored fields without forwarding raw child output on errors. Verification happens in the existing private Go verifier before import; subsequent broker operations must use reviewed, bound handle operations. Temporary FileStore remains a separate explicit choice. Windows must preserve wp318's existing fail-closed behavior. No lmauth source is modified by this lmconn delivery.
