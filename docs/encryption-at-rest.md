# Encryption at rest

The credential store keeps every value in `creds.value` as AES-256-GCM ciphertext. A copied database file
(backup, snapshot, sync folder, accidental commit, disk image, a bug that dumps the table) is then not a
credential leak. Zero dependencies (`node:crypto`), still one SQLite file, no daemon, no passphrase prompt.

## Threat model (honest)

Protected: disclosure of the database file **alone**.

Not protected:

- Anyone who can read both the database and the key: the same user, root, a debugger, a process the key is
  injected into. Same-principal agents stay out of scope exactly as in [broker-store.md](broker-store.md); the
  lmauth broker split is what keeps agents away from the key.
- **A backup of the whole home directory** holds the database (`~/.lmconn`) and the default key
  (`~/.config/lmconn`). It is not protected. Keep the key out of home backups or back it up elsewhere.
- Names: service and field names, `credential_policy` documents (origins and flags, no secrets) and timestamps
  are not encrypted. They are authenticated once the store is sealed, see below.
- Memory: JavaScript strings and buffers cannot be zeroed. Key and plaintext live in process memory.
- **Rollback and freshness.** Anyone who can write the database file can restore an older consistent state: one
  row, several rows, a policy document, or the whole file. lmconn cannot detect that (it would need a counter outside
  the attacker's reach; out of scope). The policy MAC covers the existence and content of the *current* document, not
  its freshness: an older, validly MACed document can be put back. Encryption binds a value to its service, field and
  data key, so a value moved to another row fails; it does not bind it to a point in time.
- **Environment key.** `LMCONN_KEY` is captured and removed from `process.env` at the very top of the bin entry, so
  children (mcp, acp servers, anything spawned) do not inherit it. It stays readable in `/proc/PID/environ` of the
  lmconn process by the same uid (same-principal limit), and in whatever launched lmconn.
- Old plaintext: `cred encrypt-existing` writes a new file, but earlier backups, copies, journals and SSD
  blocks may still hold the old plaintext. Rotate any credential whose old file was ever copied.
- Windows file keys: see the Windows section.

## Key model

- **Instance key (IK)**: 32 random bytes, never in the database.
- **Data keys (DEK)**: 32 random bytes each, wrapped by the IK in table `data_keys(id, wrapped, ik_id, created, active)`.
  Rows are encrypted with the active DEK. Rotating the IK rewraps a few DEKs and does not touch rows.

IK source, first match wins:

1. `LMCONN_KEY`: base64 of 32 bytes (CI, containers). It is deleted from `process.env` as soon as it is
   read, so it is never passed to a child process. Without a file there is nothing to rotate or leave behind.
2. `LMCONN_KEY_FILE`: path to a file holding the base64 key.
3. `${XDG_CONFIG_HOME:-~/.config}/lmconn/instance.key`, mode 0600, directory 0700.

Every key file source gets the same checks as the store path: owned by the effective uid, no symlinks (also
none in the path except root-owned system links), no extra hard links, trusted ancestors, directory 0700.
A key file wider than 0600 is `STORE_SECURITY` and is **not** repaired (it may already have been read): rotate
the key. The key directory must differ from the database directory, so one careless copy of the store does not
take the key along: a key directory that is equal to, inside or containing the database directory is refused.
`LMCONN_KEY_FILE` and `XDG_CONFIG_HOME` must be absolute. A group- or world-writable key directory is `STORE_SECURITY`
and, like a loose key file, is refused rather than chmod-repaired (the store directory is repaired; the key directory
is not). Keys are exactly 32 bytes of strict base64; anything else is `KEY_INVALID`.

### Creation

Only a write may create the default key file: `cred set`, `cred store`, `cred oauth-store`, `cred encrypt-existing`,
and the writes inside `oauth refresh` and the first-use origin pin of `http request`. A read never creates a key.
Creation is race-safe: the key is written to a temp file in the same directory, fsynced and `link()`ed into place;
the loser re-reads the winner's key. The first data key is inserted under a unique index on the active marker.
The first creation prints one warning on stderr naming the file and saying to back it up separately.

**If the database already holds ciphertext and no key is found, every command fails closed (`KEY_MISSING`);
a new key is never generated** (that would orphan every credential). A wrong key is `KEY_MISMATCH`, detected by
a canary (one data key is unwrapped before any write).

If no key can be found or created (unwritable directory, read-only filesystem), a write fails with
`KEY_UNAVAILABLE`. Setting `LMCONN_ALLOW_PLAINTEXT=1` allows plaintext in that case only, and never once the
store holds ciphertext, is sealed, or runs in broker mode. Every plaintext write prints a warning on stderr; the next
write that can use a key encrypts the plaintext rows in place and says so.

## Format and integrity

Per value: `lmc1:<keyId>:<b64 nonce 12 B>:<b64 ciphertext||tag 16 B>`.

- AES-256-GCM, 12-byte random nonce, 16-byte tag, all enforced (a truncated tag, nonce or key fails).
- AAD: `u8 version, u32 len||service, u32 len||field, u32 len||keyId`. A value moved to another row
  fails authentication; names containing NUL are unambiguous. There is no generation counter: it would not stop
  an attacker restoring value and counter together (see Rollback above).
- DEK wrap: AES-256-GCM with the IK, AAD `data_keys` and the DEK id.
- Errors: `DECRYPT_FAILED`, `KEY_MISSING`, `KEY_MISMATCH`, `KEY_INVALID`, `KEY_UNAVAILABLE`, `STORE_TAMPERED`,
  `STORE_SECURITY`, `STORE_VERSION`. No key, secret or ciphertext appears in any message, stdout or stderr.

### Sealing: no downgrade

A store is **required** (every non-`lmc1:` value and every `credential_policy` row without a valid MAC is
`STORE_TAMPERED`) when ANY of these holds: the `meta.encrypted_required` marker; any `data_keys` row; any `lmc1:` value;
`PRAGMA user_version >= 2` or the seal triggers; the **sealed record**; or broker mode. The first four need only the
database, so an attacker has to remove all of them (and every ciphertext) to look like a legacy store; the sealed
record closes that gap.

The sealed record is a small file `sealed.<sha256 of the database realpath>` (0600) in the **key directory**, holding an
HMAC (key = HKDF(IK, "lmconn sealed")) over that realpath. It is written when the store is sealed, rewritten after a key
rotation, and is not written for `LMCONN_KEY` (no key directory) or on Windows. A database writer who cannot touch the
key directory therefore cannot turn a sealed store back into a legacy one, even by dropping the triggers, deleting
`meta` and `data_keys`, resetting `user_version` and planting plaintext. A record that does not verify is `KEY_MISMATCH`.
Whoever can write the key directory is the same principal as the key (out of scope). With `LMCONN_KEY` only, the seal
rests on the in-database rules above.

There is no half-plaintext state: the first encrypted write into a store that still has legacy plaintext rows encrypts
all of them in place in the same transaction, seals the store and prints a notice (old plaintext may remain in free
pages, journals and backups; `cred encrypt-existing` rewrites the file). Legacy plaintext is readable only until then.

Policy rows each carry an HMAC-SHA256 (key = HKDF(IK, "lmconn policy mac")) and a second MAC covers the set of services
and the marker, so edited, planted and **deleted** policy rows (which would unprotect a no-reveal handle) are
`STORE_TAMPERED`. These MACs prove existence and content of the current document, not freshness.

The seal triggers make SQLite refuse a plaintext insert or update, so an **older lmconn cannot write plaintext into a
sealed store**. An older lmconn does *not* refuse to open it: it can read `lmc1:` blobs as if they were secrets
(harmless ciphertext), and it cannot decrypt anything. A newer file format is refused by this version (`STORE_VERSION`).

## Commands

| Command | Does |
|---|---|
| `cred encrypt-existing [--all]` | Encrypt every legacy plaintext value and seal the store. `--all` also re-encrypts rows under older data keys, deletes data keys no row names and removes `instance.key.prev`. Safe to re-run. |
| `key rotate` | New IK, DEKs rewrapped, rows untouched, old IK kept as `instance.key.prev`. Hygiene only, see below. |
| `key rotate --data` | New active DEK for new writes. Old DEKs are never deleted while a row names them. |
| `key backup --to FILE` | Copy the IK to a new 0600 file (`O_EXCL`, fsync). Never prints the key. Refuses a target in the database directory, under a folder named like a sync client (Dropbox, iCloud, OneDrive, My Drive, Google Drive, Box, pCloud, Nextcloud, MEGA, Syncthing, Sync; best effort) and existing files. |

`cred encrypt-existing` builds a new database file holding only live data (rows encrypted as they are copied, so
the new file never holds plaintext), fsyncs it and renames it over the old one while holding the write lock.
Where the file cannot be replaced it falls back to one transaction followed by `VACUUM`. It warns about the
legacy directory `~/.lmconnectors/creds.db` (never migrated by this command) and about plaintext remnants. Stop
long-lived processes that hold the store open first: they keep the replaced file until they reopen it.

## Backup rule

Back up the key **separately** from the database, or the encryption is worth nothing. Do not rely on a home
directory backup. Losing the key loses every stored credential: recovery is to re-collect them through lmauth
(human links) or re-enter them.

## Rotation procedures

**Hygiene** (scheduled, no suspected leak): `lmconn key rotate`. Each wrapped DEK records `ik_id` (first 8 bytes
of SHA-256 of the IK). Order: new key file written and fsynced, old key saved as `instance.key.prev`, new key
switched in, DB rewrap committed in one transaction. A reader picks the key matching `ik_id` from the current
file and `.prev`, so a crash at any step leaves the store readable; writes wait (`KEY_MISMATCH`) until a re-run of
`key rotate` finishes the rewrap. Delete `.prev` when satisfied (`cred encrypt-existing --all` does it too).
After a rotation every earlier key backup is stale (lmconn says so on stderr): make a new `key backup`. `key rotate` needs a key file; with `LMCONN_KEY` rotate the secret in your CI system and re-create the store.

**After a suspected IK or database-plus-IK leak**: rotating the IK alone is *not* enough (an attacker who copied
the old IK and a database can unwrap the DEKs, which are unchanged). Do:

1. `lmconn key rotate --data`
2. `lmconn cred encrypt-existing --all` (re-encrypts under the new DEK, deletes old DEKs and `.prev`)
3. Rotate the credentials themselves at their providers if the old file or key may have been copied.

## Windows

Encryption works with `LMCONN_KEY`. A file-based key (default or `LMCONN_KEY_FILE`) fails closed with
`STORE_SECURITY` until lmconn has native owner/DACL enforcement (no `O_NOFOLLOW`, no `geteuid`), the same stance
as the broker store. `key backup` is refused on Windows for the same reason. With no `LMCONN_KEY`, a legacy store
stays usable only with `LMCONN_ALLOW_PLAINTEXT=1` (explicit opt-in). `LMCONN_KEY` is inherited by children
unless removed; lmconn removes it from its own `process.env` right after reading it.

## Compatibility

Existing stores open unchanged: the column `credential_policy.mac` and the tables `meta` and `data_keys`
are added in place. The no-reveal policy, broker mode and handle semantics are unchanged; a no-reveal handle is
simply also ciphertext on disk. Out of scope: KMS, HSM, OS keychain (a keychain would slot in as key source 0),
per-credential access control, a secrets server, any new reveal or export path.
