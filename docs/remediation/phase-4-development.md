# Phase 4: new development and features

## 1. Feature evaluation

Scores are 0–10, where higher is better for every criterion: "complexity" and "maintenance" score 10 when cheap. Weights: user value 30, security 25, complexity 15, maintenance 15, cross-platform 10, performance 5.

| # | Feature | Value | Sec | Cmplx | Maint | X-plat | Perf | **Score** | Decision |
|---|---|---|---|---|---|---|---|---|---|
| F-01 | Tags, favorites, notes, filtering | 8 | 9 | 9 | 9 | 10 | 10 | **8.9** | Implemented |
| F-04 | Public key export (`pubkey`, `show`) | 8 | 10 | 10 | 10 | 10 | 10 | **9.4** | Implemented |
| F-05 | Shell completion (commands/flags) | 6 | 10 | 9 | 9 | 7 | 10 | **8.2** | Implemented |
| F-02 | Key age metadata + rotation review filter | 7 | 8 | 9 | 9 | 10 | 10 | **8.3** | Implemented |
| F-03 | Rotation helper `sendkey --via OLD` | 8 | 8 | 8 | 8 | 6 | 10 | **7.9** | Implemented (Linux, macOS, Windows) |
| F-06 | Structured JSON output + exit codes | 7 | 9 | 9 | 9 | 10 | 10 | **8.6** | Implemented (Phase 3) |
| F-07 | Encrypted export/import of selected entries | 7 | 6 | 6 | 6 | 10 | 10 | **6.9** | Backlog |
| F-08 | Import from `~/.ssh/config` (hosts only, no keys) | 7 | 8 | 6 | 6 | 9 | 10 | **7.3** | Backlog (next) |
| F-09 | Per-entry pinned host key (dedicated `UserKnownHostsFile`) | 6 | 9 | 6 | 7 | 8 | 10 | **7.3** | Implemented (`pin`) |
| F-10 | Windows named-pipe agent (`connect` on Windows) | 7 | 6 | 3 | 5 | 10 | 10 | **6.3** | Implemented: named-pipe agent (D-10, Q-13; commits 7cbd42d, fbe68e1, 2a17117) |
| F-11 | Hardware/FIDO2 keys | 7 | 9 | 2 | 4 | 5 | 10 | **6.3** | Rejected for now: x/crypto can't sign with `sk-*` keys in-process; would mean delegating to ssh-agent, changing the trust model |
| F-12 | Windows ACL checks | 4 | 8 | 5 | 6 | 3 | 10 | **5.7** | Implemented: owner and ACL checks, owner-only ACL on new files (Q-13; commit 2a17117) |
| F-13 | Interactive TUI | 6 | 7 | 3 | 4 | 7 | 9 | **5.8** | Deferred: would need a TUI framework (bubbletea), a large dependency |
| F-14 | Desktop GUI | 5 | 6 | 1 | 2 | 5 | 8 | **4.4** | Deferred; the `app` layer keeps the logic UI-independent |
| F-15 | OS keychain session cache | 6 | 4 | 4 | 3 | 4 | 10 | **4.8** | Rejected (adds a second secret store; needs explicit approval) |
| F-16 | Connection history | 4 | 5 | 8 | 7 | 10 | 6 | **6.0** | Rejected: a vault write per connect churns the backup and records metadata (D-15) |
| F-17 | One-step rotation `rotate` (install new, save, remove old) | 8 | 8 | 7 | 7 | 8 | 10 | **7.8** | Implemented (supersedes the manual F-03 steps) |
| F-18 | Entry name as a positional argument (`sshman connect web`) | 6 | 10 | 9 | 9 | 10 | 10 | **8.5** | Implemented |
| — | Cloud sync, telemetry | — | — | — | — | — | — | — | Out of scope without explicit approval |

## 2. Implemented features

### F-01 Tags, favorites, notes
- **Problem:** finding hosts in a growing vault.
- **Workflow:** `sshman add … --tag prod,web --favorite`; `sshman list --tag prod`; `sshman list --favorites`; `sshman search -q web` also matches tags; `sshman update --name x --tag ""` clears tags.
- **Security:** notes are encrypted with the vault; help text warns not to store secrets there. Tags are validated like names.
- **Design:** optional JSON fields (`omitempty`), so older vaults are unchanged and older sshman versions ignore them.
- **Tests:** `TestMatchesTags`, `TestListJSONHasNoSecrets`.
- **Compatibility:** additive.

### F-02 Key age and rotation review
- **Workflow:** `sshman show --name x` shows "Key created: 2026-11-08 (0 days ago)". `sshman list --key-older-than 365` lists keys due for rotation, including keys of unknown age from older vaults.
- **Design:** `key_created_at` is set by `add`, `genkey` and `update --key`.
- **Tests:** `TestListKeyOlderThanAndCompletion`.

### F-03 Rotation helper
- **Workflow:**
  1. `sshman genkey --name web-2026 --user deploy --host web` creates the new key.
  2. `sshman sendkey --name web-2026 --via web` installs it, logging in with the old entry's vault key.
  3. `sshman connect --name web-2026 -- true` verifies it.
  4. Remove the old key line on the server, then `sshman delete --name web --yes`.
- **Security:** the same read-only agent and no-forwarding rules apply. The remote append is idempotent and never removes lines; automatic removal of the old key was deliberately not implemented, because remote `authorized_keys` edits beyond append are risky.
- **Tests:** `TestIntegrationSendKeyViaAndIdempotent`.
- **Update:** superseded for the common case by F-17 `rotate`, which removes the old key with the safeguards below.

### F-17 One-step rotation
- **Workflow:** `sshman rotate --name web [--type ed25519|rsa] [--bits N]`. One password prompt.
- **Order:** (1) generate the new key and install it by logging in with the current key; (2) save it in the vault, only if the entry's key is unchanged since unlock; (3) log in with the new key and remove the old key from `authorized_keys`.
- **Security:** reverses the F-03 decision not to edit `authorized_keys` beyond appending. The removal is guarded so it cannot lock the user out: it only runs after the new key is saved and has just logged in; the remote script also refuses to change the file unless the new key is listed; only lines carrying the old key's type and blob are dropped; the file is rewritten to a 0600 temp file and renamed. A failure in step 1 changes nothing; in step 2 the old key stays in use; in step 3 the old key line is printed for manual removal.
- **Limit:** a symlinked `authorized_keys` is replaced by a regular file (marked `shortcut:` in `removeKeyScript`).
- **Tests:** `TestRemoveKeyScriptLocally`, `TestRotate`, `TestRotateFailsSafely` (fake ssh that enforces `authorized_keys`), `TestIntegrationRotateRemovesOldKey` (real sshd).

### F-04 Public key export
`sshman pubkey --name x >> authorized_keys` and `sshman show --name x [--json]`. The private key is never printed by any command. `EntryView` has no private-key field by construction.

### F-05 Shell completion
`source <(sshman completion bash)` (or `zsh`). It completes commands and flags only; completing entry names would need the vault password.

### F-06 JSON and exit codes
`list/search/show --json`; exit codes documented in the README. Covered in Phase 3.

### F-09 Host-key pinning
- **Workflow:** `sshman pin web` logs in with the entry's vault key using an empty, private known_hosts; ssh shows the fingerprint to confirm (or `--accept-new-host-key`). The lines ssh records are stored in the entry (`host_keys`, additive field). `pin` again replaces the pin, `pin --clear` removes it; `show` prints the pinned fingerprints.
- **Enforcement:** for pinned entries, `connect`, `sendkey` (both forms) and `rotate` write the pins to a 0600 file in a private temp dir and pass it as both `UserKnownHostsFile` and `GlobalKnownHostsFile`, with `StrictHostKeyChecking=yes` (placed before any accept-new; ssh keeps the first value) and `UpdateHostKeys=no`. The file is deleted afterwards.
- **Edge cases:** `update --host/--port` drops the pin (it would no longer match); `pin` refuses to save if the entry's host or port changed meanwhile; a failed pinned `connect` prints how to re-pin after a legitimate key change.
- **Tests:** `TestSSHArgsPinnedHostKeys`, `TestPinAndPositionalName`, `TestIntegrationPinnedHostKey` (real sshd: pin, connect with no known_hosts, MITM key refused even with accept-new).

### F-18 Positional entry name
- **Workflow:** every command acting on one existing entry accepts `NAME` as its first argument as well as `--name`. Flags must precede the name; a flag after it is a usage error rather than being sent as a remote command.
- **Tests:** `TestPinAndPositionalName`.

## 3. Next candidates (designs)

- **F-08 Import from ssh_config:** parse `Host` blocks (HostName, User, Port) into entries without keys, then `add --key` or `genkey` per entry. Acceptance: no key files are read implicitly; there's a dry-run preview; existing names are never overwritten. Tests: fixture configs with `Include` and `Match` (`Match` blocks are skipped).
- **F-07 Encrypted export:** export selected entries to a new vault-format file under a separate password (reusing `vault` code). Acceptance: the export is never plaintext; there's an import preview; names never collide silently.

## 4. Acceptance gate

Each implemented feature has functional tests, was reviewed against the threat model (no new secret outputs, no new network paths, no new dependencies), passes all regression suites, is documented in the README, and is additive to the vault format. **Decision: PASS.**
