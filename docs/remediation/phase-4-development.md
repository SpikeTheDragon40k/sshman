# Phase 4: new development and features

## 1. Feature evaluation

Scores are 0–10, where higher is better for every criterion: "complexity" and "maintenance" score 10 when cheap. Weights: user value 30, security 25, complexity 15, maintenance 15, cross-platform 10, performance 5.

| # | Feature | Value | Sec | Cmplx | Maint | X-plat | Perf | **Score** | Decision |
|---|---|---|---|---|---|---|---|---|---|
| F-01 | Tags, favorites, notes, filtering | 8 | 9 | 9 | 9 | 10 | 10 | **8.9** | Implemented |
| F-04 | Public key export (`pubkey`, `show`) | 8 | 10 | 10 | 10 | 10 | 10 | **9.4** | Implemented |
| F-05 | Shell completion (commands/flags) | 6 | 10 | 9 | 9 | 7 | 10 | **8.2** | Implemented |
| F-02 | Key age metadata + rotation review filter | 7 | 8 | 9 | 9 | 10 | 10 | **8.3** | Implemented |
| F-03 | Rotation helper `sendkey --via OLD` | 8 | 8 | 8 | 8 | 6 | 10 | **7.9** | Implemented (Unix) |
| F-06 | Structured JSON output + exit codes | 7 | 9 | 9 | 9 | 10 | 10 | **8.6** | Implemented (Phase 3) |
| F-07 | Encrypted export/import of selected entries | 7 | 6 | 6 | 6 | 10 | 10 | **6.9** | Backlog |
| F-08 | Import from `~/.ssh/config` (hosts only, no keys) | 7 | 8 | 6 | 6 | 9 | 10 | **7.3** | Backlog (next) |
| F-09 | Per-entry pinned host key (dedicated `UserKnownHostsFile`) | 6 | 9 | 6 | 7 | 8 | 10 | **7.3** | Backlog (next) |
| F-10 | Windows named-pipe agent (`connect` on Windows) | 7 | 6 | 3 | 5 | 10 | 10 | **6.3** | Backlog; needs a Windows test lab (D-10) |
| F-11 | Hardware/FIDO2 keys | 7 | 9 | 2 | 4 | 5 | 10 | **6.3** | Rejected for now: x/crypto can't sign with `sk-*` keys in-process; would mean delegating to ssh-agent, changing the trust model |
| F-12 | Windows ACL checks | 4 | 8 | 5 | 6 | 3 | 10 | **5.7** | Backlog |
| F-13 | Interactive TUI | 6 | 7 | 3 | 4 | 7 | 9 | **5.8** | Deferred: would need a TUI framework (bubbletea), a large dependency |
| F-14 | Desktop GUI | 5 | 6 | 1 | 2 | 5 | 8 | **4.4** | Deferred; the `app` layer keeps the logic UI-independent |
| F-15 | OS keychain session cache | 6 | 4 | 4 | 3 | 4 | 10 | **4.8** | Rejected (adds a second secret store; needs explicit approval) |
| F-16 | Connection history | 4 | 5 | 8 | 7 | 10 | 6 | **6.0** | Rejected: a vault write per connect churns the backup and records metadata (D-15) |
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

### F-04 Public key export
`sshman pubkey --name x >> authorized_keys` and `sshman show --name x [--json]`. The private key is never printed by any command. `EntryView` has no private-key field by construction.

### F-05 Shell completion
`source <(sshman completion bash)` (or `zsh`). It completes commands and flags only; completing entry names would need the vault password.

### F-06 JSON and exit codes
`list/search/show --json`; exit codes documented in the README. Covered in Phase 3.

## 3. Next candidates (designs)

- **F-08 Import from ssh_config:** parse `Host` blocks (HostName, User, Port) into entries without keys, then `add --key` or `genkey` per entry. Acceptance: no key files are read implicitly; there's a dry-run preview; existing names are never overwritten. Tests: fixture configs with `Include` and `Match` (`Match` blocks are skipped).
- **F-09 Host-key pinning:** store the host key on first connect (opt-in) and pass `-o UserKnownHostsFile=<tmp pinned file> -o StrictHostKeyChecking=yes` for that entry. Acceptance: a changed key fails with both fingerprints shown. Tests: the integration lab's MITM scenario.
- **F-07 Encrypted export:** export selected entries to a new vault-format file under a separate password (reusing `vault` code). Acceptance: the export is never plaintext; there's an import preview; names never collide silently.

## 4. Acceptance gate

Each implemented feature has functional tests, was reviewed against the threat model (no new secret outputs, no new network paths, no new dependencies), passes all regression suites, is documented in the README, and is additive to the vault format. **Decision: PASS.**
