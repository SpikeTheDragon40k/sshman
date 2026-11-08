# 04 — Code Quality, Reliability & Architecture

Engineering findings that are not primarily security vulnerabilities. Line numbers refer to `HEAD`.

| ID | Title | Severity | Status |
|---|---|---|---|
| Q-01 | Build broken: module path does not match the imports | HIGH | CONFIRMED |
| Q-02 | `connect` cannot authenticate with the vault key (`IdentitiesOnly=yes`) | HIGH | CONFIRMED |
| Q-03 | Concurrent saves corrupt the vault; lost updates | MEDIUM | CONFIRMED |
| Q-04 | `sendkey` cannot bootstrap a password-only server | MEDIUM | CODE-SUPPORTED |
| Q-05 | Duplicate entry names allowed; `delete` removes all of them | LOW | CONFIRMED |
| Q-06 | Key content not validated on `add`/`update`/`genkey` | LOW | CONFIRMED |
| Q-07 | `go vet` / staticcheck SA4021 failures | LOW | CONFIRMED |
| Q-08 | No CI; no tests for `cmd` or `sshutil` | LOW | CONFIRMED |
| Q-10 | `genkey --bits` has no upper bound; RSA default is 2048 | LOW | CODE-SUPPORTED |
| Q-11 | Missing lifecycle commands (change password, export/backup, rotate) | LOW | CODE-SUPPORTED |
| Q-13 | Windows `connect` likely incompatible (unix-socket agent) | LOW | POTENTIAL |
| Q-15 | `init` TOCTOU; no directory fsync; cleanup errors ignored | LOW | CONFIRMED (gosec G104) |
| Q-09 | Duplicated command boilerplate | INFO | CODE-SUPPORTED |
| Q-12 | Error handling and output conventions | INFO | CODE-SUPPORTED |
| Q-14 | gosec triage: G204 and G304 are false positives | INFO | Analysed |
| Q-16 | Documentation drift | INFO | CONFIRMED |

---

### Q-01 — Build broken (HIGH)
`go.mod:1` declares `module github.com/sshman-org/sshman` (commit `1837f15`, "Update go.mod"). Every import (`main.go:7`, `cmd/cmd.go:10-13`, `sshutil/ssh.go:12`, `vault/vault.go:11`, tests) uses `github.com/SpikeTheDragon40k/sshman/...`.
Evidence: `go build ./...` gives "no required module provides package …" (exit 1). `go vet` exits 1. In `go test ./...`, `vault` reports `[setup failed]`.
**Fix:** rewrite the imports to `github.com/sshman-org/sshman/...`, which matches the README badge and repo name. Add a CI build so this can't regress.

### Q-02 — `connect` cannot authenticate (HIGH)
`sshutil/ssh.go:46` passes `IdentitiesOnly=yes`. Per `ssh_config(5)`, ssh then only uses configured or default identity files, *even if ssh-agent offers more identities*. sshman's agent key matches none of them, so it is never offered.
Evidence: with a localhost sshd, the real `Connect` got `Permission denied (publickey,password)`. A replicated agent failed with `IdentitiesOnly=yes` and returned `AUTH_OK` with `=no`. It only works when a matching `~/.ssh/id_*.pub` happens to exist (test E).
**Fix (recommended):** write the **public** key to `tmpDir/id.pub` (0600) and pass `-o IdentityFile=<tmpDir>/id.pub -o IdentityAgent=<sock> -o IdentitiesOnly=yes -o ForwardAgent=no`. ssh then signs through the agent for that public-key identity. This keeps the protection against offering every key, stores no secret on disk, and also closes S-01. If `PubKey` is empty, derive it from the private key.

### Q-03 — Concurrent saves corrupt the vault (MEDIUM, data loss)
`vault/vault.go:109` uses a fixed `.tmp` name, and nothing locks the file. Two writers truncate and write the same inode. If the shorter write lands last, the longer write's tail remains, and the GCM tag check fails on the next load. **Every stored key is lost.** Separately, read-modify-write across commands loses the earlier writer's update.
Evidence: P5 found one unreadable vault in 200 four-way concurrent rounds, plus 77 `Save` errors (`rename … no such file`).
**Fix:** unique temp file via `os.CreateTemp`, an advisory lock (`flock` on `vault.lock`; `LockFileEx` on Windows, via `golang.org/x/sys`, already an indirect dependency) held across load→save, and keep one rotating backup (`vault.vssh.bak`).

### Q-04 — `sendkey` cannot bootstrap (MEDIUM)
`SendPublicKey` reuses the hardening args (`PasswordAuthentication=no`, `IdentitiesOnly=yes`) and does not use the vault key. It only succeeds if the user can already log in with a default identity or keyboard-interactive auth. That defeats the purpose of "set up passwordless login".
**Fix:** for `sendkey`, allow password / keyboard-interactive auth (the user types it into ssh's own prompt, not sshman's), or authenticate with an existing vault entry's key through the agent, as in Q-02.

### Q-05 — Duplicate names (LOW)
`add`/`genkey` don't check uniqueness. `FindByName` returns the first match (`model/entry.go:35`), and `DeleteByName` deletes **all** matches (P8: 2 removed). **Fix:** reject duplicates on add; make names case-sensitive unique keys.

### Q-06 — Key not validated (LOW)
`ValidateEntry` (`sshutil/ssh.go:20-40`) never parses `Key` or `PubKey`. A mistyped `--key` path is stored as the key text (P7), and the error only appears at `connect`. **Fix:** parse the private key on input, and check that `PubKey` matches the private key, or derive it.

### Q-07 — vet / staticcheck (LOW)
`sshutil/ssh.go:89` `append(sshHardeningArgs())` and `:125` `append(os.Environ())`: SA4021, "append with no values". Harmless, but `go vet` fails, so it blocks a vet-gated CI.

### Q-08 — Test & CI gaps (LOW)
- No `.github/workflows` exists, although the README marks "Tests and CI" done.
- `cmd` and `sshutil` have no tests. `vault` tests cover the happy path and a wrong password, but not tampering, truncation, permissions, symlinks or concurrency.
- No fuzz targets. See 07-test-plan.md.

### Q-10 — RSA bits (LOW)
`--bits` is only lower-bounded (`keygen.go:21`). `--bits 65536` hangs for a very long time. The default is 2048 (`cmd.go:408`). **Fix:** allow {3072, 4096} and default to 3072. Ed25519 is already the default type, which is good.

### Q-11 — Missing lifecycle (LOW)
There is no `passwd` (re-key), `export`/`backup`, `show-pubkey`, or entry rename. Without `passwd`, a leaked password can't be rotated without manually rebuilding the vault.

### Q-13 — Windows (LOW, POTENTIAL)
`net.Listen("unix")` works on Windows 10+, but Win32-OpenSSH's `ssh.exe` expects the agent on a named pipe (`\\.\pipe\…`). Unix-socket `SSH_AUTH_SOCK` support depends on the version. This was not tested; the README claims Windows support. **Validate on Windows** or use a named-pipe listener there.

### Q-15 — Atomicity details (LOW)
- `init` checks `os.Stat` and then `Save` (`cmd/cmd.go:90-104`), a TOCTOU that could overwrite a vault created concurrently.
- No `fsync` of the parent directory after `Rename`.
- `f.Close()` and `os.Remove` errors are ignored (gosec G104 ×5, `vault.go:115-125`).
- `Sync()` runs on an `O_RDONLY` handle. That works on Linux; the portable fix is to sync the write handle.

### Q-09 — Duplication (INFO)
The vault-path defaulting block is repeated 10×. Password prompt + load is repeated 9×. `list` and `search` print with identical code. A `withVault(c, fn)` helper plus a global `--vault` flag (also via `SSHMAN_VAULT`) would remove about 150 lines.

### Q-12 — Errors & output (INFO)
`main.go` prints errors to **stdout** (`fmt.Println`); they should go to stderr. `list` prints the banner after the password prompt, which mixes UX and data output and hurts scripting. A wrong password and a corrupted file produce the same message. That is correct for GCM, but a "file truncated / not a vault" check (magic number, S-12) would help users.

### Q-14 — gosec triage (INFO)
- G204 (`ssh.go:95,121`): `exec.Command` with an argument slice and no shell. Not exploitable locally (the remote-shell aspect is covered in S-13 and S-06). **FALSE POSITIVE** as command injection.
- G304 (`vault.go:97,113`, `cmd.go:56`): reading a user-chosen path is intended. **FALSE POSITIVE**.
- G104: valid, LOW (Q-15).

### Q-16 — Documentation drift (INFO)
- README says `genkey` generates RSA and lists "More key types (ED25519…)" as TODO, but Ed25519 is the default.
- README says "Requires Go 1.23+"; `go.mod` requires 1.24.0.
- The clone URL points at `SpikeTheDragon40k/sshman`.
- "SSH agent integration" is listed as TODO, but it is used internally.
- "Keys generated by `genkey` are without passphrase" is accurate, but should say they are protected only by the vault.

---

## Architecture assessment

- **Separation of concerns:** reasonable for the size. Pure model, crypto in `vault`, ssh glue in `sshutil`. `cmd` mixes I/O, defaults and orchestration. A small `app` layer (`OpenVault`, `Mutate(func([]Entry) []Entry)` with locking) would make `cmd` testable without a tty.
- **Dependencies:** minimal and appropriate (urfave/cli, x/crypto, x/term, clipboard). **Do not** add heavy frameworks. Remediations need only `golang.org/x/sys` (already indirect).
- **Delegating to OpenSSH** for the session is a good choice: mature host-key handling, no reimplementation of the protocol. The cost is that the user's config influences behaviour. That needs explicit overrides (S-01, S-05) rather than a switch to an x/crypto client.
- **Performance:** Argon2 at 64 MiB per command costs about 0.1–0.3 s, which is fine. The whole vault is decrypted for every command, which is fine at expected sizes.
- **Concurrency:** the only goroutine is the agent accept loop. It ends when the listener closes, and in-flight `ServeAgent` goroutines end when ssh exits. No data races were detected (`go test -race` passed for the existing tests).
