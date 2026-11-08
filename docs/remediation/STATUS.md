# Remediation status

Branch `remediation` (from `review`). The security audit (kept on the `review` branch, not part of this change) describes upstream `sshman-org/sshman` at `0a430e9`, which is the same tree as this fork's `0a430e9`, so every finding applied unchanged.

**Statuses:** CONFIRMED, PARTIALLY_CONFIRMED, NOT_REPRODUCED, FALSE_POSITIVE, FIXED, BLOCKED, ACCEPTED_RISK.
"Verified" is how the finding was independently checked *before* the fix. "Test evidence" names the regression tests that now guard it. All named tests pass locally (Go 1.26.10, Linux) and in CI run [42459809140](https://github.com/SpikeTheDragon40k/sshman/actions/runs/42459809140) (Linux, macOS, Windows).

## Security findings

| ID | Title | Audit sev. | Assessed sev. | Phase | Verified (before fix) | Status | Commit | Test evidence |
|---|---|---|---|---|---|---|---|---|
| S-01 | Vault key forwarded to remote via user `ForwardAgent yes` | MEDIUM | MEDIUM (HIGH once Q-02 is fixed alone) | 1 | Lab: localhost sshd, `~/.ssh/config Host * ForwardAgent yes`; remote `ssh-add -l` printed the vault key `SHA256:krsfCpgh…` | FIXED | 89bfe10 | `TestIntegrationNoAgentForwarding`, `TestConnectArgs`; E2E: remote `SSH_AUTH_SOCK` empty, `ssh-add` rc=2 |
| S-02 | Private key in argv / shell history (`--key` raw PEM) | MEDIUM | MEDIUM | 1 | Code: `resolveKeyInput` returned non-path values as key text | FIXED | b25cddc | `TestAddKeyInput` (raw key refused, not echoed, exit 2; `-` reads stdin) |
| S-03 | Fixed `.tmp` path: symlink followed, mode inherited | MEDIUM | MEDIUM | 1 | Original code, rerun: P1 victim overwritten and vault became a symlink; P2 final mode `-rw-r--r--` | FIXED | ad360e0 | `TestSymlinkAtLegacyTmpPathNotFollowed`, `TestPreexistingPermissiveTmpIgnored`, `TestVaultSymlinkRefused`, `TestLockSymlinkRefused` |
| S-04 | Empty / whitespace-only password accepted; `TrimSpace` | MEDIUM | MEDIUM | 1 | Original code, rerun: P4 `Save("")`/`Load("")` recovered `"SECRET"` | FIXED | b25cddc | `TestInitPasswordPolicy`, `TestPasswordWhitespacePreserved`, `TestLegacyTrimmedPasswordVault`, `TestPasswd` |
| S-05 | `accept-new` overrides stricter user policy | LOW | LOW | 1 | Lab: first connect printed `Permanently added '[127.0.0.1]:2222'` with no prompt | FIXED | 89bfe10 | `TestIntegrationHostKeyPolicy` (unknown key refused under `StrictHostKeyChecking yes`; changed key always refused) |
| S-06 | ssh option injection via leading `-` in user | LOW | LOW | 1 | Code: `validUserRe` `^[a-zA-Z0-9._-]+$` accepts `-Fevil`; no `--` before destination | FIXED | 89bfe10 | `TestValidateUserAndHostRejectOptionInjection`, `TestConnectArgs`, `FuzzValidateAndArgs` |
| S-07 | Unconstrained in-process agent | LOW | LOW | 1 | Code: plain `agent.NewKeyring()` served on the socket | FIXED | 89bfe10 | `TestReadOnlyAgent` (Add/Remove/RemoveAll/Lock/Extension refused; List returns 1 key) |
| S-08 | Reachable vulnerabilities (x/crypto, stdlib) | LOW | LOW | 1 | `govulncheck ./...`: 9 reachable (GO-2026-5972, -5033, -5018, -5006, -5005, -4971, GO-2025-4011, -4009, -4007) | FIXED | 3d8debe | `govulncheck ./...`: 0 reachable; CI `lint` job |
| S-08a | GO-2026-5932 (`x/crypto/openpgp` unmaintained) | — | INFO | 1 | Reported after the upgrade as "module required, not called" | ACCEPTED_RISK | — | sshman never imports `openpgp`; govulncheck confirms it is unreachable. Fixed only in an unreleased pseudo-version; Dependabot picks it up when tagged (DECISIONS D-11) |
| S-09 | Tracked, non-reproducible binary | LOW | LOW | 1 | `git ls-files` listed `sshman` (ELF, `vcs.modified=true`, x/crypto v0.39.0) | FIXED | cb948be, 769f5b2 | CI "no committed executables" step (flags the old binary when run against it); `release.yml` builds, checksums and attests provenance |
| S-10 | Insecure permissions / CWD location not detected | LOW | LOW | 1 | Original code, rerun: P3 a `0666` vault loaded with no error | FIXED | ad360e0, b25cddc, c0378af | `TestInsecurePermissionsRefused`, `TestWritableDirectoryRefused`, `TestVaultPathResolution`, `TestDoctor` |
| S-11 | Secrets in process memory | LOW | LOW | 1 | Code: password trimmed into an immutable `string`; no core-dump suppression | FIXED (hardening) / ACCEPTED_RISK (residual) | b25cddc | Runtime check: `RLIMIT_CORE=0`; as an unprivileged user `/proc/<pid>/mem` becomes root-owned (non-dumpable). Residual: `Entry.Key` is a `string` (DECISIONS D-07) |
| S-12 | No vault version / KDF parameters | INFO | INFO | 1 | Code: `salt‖nonce‖ct`, constants in code | FIXED | ad360e0 | `TestTamperEveryByte`, `TestHeaderParamBounds`, `TestLegacyFixtureMigration`, `TestRecommendedParams`, `FuzzDecryptVault` |
| S-13 | `sendkey` appends unvalidated trailing lines | LOW | LOW | 1 | Code: `rest` of `ParseAuthorizedKey` ignored; whole string appended | FIXED | 89bfe10 | `TestCanonicalAuthorizedKey`, `TestInstallKeyScriptLocally` (runs the script with `sh`), `FuzzCanonicalAuthorizedKey`, `TestIntegrationSendKeyViaAndIdempotent` |
| S-14 | Passphrase-protected keys unsupported | LOW | LOW | 1 | Code: no passphrase path; `add` stored the key unparsed | FIXED | 89bfe10, b25cddc | `TestParsePrivateKey`, `TestAddPassphraseProtectedKey` |

## Engineering findings

| ID | Title | Audit sev. | Assessed sev. | Phase | Verified (before fix) | Status | Commit | Test evidence |
|---|---|---|---|---|---|---|---|---|
| Q-01 | Build broken (module path vs imports) | HIGH | HIGH | 2 (done first) | `go build ./...`: "no required module provides package github.com/SpikeTheDragon40k/sshman/cmd" | FIXED | 4fd4ea8 | CI `test` on 3 OSes; cross-build on 6 targets |
| Q-02 | `connect` cannot authenticate | HIGH | HIGH | 2 (done with S-01) | Lab: `Permission denied (publickey,password)`, exit 255, with an empty `~/.ssh` | FIXED | 89bfe10 | `TestIntegrationConnectUsesVaultKey`, `TestIntegrationUserIdentityAgentIgnored`; E2E with the real binary |
| Q-03 | Concurrent saves corrupt the vault / lost updates | MEDIUM | MEDIUM (data loss) | 1 | Mutation check: with the lock disabled, 24/32 multi-process and 28/40 goroutine updates were lost | FIXED | ad360e0, c0378af | `TestConcurrentUpdatesNoLostWrites` (-race), `TestMultiProcessUpdates` (also on Windows CI) |
| Q-04 | `sendkey` cannot bootstrap a password-only server | MEDIUM | MEDIUM | 2 | Code: `PasswordAuthentication=no` | FIXED | 89bfe10 | E2E: lab account with a password and an empty `authorized_keys`; `sendkey` prompted via ssh, added 1 line, second run added none. `TestSendKeyArgs`, `TestIntegrationSendKeyViaAndIdempotent` |
| Q-05 | Duplicate names; delete removes all | LOW | LOW | 2 | Code: `DeleteByName` filtered all matches | FIXED | 89bfe10, b25cddc | `TestDeleteByNameRemovesOnlyFirst`, `TestDuplicatesAndDelete`, `TestLegacyTrimmedPasswordVault` (legacy duplicates) |
| Q-06 | Key not validated on add/update | LOW | LOW | 2 | Code: `ValidateEntry` never parsed `Key` | FIXED | 89bfe10, b25cddc | `TestParsePrivateKey` (typo path, garbage, trailing data, two keys, oversize), `TestAddKeyInput` (mismatched `--pubkey`) |
| Q-07 | `go vet` / staticcheck SA4021 | LOW | LOW | 2 | `go vet`: `ssh.go:89:10`, `:125:15` | FIXED | 4fd4ea8 | `go vet ./...`, `staticcheck ./...` exit 0 (CI) |
| Q-08 | No CI; no cmd/sshutil tests | LOW | LOW | 2 | No `.github/workflows` | FIXED | 769f5b2 and earlier | 80 unit/CLI tests, 6 integration tests, 4 fuzz targets, CI on 3 OSes |
| Q-09 | Duplicated command boilerplate | INFO | INFO | 2 | 10× path default, 9× prompt+load | FIXED | b25cddc | `app` layer; `cmd` is flag mapping only |
| Q-10 | RSA bits unbounded; default 2048 | LOW | LOW | 2 | Code: only `bits < 2048` rejected | FIXED | 89bfe10 | `TestGenerateRSARejectsOtherSizes`, `TestGenKeyAndRename` |
| Q-11 | Missing lifecycle commands | LOW | LOW | 3 | — | FIXED | b25cddc, ad360e0 | `passwd` (`TestPasswd`, `TestChangePassword`), `restore` (`TestRestoreCommand`), `rename`, `show`, `pubkey`; automatic `.bak`. Encrypted export: see Phase 4 backlog F-07 |
| Q-12 | Errors on stdout; mixed output | INFO | INFO | 2 | `main.go` used `fmt.Println` | FIXED | b25cddc | `TestWrongPasswordExitCode` (stderr only, clean stdout), `TestListJSONHasNoSecrets` |
| Q-13 | Windows `connect` incompatible | LOW | LOW | 2 | Code: unix-socket agent; Win32-OpenSSH uses a named pipe | FIXED | 7cbd42d, fbe68e1, 2a17117 | Named-pipe agent (DECISIONS D-10). `TestConnectInprocServer` and `TestSessionAgentEndpoint` pass on windows-latest with the built-in ssh.exe (CI run 42464601399) |
| Q-14 | gosec G204/G304 | INFO | — | — | Re-reviewed: `exec.Command` takes an argv slice; the paths are the user's own | FALSE_POSITIVE | — | G104 (ignored errors) was valid and fixed in Q-15 |
| Q-15 | `init` TOCTOU; no dir fsync; ignored errors | LOW | LOW | 1 | Code inspection | FIXED | ad360e0 | `TestCreateRefusesExisting`, `TestInitRefusesExisting`, `TestInterruptedWriteKeepsOldVault` (fault injection) |
| Q-16 | Documentation drift | INFO | INFO | 3 | README claims vs code | FIXED | (docs commit) | README rewritten against the implementation |

## Improvements and features (Phases 3–4)

| ID | Item | Phase | Status | Commit | Test evidence |
|---|---|---|---|---|---|
| I-01 | `doctor` (location, permissions, format, backup, ssh) without the password | 3 | FIXED | 9d3b382 | `TestDoctor` |
| I-02 | Configurable/upgradeable KDF via versioned header; `passwd` upgrades | 3 | FIXED | ad360e0, b25cddc | `TestLegacyFixtureMigration`, `TestChangePassword` |
| I-03 | Automatic encrypted backup + `restore` | 3 | FIXED | ad360e0, b25cddc | `TestRestoreFromBackup`, `TestBackupIsSeparateInode` |
| I-04 | Benchmarks (unlock, save, 5000 entries, search, keygen) | 3 | FIXED | 9d3b382 | see phase-3 report |
| I-05 | Exit codes, `--json`, stderr discipline | 3 | FIXED | b25cddc | `TestListJSONHasNoSecrets`, `TestWrongPasswordExitCode` |
| F-01 | Tags, favorites, notes, filtering | 4 | FIXED | 89bfe10, b25cddc | `TestMatchesTags`, `TestListJSONHasNoSecrets` |
| F-02 | Key age metadata + `list --key-older-than` | 4 | FIXED | b25cddc, 9d3b382 | `TestListKeyOlderThanAndCompletion` |
| F-03 | Key rotation helper `sendkey --via` | 4 | FIXED | 89bfe10 | `TestIntegrationSendKeyViaAndIdempotent` |
| F-04 | Public key export (`pubkey`, `show`) | 4 | FIXED | b25cddc | `TestListJSONHasNoSecrets` |
| F-05 | Shell completion | 4 | FIXED | 9d3b382 | `TestListKeyOlderThanAndCompletion`; real binary lists commands |
| F-06..F-12 | Remaining candidates | 4 | Backlog (not implemented) | — | Ranked in phase-4-development.md |

## Follow-up (test-plan gaps closed after the first merge)

| ID | Item | Status | Commit | Test evidence |
|---|---|---|---|---|
| T-01 | Malformed inputs from the audit test plan §3 | FIXED | c3af13e | `TestHugeVaultFileRefusedWithoutReading` (1 GiB sparse file refused from its size; new pre-read size check), `TestHostileDecryptedPayloads` (100k-deep nesting, wrong types, truncated/non-JSON, huge numbers, invalid UTF-8), `TestManyEntries` (100k entries), `TestUnusualPasswordBytes` (NUL, non-UTF-8, 1 KiB), `TestCheckPasswordPolicyMalformed`, `TestValidateMalformedHostsAndUsers` (homoglyphs, zero-width, control characters, overlong) |
| T-02 | ProxyJump with `ForwardAgent yes` on the jump host (R-3) | FIXED (tested) | d88b814 | `TestIntegrationProxyJump`; mutation check |
| T-03 | Windows `connect` (Q-13) and Windows vault ACL checks (S-10) | FIXED | 7cbd42d, fbe68e1, 2a17117 | CI run 42464601399: all 11 jobs green; Windows: `TestConnectInprocServer`, `TestSessionAgentEndpoint`, `TestWindowsNewFilesAreOwnerOnly`, `TestWindowsInsecureACLRefused`, `TestDoctor` |
