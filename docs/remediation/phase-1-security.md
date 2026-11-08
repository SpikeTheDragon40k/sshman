# Phase 1: security remediation

**Scope:** S-01 to S-14 and the security-relevant reliability findings Q-03 and Q-15. Q-01 (build) was fixed first, as a prerequisite.
**Branch:** `remediation`. **Commits:** 4fd4ea8, 3d8debe, cb948be, ad360e0, 89bfe10, b25cddc, c0378af, 769f5b2.
**Method limitation:** the team roles were simulated sequentially by one agent (see DECISIONS, "Process note"). Every conclusion below rests on a command or test that was actually run.

## 1. Lab and evidence sources

- **Localhost lab:** OpenSSH 9.6p1 sshd on `127.0.0.1:2222`, a disposable account (`sshlab`) with a synthetic password, and synthetic ed25519 keys. A hostile client config (`Host * / ForwardAgent yes`) was installed in the test user's `~/.ssh/config`. No real credentials or external hosts were used.
- **Original-code reruns:** `vault/vault.go` and `model/entry.go` from commit 4fd4ea8 (the original code with only the import fix), compiled in a scratch module.
- **Automated:** `go test -tags integration ./sshutil/` starts its own sshd on a random port with an isolated remote `HOME`, a client config passed with `-F` and `known_hosts`. It runs as root locally and as a normal user in CI.

## 2. Before and after

| ID | Before (command → observed) | After (command → observed) |
|---|---|---|
| S-01 | Original `Connect` + hostile config → remote `ssh-add -l`: `256 SHA256:krsfCpghkKGlCapX9P2OI9m59NlIXm6mLt7Me5o/UyQ (ED25519)` | Real binary, same hostile config: `sshman connect --name lab -- 'echo "SOCK=[$SSH_AUTH_SOCK]"; ssh-add -l'` → `SOCK=[]`, `Could not open a connection to your authentication agent.`, rc=2. `TestIntegrationNoAgentForwarding` PASS |
| Q-02 | Original `Connect`, empty `~/.ssh` → `Permission denied (publickey,password)`, exit 255 | `TestIntegrationConnectUsesVaultKey` PASS; E2E `AUTH_OK` |
| S-05 | Original `Connect` → `Warning: Permanently added '[127.0.0.1]:2222'` (no prompt) | `StrictHostKeyChecking yes` + unknown host → refused, `known_hosts` untouched; changed host key → refused even with `--accept-new-host-key` (`TestIntegrationHostKeyPolicy`) |
| S-03 P1 | Original `Save` with `vault.vssh.tmp → victim.txt` → `err=<nil> victimOverwritten=true vaultIsSymlink=true` | `TestSymlinkAtLegacyTmpPathNotFollowed` PASS: victim unchanged, vault a regular file |
| S-03 P2 | Pre-existing 0644 `.tmp` → final vault `-rw-r--r--` | `TestPreexistingPermissiveTmpIgnored` PASS: 0600 |
| S-10 P3 | `Load` of a 0666 vault → `err=<nil>` | Refused with `chmod 600` hint for 0644/0640/0666/0604 (`TestInsecurePermissionsRefused`) |
| S-04 P4 | `Save("")`, `Load("")` → recovered `"SECRET"` | `init` with `""`, `"   "`, `"\t\t"`, `"short-pw"` → exit 2, no file written (`TestInitPasswordPolicy`) |
| Q-03 | Mutation check (lock disabled): 24 of 32 multi-process and 28 of 40 goroutine updates lost | Lock enabled: 0 lost (`TestMultiProcessUpdates`, `TestConcurrentUpdatesNoLostWrites`; also on Windows CI) |
| S-02 | `--key "$(cat key)"` stored the key; argv readable through `/proc` | Refused before any I/O; message doesn't echo the key; exit 2 |
| S-08 | `govulncheck ./...` → 9 reachable vulnerabilities, exit 3 | 0 reachable; 1 module-level advisory not called (S-08a, accepted) |
| S-09 | `git ls-files` → `sshman` ELF (go1.23.0, `vcs.modified=true`) | Untracked; CI step detects any tracked executable (verified against the old blob: `application/x-executable`) |
| S-11 | No hardening | Running as uid 30033: `RLIMIT_CORE` 0/0; `/proc/<pid>/mem` owner uid 0 (non-dumpable) |
| Q-04 | `sendkey` forced `PasswordAuthentication=no` | Real binary vs a password-only account: ssh prompted for the password, `sshman: key added`, second run added nothing (1 line) |

## 3. Fix summary

- **S-01, S-05, S-06, S-07, Q-02:** see DECISIONS D-08. The vault key is offered only to the child ssh, never forwarded, and the agent is read-only.
- **S-02, S-14, Q-06:** `--key PATH|-`; PEM parsed with trailing data rejected; passphrase prompt; public key derived or verified; RSA < 2048 and DSA rejected.
- **S-03, S-10, Q-03, Q-15:**
  - Writes go to an O_EXCL random temp file, are fsynced, renamed, and the directory is fsynced.
  - `flock`/`LockFileEx` is held across read-modify-write.
  - `O_NOFOLLOW`, ownership and mode checks apply.
  - `Create` never overwrites.
  - A `.bak` is kept, and `restore` recovers from it.
- **S-04:** ≥ 12-character policy for new passwords; whitespace preserved; legacy trimmed passwords still open (D-04).
- **S-12:** authenticated v2 header with bounded KDF parameters; v1 read; upgrade on write; `passwd`.
- **S-13:** canonical single-line key, options rejected, idempotent `sh -c` script.
- **S-08, S-09:** dependency and toolchain upgrade; binary removed; release workflow with checksums, provenance attestation and draft-only publication.
- **S-11:** see D-07.

## 4. Adversarial review (red team / independent reviewer)

| Attack or question | Result |
|---|---|
| Remote host requests agent forwarding | Refused by `ForwardAgent=no` on the command line, even with `ForwardAgent yes` in config (tested) |
| User config `IdentityAgent /elsewhere` / `IdentityFile` | Overridden by our explicit options (`TestIntegrationUserIdentityAgentIgnored`) |
| ProxyJump host with `ForwardAgent yes` | The jump ssh doesn't inherit our `-o` options and never sees the vault agent, because `SSH_AUTH_SOCK` is left as the user's own (D-08). **Tested** (`TestIntegrationProxyJump`): with no jump identity the hop fails to authenticate; with its own key the session works, the destination has no agent, and the vault key is used only for the destination. Mutation check: exporting the session socket as `SSH_AUTH_SOCK` makes the test fail |
| Another local process connects to the session socket | 0700 directory, 0600 socket; even the same uid gets List/Sign only (`TestReadOnlyAgent`). It can still request signatures during the session (accepted, audit D-9) |
| Option injection via user/host/port | Leading `-` rejected, `--` placed before the destination, fuzzed (`FuzzValidateAndArgs`, 45 s, no failures) |
| Injection into the remote `sendkey` command | The key line is re-marshalled; comment characters are allowlisted; fuzzing asserts a safe character set (`FuzzCanonicalAuthorizedKey`); the script is run under `sh` in a test |
| Crafted vault header with huge Argon2 memory | Rejected before key derivation (`TestHeaderParamBounds`) |
| Bit flips or truncation anywhere in the vault | Every single-byte flip fails and every truncation fails; no panics (`TestTamperEveryByte`, `TestTruncationNeverPanics`, `FuzzDecryptVault`) |
| Symlink planted at vault, lock or `.tmp` path | Refused or ignored; target untouched (4 tests) |
| Crash between temp write and rename | Old vault intact, temp removed (`TestInterruptedWriteKeepsOldVault`) |
| Password rotation leaves an old-password backup | The backup is replaced after verification (`TestChangePassword` asserts the old password no longer opens `.bak`) |
| Raw key in an error message | `TestAddKeyInput` asserts no PEM fragment on stderr |
| Group member in a group-writable directory | Can delete or replace the vault (DoS), cannot read or redirect it; warning shown (D-06) |

**Rejected during review (iteration):**
1. First version refused group-writable directories. That broke umask-002 users (found by running the suite as a non-root user), so it became a warning (c0378af).
2. First integration test wrote to the real `~/.ssh/authorized_keys`. The test now isolates the remote `HOME` via sshd `SetEnv`. The stray line was removed from the lab account, and the non-root run confirmed the account's own file stayed untouched.

## 5. Scores (0–10; weights: Security 30, Correctness 25, Reliability 20, Maintainability 15, Compatibility 10)

| Change | Sec | Corr | Rel | Maint | Compat | Weighted |
|---|---|---|---|---|---|---|
| Vault write path / locking / format (ad360e0) | 9 | 9 | 9 | 8 | 9 | **8.9** |
| SSH invocation + read-only agent (89bfe10) | 9 | 9 | 8 | 8 | 8 | **8.6** |
| Key input / password policy / CLI (b25cddc) | 9 | 9 | 8 | 9 | 8 | **8.7** |
| Supply chain (3d8debe, cb948be, 769f5b2) | 8 | 9 | 9 | 9 | 9 | **8.7** |
| Memory hardening (S-11, part of b25cddc) | 6 | 9 | 9 | 9 | 10 | **8.2** |

Scores below 9 reflect the documented residual risks, not failing checks.

## 6. Test results (final, commit 9d3b382 + docs)

```
go build ./...                                   exit 0
go vet ./...  (and -tags integration)            exit 0
staticcheck ./...  (and -tags integration)       exit 0
govulncheck ./...                                exit 0  (0 reachable)
go test -count=1 ./...                           exit 0  (80 passing tests and subtests)
go test -race -count=1 ./...                     exit 0
go test -tags integration -run Integration ./sshutil/   exit 0  (6 PASS)
fuzz: 4 targets × 45 s                           no failures
CI run 42459809140: 11/11 jobs green (ubuntu, macOS, Windows tests; lint; integration; 6 cross-builds)
```

## 7. Unresolved risks

| # | Risk | Disposition |
|---|---|---|
| R-1 | `Entry.Key` is a Go `string`; no `mlock` | ACCEPTED_RISK (D-07); attacker needs same uid/root |
| R-2 | Same-uid process can request signatures from the session agent while `connect` runs | ACCEPTED_RISK (audit D-9); limited to List/Sign, socket 0700/0600, lifetime = session |
| R-3 | ProxyJump/ProxyCommand behaviour | **Resolved**: covered by `TestIntegrationProxyJump` (d88b814). ProxyCommand runs a user-chosen command that also doesn't receive the vault socket; it is not separately tested |
| R-4 | Windows: no ACL check; `connect` unsupported | ACCEPTED_RISK / BLOCKED (D-09, D-10) |
| R-5 | GO-2026-5932 module advisory (unreachable) | ACCEPTED_RISK (D-11) |
| R-6 | Release provenance untested until the first tag is pushed | The workflow is syntax-checked and its steps mirror the CI build; it creates drafts only |

## 8. Security sign-off

**Decision: PASS for Phase 1, with the accepted risks above.** Every CONFIRMED security finding is FIXED and guarded by a regression test. Agent forwarding protection is validated against a real sshd with a hostile config. Vault compatibility (two fixtures made by the original code) and recovery tests pass. No known unmitigated release-blocking issue remains. The Windows `connect` gap is a missing feature that fails closed, not a vulnerability.
