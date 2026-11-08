# 07 — Test Plan

## 1. Current state (measured)

| Command (scratch copy, module path fixed) | Exit | Result |
|---|---|---|
| `go build ./...` (**repo as-is**) | 1 | module path mismatch (Q-01) |
| `go test ./...` (repo as-is) | 1 | keygen and model ok; vault `[setup failed]` |
| `go build .` (copy) | 0 | ok |
| `go test ./...` (copy) | 0 | keygen, model and vault ok; cmd, sshutil and main have no tests |
| `go test -race ./...` (copy) | 0 | ok |
| `go vet ./...` (copy) | 1 | `sshutil/ssh.go:89:10` and `:125:15` append with no values |
| `staticcheck ./...` | 1 | SA4021 ×2 (same lines) |
| `gosec -quiet ./...` | 1 | 10 issues: G204×2, G304×3 (FALSE POSITIVE), G104×5 (LOW) |
| `govulncheck ./...` | 3 | 9 reachable vulnerabilities (S-08) |
| `govulncheck -mode=binary sshman` (tracked binary) | 3 | 6 vulnerabilities (S-09) |

Existing tests cover: vault round-trip, wrong password, too-short/zero data, Save/Load, missing file, empty vault; model helpers; keygen output format.

## 2. Regression tests for confirmed findings

| Finding | Test | Type |
|---|---|---|
| Q-01 | CI `go build ./... && go vet ./...` | CI |
| S-03 | `Save` with `path.tmp` → symlink to a victim: the victim is unchanged; the vault is not a symlink; with a pre-existing 0644 temp file, the final vault mode is `0600` | unit (Unix) |
| S-03 | `Load`/`Save` refuse a vault path that is a symlink | unit |
| Q-03 | 4 goroutines × 200 rounds of locked `Mutate`: the vault always decrypts; the final entry count equals the number of successful mutations | unit, `-race` |
| S-04 | `init` rejects `""`, `"   "` and length < 12; `" pw with spaces "` round-trips exactly | unit with an injected password reader |
| S-02 / Q-06 | `resolveKeyInput("nonexistent")` returns an error; `-` reads stdin; non-key content is rejected; mismatched `PubKey` is rejected | unit |
| S-06 | `ValidateEntry` rejects user/host with a leading `-`; the built argv has `--` right before the destination | unit (export a `buildArgs` function) |
| Q-02 / S-01 | Integration: localhost sshd with an empty `~/.ssh` → `connect` succeeds; with `ForwardAgent yes` in a temp `HOME`'s ssh config, the remote `ssh-add -l` fails | integration (tagged `//go:build integration`; needs `sshd`) |
| S-05 | With the user config `StrictHostKeyChecking yes` and an unknown host, `connect` fails (doesn't auto-add) | integration |
| S-07 | An agent client on the socket: `Add`/`RemoveAll` fail; `List` returns 1 key | unit |
| S-13 | `PubKey` containing a second line or trailing data is rejected; the remote command contains exactly one key line | unit |
| S-14 | Importing a passphrase-protected key prompts and stores a decrypted key that `connect` can use | unit |
| Q-05 | Adding a duplicate name returns an error | unit |
| S-09 | CI check: `git ls-files` contains no ELF/PE binaries | CI |

## 3. Security and malformed-input tests

- Vault tampering: flip each byte of salt, nonce, ciphertext and tag; each must give the same generic error and no panic.
- Truncation at every length 0…N; must not panic.
- A huge vault file (e.g. 1 GiB of zeros): should be refused by a size cap before reading (add the cap).
- JSON inside a valid encryption: wrong types, deeply nested arrays (stack-depth DoS), 10⁶ entries.
- Hosts: IPv6 `[::1]`, zone `%eth0`, Unicode homoglyphs, 300-char names; ports -1, 0, 65536.
- `--bits` 1024 (reject), 65536 (reject once the allowlist exists).
- Password: 1 MiB input, NUL bytes, non-UTF-8 bytes.

## 4. Fuzz targets (Go native fuzzing)

```go
func FuzzDecryptVault(f *testing.F)      // arbitrary []byte + password → no panic, error or valid entries
func FuzzResolveAndValidate(f *testing.F) // arbitrary user/host/port → ValidateEntry; built args never start an element with '-' at destination
func FuzzSendKeyCommand(f *testing.F)     // arbitrary PubKey → either rejected, or the remote cmd is exactly one quoted line
func FuzzParseKeyImport(f *testing.F)     // arbitrary key bytes → parse error or valid signer; no panic
```
Run each for ≥ 10 minutes in CI nightly (`go test -fuzz=… -fuzztime=10m`).

## 5. Cross-platform validation

| Platform | Must verify |
|---|---|
| Linux (glibc, musl) | All of the above; permission checks; `flock` |
| macOS | `os.UserConfigDir` path; unix-socket agent with Apple's OpenSSH; `flock`; `$TMPDIR` length limits for socket paths (macOS caps `sun_path` at 104 bytes) |
| Windows 10/11 | Win32-OpenSSH agent transport (named pipe vs unix socket), Q-13; `LockFileEx`; ACL on the vault file (0600 has no meaning there; use `golang.org/x/sys/windows` to set an owner-only DACL); `term.ReadPassword` in cmd/PowerShell/Windows Terminal |

## 6. Reproduction harness used in this audit

The PoC tests (`TestPoC_*`) and the `harness` / `agentsrv` helpers were written in a **scratch copy** and were not committed. They are described in 03-security-findings.md §Evidence log, so they can be recreated as the regression tests above.
