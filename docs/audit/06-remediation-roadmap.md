# 06 — Remediation Roadmap

Complexity: S = under 2 h, M = under 1 day, L = over 1 day. Work through the items in numbered order. No new third-party dependencies are needed; `golang.org/x/sys` is already an indirect dependency.

## P0 — Immediate (blocks any release)

| # | Task | Fixes | Complexity | Depends on | Security benefit |
|---|---|---|---|---|---|
| R-01 | Rewrite imports to `github.com/sshman-org/sshman/...`; add a CI workflow running `go build`, `go vet`, `go test -race` and `govulncheck` | Q-01, Q-07, Q-08 (CI) | S | — | Makes the tested code the shipped code |
| R-02 | Fix the `connect` invocation: temp `id.pub`, `IdentityAgent=<sock>`, `IdentitiesOnly=yes`, **`ForwardAgent=no`**, `--` before the destination; reject a leading `-` in user and host | Q-02, S-01, S-06 | S–M | R-01 | Stops vault-key forwarding; makes the core feature work |
| R-03 | Safe vault writes: `os.CreateTemp` in the same directory, 0600, sync, rename, directory fsync; refuse a symlinked or foreign-owned vault; `flock` around load→save; keep a `.bak` | S-03, Q-03, Q-15 | M | R-01 | Removes arbitrary overwrite and corruption/data loss |
| R-04 | Password policy: reject empty passwords, enforce a minimum length (≥ 12), stop `TrimSpace` (a compatibility note is needed: existing vaults whose password had surrounding spaces were stored trimmed, so try the trimmed form as a fallback on load) | S-04 | S | R-01 | Prevents a trivially decryptable vault |
| R-05 | Remove raw-PEM `--key`: accept a path or `-` (stdin) only; error on a missing file; parse and validate the key on import; derive or verify `PubKey` | S-02, Q-06 | S | R-01 | Removes argv / history key leakage |
| R-06 | `git rm --cached sshman`; release binaries only from CI with checksums and signatures | S-09 | S | R-01 | Supply-chain integrity |
| R-07 | Bump `golang.org/x/crypto` ≥ v0.52.0 and Go to a supported patch release | S-08, S-07 (GO-2026-5005) | S | R-01 | Clears 9 reachable advisories |

## P1 — High-priority hardening

| # | Task | Fixes | Complexity | Depends on | Benefit |
|---|---|---|---|---|---|
| R-08 | Stop overriding `StrictHostKeyChecking`; print the fingerprint on first use; optional per-entry pinned host key via a dedicated `UserKnownHostsFile` | S-05 | M | R-02 | Removes silent TOFU; MITM resistance |
| R-09 | Versioned vault header (`magic, version, argon2 t/m/p`) as GCM AAD; read legacy format; raise to t=3 | S-12 | M | R-03 | Crypto agility; clearer errors |
| R-10 | `passwd` command (re-encrypt under a new password and parameters) | Q-11, S-12 | S | R-09 | Password rotation after compromise |
| R-11 | Default vault in `os.UserConfigDir()/sshman/` (0700); warn or refuse on group/world-accessible files; global `--vault` and `SSHMAN_VAULT` | S-10, Q-09 | S | R-03 | Predictable, protected location |
| R-12 | Read-only agent wrapper (List and Sign only); optional `ConfirmBeforeUse` | S-07 | S | R-07 | Limits same-uid abuse of the socket |
| R-13 | Import passphrase-protected keys (prompt, decrypt, store) | S-14 | S | R-05 | Users stop keeping plaintext key files |
| R-14 | `sendkey`: re-marshal the key (reject trailing data), idempotent append, allow password/keyboard-interactive or a vault-key bootstrap | S-13, Q-04 | S | R-02 | Integrity of remote `authorized_keys`; feature works |

## P2 — Reliability & architecture

| # | Task | Fixes | Complexity |
|---|---|---|---|
| R-15 | `withVault` helper and an `app` layer so `cmd` can be tested without a tty (inject the password reader) | Q-09, Q-08 | M |
| R-16 | Unique entry names; reject duplicates; add `rename` | Q-05 | S |
| R-17 | RSA bits allowlist {3072, 4096}, default 3072 | Q-10 | S |
| R-18 | Errors to stderr; banner only on `init`/`--help`; distinct "not a vault" error once the header exists | Q-12 | S |
| R-19 | Test suite and fuzz targets from 07-test-plan.md | Q-08 | M |
| R-20 | Windows: named-pipe agent listener, or document `connect` as unsupported; matrix CI for linux, macOS and windows | Q-13 | M–L |

## P3 — Optional enhancements

| # | Task | Notes |
|---|---|---|
| R-21 | Core-dump suppression (`PR_SET_DUMPABLE`, `RLIMIT_CORE`); keep secrets as `[]byte` | S-11. Best effort, given the Go runtime |
| R-22 | Encrypted export/backup command (vault copy, or OpenSSH-format key export with a passphrase) | Q-11 |
| R-23 | OS keychain to cache the vault key for a short session | Increases complexity; only if users demand it |
| R-24 | Signal handling to clean up the socket directory on SIGINT/SIGTERM | §5.4 of 05 |
| R-25 | README rewrite (Q-16), including the threat model statement ("protects at rest; not against same-user malware") | Docs |

## Implementation order

R-01 → R-07 → R-02 → R-05 → R-03 → R-04 → R-06 → (P1: R-08, R-09 → R-10, R-11, R-12, R-13, R-14) → P2 → P3.
R-01 comes first because nothing else can be tested before it. R-02 together with R-07 removes the most serious exposure (S-01) and unblocks real use.
