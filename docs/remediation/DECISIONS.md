# Decisions

Architectural decisions, rejected approaches, compatibility trade-offs and accepted risks.

## Process note

The engineering-team roles (security architect, crypto/SSH specialist, red team, Go engineer, QA, architect, UX, independent reviewer) were **simulated sequentially by one agent**. No independent subagents were used. To offset this, every security claim is backed by an executable check rather than a review opinion: a regression test, a lab run against a real sshd, a mutation check (disable the fix, watch the test fail) or a rerun of the original code.

---

## D-01 Canonical module path: `github.com/sshman-org/sshman`
- **Context:** `go.mod` declared `sshman-org/sshman` (commit `1837f15`, "Update go.mod"), while the imports used the fork path.
- **Decision:** keep the module line and rewrite the imports. It matches the README's pkg.go.dev badge, the upstream repository and the audit's recommendation. This fork builds and tests unchanged; `go install` users should install from upstream.
- **Rejected:** reverting `go.mod` to the fork path, which would split the module identity from upstream.

## D-02 Toolchain: `go 1.26.0`, `toolchain go1.26.10`
`golang.org/x/crypto v0.58.0` (needed for S-08/S-07) requires Go ≥ 1.26. The toolchain is pinned to the newest 1.26 patch release so that stdlib advisories are fixed in builds. Go 1.27.3 was also available; 1.26 keeps the minimum as low as the dependency allows.

## D-03 Vault format v2
- Header `SSHMAN|ver|kdf|t|m|p|saltLen|salt|nonce` is passed whole as GCM additional data.
- AES-256-GCM and Argon2id are kept: no evidence justified a change.
- New parameters follow RFC 9106's second recommendation (t=3, m=64 MiB, p=4). Unlock costs about 57 ms on the test machine.
- Header parameters are bounded on read (t ≤ 16, m ≤ 1 GiB, p ≤ 64, salt 16–64 bytes), and files over 64 MiB are refused, so a planted file cannot force huge allocations.
- The payload is a JSON object `{"entries": [...]}`, which leaves room for vault-level metadata later.
- **Compatibility:** v1 is read indefinitely. Any write upgrades to v2, and the v1 bytes stay as `.bak`, so downgrading means copying `.bak` back. A fixture produced by the unmodified original code is tested (`vault/testdata/legacy-v1.vssh`).
- **Rejected:** changing the cipher or KDF; a separate MAC over the header (GCM AAD already covers it).

## D-04 Legacy password trimming
Older versions trimmed the typed password. New passwords are used exactly as typed. If the exact password fails to open a vault, the trimmed form is tried once, which costs one extra KDF only on failure. A vault opened that way keeps the trimmed password (it is not silently changed), and `passwd` sets an exact one. Tested with a fixture made by the original code (`cmd/testdata/legacy-trimmed.vssh`).

## D-05 Password policy: ≥ 12 characters, not whitespace-only
Applies to `init` and `passwd` only. Existing vaults with shorter passwords still open, with a warning to run `passwd`. A strength estimator (zxcvbn) was **rejected**, because it adds a heavy dependency for marginal benefit over a length rule that encourages passphrases.

## D-06 Vault location and file-safety rules
- **Default path:** `os.UserConfigDir()/sshman/vault.vssh`, with the directory created 0700. Resolution order: `--vault` (global or per-command), then `$SSHMAN_VAULT` (a path, never a secret), then the default. A `./vault.vssh` from older versions is still used, with a warning, when the default doesn't exist. Nothing is moved automatically.
- **Unix refusals:** a symlinked vault or lock file (opened `O_NOFOLLOW`); a vault owned by another uid; a vault with any group/other permission bits (the same rule as OpenSSH private keys, with a `chmod 600` hint); a directory owned by someone other than you or root; a world-writable, non-sticky directory.
- **Group-writable, non-sticky directory: warning only.** Ubuntu's default umask (002 with per-user groups) produces such directories. Members of the group can delete or replace the vault (DoS) but cannot read it, redirect writes (random O_EXCL temp names, no symlink following) or substitute a vault that the victim's password opens. Making it fatal would have broken existing CWD vaults.
- **Rejected:** auto-`chmod` of an existing vault (silently changing user files); following symlinks after resolving them (users can pass the real path).

## D-07 Secrets in memory (S-11): partial, residual risk accepted
- **Done:** passwords and passphrases stay `[]byte` and are zeroed; no password is converted to `string`. Core dumps are disabled (`RLIMIT_CORE=0`), and on Linux `PR_SET_DUMPABLE=0` blocks same-user ptrace and `/proc/<pid>/mem`.
- **Accepted:** `Entry.Key` stays a `string`. Making it `[]byte` changes the JSON codec and every caller, and with Go's moving GC zeroing still couldn't be guaranteed. The attacker who could read this memory (same uid or root) can also keylog the vault password. There is no `mlock`, for the same reason and because of portability.
- Documented in the README security model.

## D-08 Agent and ssh invocation
- **Always:** `IdentityAgent=<session socket>`, `IdentityFile=<public key>`, `IdentitiesOnly=yes`, `ForwardAgent=no`, `AddKeysToAgent=no`, `PasswordAuthentication=no`, and `--` before the destination.
- **`SSH_AUTH_SOCK` is not replaced.** ProxyJump/ProxyCommand children therefore use the user's own agent, not the vault key. This matters because `ForwardAgent=no` on our command line doesn't propagate to the jump-host ssh.
- **Socket path safety:** paths are restricted to `[A-Za-z0-9/._-]`, because ssh_config expands `%`, `~` and `${}`. Paths are kept under 100 bytes for macOS `sun_path`, falling back to `/tmp`.
- **Read-only agent:** List and Sign only.
- **`ConfirmBeforeUse`: evaluated, rejected.** The only intended client is the child ssh that the user just started. A confirmation prompt per signature adds friction without a separate trust decision, and x/crypto's keyring has no UI for it.
- **Rejected:** `-F none`, which breaks aliases, jump hosts and corporate configs (audit D-3); forcing `ClearAllForwardings=yes` on `connect`, which breaks deliberate port forwarding (set for `sendkey` only); a per-entry agent-forwarding opt-in, which would need a separately reviewed authorization design. Forwarding is simply off.
- **Host keys:** the user's `StrictHostKeyChecking` policy applies, and OpenSSH's own prompt shows the fingerprint. `--accept-new-host-key` is an explicit opt-in. Per-entry host-key pinning is backlog (F-09).

## D-09 Windows file permissions
POSIX mode checks are skipped on Windows. ACL inspection (owner-only DACL) is not implemented. The vault is created in the per-user AppData directory. Its inherited ACL normally grants access to the user, SYSTEM and Administrators, not to other standard users, but sshman does not verify this. Locking uses `LockFileEx`, verified on Windows CI by the concurrency tests. **Accepted risk** until ACL checks are added (backlog F-12).

## D-10 Windows `connect`: BLOCKED
Win32-OpenSSH's `ssh.exe` reads the agent from a named pipe. Serving one securely (with a DACL restricted to the current user) needs either `go-winio` (a new dependency) or about 150 lines of `x/sys/windows` code. It also can't be validated in this environment, only on a Windows runner with interactive OpenSSH. Rather than ship an untested agent transport on the credential path, `connect` and `sendkey --via` return a clear error on Windows. Vault management, `genkey`, `sendkey` (without `--via`), `copy` and `doctor` work, and the unit suite passes on Windows CI. The README doesn't claim Windows `connect` support.

## D-11 GO-2026-5932 (x/crypto/openpgp)
The module-level advisory is fixed only in a pseudo-version (`v0.58.1-0.2026…`). sshman doesn't import `openpgp`, and govulncheck reports it as not called. Pinning a pseudo-version for an unreachable package was rejected; Dependabot will pick up the next tagged release.

## D-12 Backups
The previous vault is hard-linked to `<vault>.bak` before each replacement (falling back to a copy), so recovery needs no extra I/O. `passwd` replaces the backup with the re-encrypted vault after verifying it, so no copy under the old password is left by sshman. Copies elsewhere, such as filesystem snapshots or cloud sync, are outside its control and documented. `restore` keeps the replaced file as `<vault>.corrupt`.

## D-13 RSA sizes
New keys: 3072 (default) or 4096. Imports: ≥ 2048, since existing 2048-bit keys are still acceptable to NIST through 2030. DSA is rejected. Ed25519 stays the default. `genkey` now writes OpenSSH-format private keys, which `ssh-keygen` can read. Existing PKCS#1/PKCS#8 entries keep working.

## D-14 Behaviour changes users may notice
`list` output is sorted (favorites first) and prefixed with a favorite marker. Success messages and the banner go to stderr. `delete` asks for confirmation (`--yes` to skip). Raw `--key` text is refused. `connect` no longer auto-accepts unknown host keys. The default vault moved to the config directory (the old path still works with a warning). All of these are listed in the README "Upgrading" section.

## D-15 Rejected / deferred features
These were not implemented: connection history (a write per connect churns the backup and records metadata); cloud sync; OS keychain caching; TUI and GUI; FIDO2 keys (x/crypto can't sign with `sk-*` private keys in-process). See the phase-4 report for scores.
