# 01 — Executive Summary

**Project:** `sshman`, a Go CLI SSH key and connection manager
**Revision audited:** `0a430e9` (branch `claude/ssh-key-manager-audit-cb9mkp`)
**Audit date:** 2026-11-07
**Method:** One agent simulated the seven reviewer roles in the brief (security, crypto/SSH, Go, desktop, red team, QA, architecture) **sequentially**. No independent parallel subagents were used. Reviews were static plus dynamic: PoCs ran on a scratchpad copy with synthetic keys and a localhost-only `sshd`. No application source was modified.

---

## Overall security posture

The cryptographic core is sound. The vault uses AES-256-GCM with a key derived by Argon2id from the password, with a fresh random salt and nonce on every save. No hard-coded keys, no insecure host-key callback (`ssh.InsecureIgnoreHostKey` is not used) and no shell-string command execution were found. Private keys stay inside the encrypted vault and never get written to disk as key files.

The risks are around that core:

1. **The product does not work as shipped.** `go build` fails at `HEAD` because the module path doesn't match the imports. Even with that fixed, `sshman connect` **cannot authenticate with the vault key** in a clean environment: `-o IdentitiesOnly=yes` stops ssh from offering the key held by sshman's in-process agent. Both are CONFIRMED.
2. **Key-exposure paths outside the vault:** the raw-PEM `--key` mode puts the private key in world-readable `/proc/<pid>/cmdline` and shell history. Agent forwarding is not disabled, so a user's `ForwardAgent yes` hands the vault key to the remote host. Both are CONFIRMED.
3. **Weak operational safeguards:** an empty or whitespace-only vault password is accepted. `Save` follows a planted `vault.vssh.tmp` symlink and keeps a planted file's permissions. Concurrent writes can corrupt the vault. All CONFIRMED.

## Findings by severity

| Severity | Security (03) | Engineering / reliability (04) |
|---|---|---|
| Critical | 0 | 0 |
| High | 0 | 2 (Q-01 build broken, Q-02 `connect` broken) |
| Medium | 4 | 2 |
| Low | 9 | 8 |
| Info | 1 | 4 |

## Top risks

| # | ID | Risk | Severity | Evidence |
|---|---|---|---|---|
| 1 | S-01 | Vault key forwarded to the remote host when the user's ssh_config enables `ForwardAgent` | Medium | CONFIRMED |
| 2 | S-02 | Private key exposed via process argv and shell history (`--key "<PEM>"`) | Medium | CONFIRMED |
| 3 | S-04 | Empty or whitespace-only vault password accepted (`TrimSpace`), so the vault is effectively plaintext | Medium | CONFIRMED |
| 4 | S-03 | `Save` follows a symlink at the fixed `.tmp` path (arbitrary file overwrite, vault redirect, inherited 0644 mode) | Medium | CONFIRMED |
| 5 | Q-02 / Q-03 | `connect` can't use the vault key; concurrent saves corrupt the vault (data loss) | High / Medium | CONFIRMED |

**Most concerning SSH key handling behavior:** sshman serves the decrypted private key from an unconstrained in-process agent. It then runs the system `ssh` with only three `-o` overrides, so the rest of the user's `~/.ssh/config` applies, including `ForwardAgent`, `IdentityAgent` and `ProxyCommand`. In the lab, a remote shell ran `ssh-add -l` and listed the vault key's fingerprint (02, 05, test E).

## Scope

In scope: every Go source file (`main.go`, `cmd`, `vault`, `model`, `sshutil`, `keygen`), the tests, `go.mod`/`go.sum`, README/SECURITY docs, the tracked prebuilt `sshman` binary, and git history for `go.mod` and the binary.

**NOT APPLICABLE / NOT IMPLEMENTED:** GUI, Electron, TUI, IPC, OS keychain integration, import/export or backup commands, update mechanism, logging subsystem, network services, CI/CD (no `.github/`).

## Limitations

- Linux only (Go 1.24.7, OpenSSH from Ubuntu 24.04). Windows and macOS behavior was reviewed from source only.
- Fuzz targets were designed, not run. Memory forensics (core dumps, swap) were not performed.
- `govulncheck` results reflect the Go vulnerability DB as of the audit date.
- To build, the module path was changed **in a scratch copy only**. The repository is unchanged apart from these reports.

## Release-readiness assessment

**Not release-ready.** The current `HEAD` doesn't build, and its headline `connect` feature doesn't authenticate. No Critical or High *security* vulnerability was found. Before any release, fix P0 items R-01 to R-06 in `06-remediation-roadmap.md`: build fix, `connect` identity/agent options with `ForwardAgent=no`, safe temp-file writes plus a lock, password policy, removal of raw-PEM argv input, and removal of the committed binary. The cryptographic design does not need a rewrite.
