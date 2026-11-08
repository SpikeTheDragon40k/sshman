# 03 — Security Findings

**Severity:** CRITICAL / HIGH / MEDIUM / LOW / INFO.
**Evidence status:** CONFIRMED / CODE-SUPPORTED / POTENTIAL / NOT REPRODUCED / FALSE POSITIVE.
No CVSS numbers are given: the preconditions vary too much by deployment for a single vector to be honest.
Line numbers refer to `HEAD` = `0a430e9`. PoC commands and output are in §"Evidence log" at the bottom.

| ID | Title | Severity | Status | Confidence |
|---|---|---|---|---|
| S-01 | Vault key exposed to remote host via agent forwarding | MEDIUM | CONFIRMED | High |
| S-02 | Private key in process argv / shell history (`--key` raw mode) | MEDIUM | CONFIRMED | High |
| S-03 | Fixed `.tmp` path: symlink following, inherited permissions | MEDIUM | CONFIRMED | High |
| S-04 | Empty / whitespace-only vault password accepted | MEDIUM | CONFIRMED | High |
| S-05 | TOFU `accept-new` overrides stricter user host-key policy | LOW | CONFIRMED | High |
| S-06 | ssh option injection via leading `-` in user field | LOW | CODE-SUPPORTED | Medium |
| S-07 | Unconstrained in-process agent (no confirm/lifetime) | LOW | CODE-SUPPORTED | High |
| S-08 | Reachable known vulnerabilities in dependencies / toolchain | LOW | CONFIRMED (govulncheck) | High |
| S-09 | Tracked, non-reproducible prebuilt binary with outdated deps | LOW | CONFIRMED | High |
| S-10 | Insecure vault permissions / location not detected | LOW | CONFIRMED | High |
| S-11 | Secret lifecycle in memory (strings, ineffective zeroing) | LOW | CODE-SUPPORTED | High |
| S-13 | `sendkey` appends unvalidated trailing lines of `PubKey` | LOW | CODE-SUPPORTED | Medium |
| S-14 | Passphrase-protected keys unsupported → forces plaintext key import | LOW | CONFIRMED | High |
| S-12 | Vault format lacks version/KDF parameters (crypto agility) | INFO | CODE-SUPPORTED | High |

Disproven or downgraded candidates (FALSE POSITIVE): gosec G204 (command injection) and G304 (file inclusion). See 08-review-debate.md, D-6.

---

## S-01 — Vault key exposed to remote host via agent forwarding
- **Files:** `sshutil/ssh.go:42-48` (hardening args), `:89-99` (ssh invocation)
- **Explanation:** `Connect` loads the decrypted key into `agent.NewKeyring()` and points `SSH_AUTH_SOCK` at it. The ssh options set only `StrictHostKeyChecking`, `PasswordAuthentication` and `IdentitiesOnly`, so everything else in `~/.ssh/config` still applies. A config with `ForwardAgent yes` (common as `Host *` in convenience setups) forwards the **vault key** to the remote host. `IdentityAgent` and `ProxyCommand` from the user config also apply.
- **Evidence:** Lab test E (evidence log): with `~/.ssh/config` `Host * / ForwardAgent yes`, running `sshutil.Connect` unmodified gave a remote shell where `ssh-add -l` printed the vault key fingerprint `SHA256:xhR90ES7…`.
- **Preconditions:** `ForwardAgent yes` in the user config, and the remote host is compromised or malicious. Today it also requires `connect` to work at all (Q-02). **Fixing Q-02 makes this reachable for every user with forwarding enabled.**
- **Impact:** For the length of the session, remote root can authenticate as the user to any other server that trusts the key.
- **Remediation:** Add `-o ForwardAgent=no`, `-o IdentityAgent=<sock>` and `-o ClearAllForwardings=yes` (or document forwarding as opt-in per entry). Consider `-F none` plus an explicit option allowlist, at some usability cost (see 08 D-3).
- **Regression test:** Run against a local sshd with a hostile `~/.ssh/config` (`ForwardAgent yes`). The remote `ssh-add -l` must fail.

## S-02 — Private key in process argv / shell history
- **File:** `cmd/cmd.go:51-63` (`resolveKeyInput`); flags `:121`, `:316`
- **Explanation:** If `--key` is not an existing file, its **value is treated as the key**. The README advertises this ("accepts a file path or raw PEM string"). Argv is world-readable on Linux (`/proc/<pid>/cmdline`, `ps`) unless `/proc` is mounted with `hidepid`, and it is saved in shell history.
- **Evidence:** Test H: a process started with `--key "$(cat key)"` exposed `-----BEGIN OPENSSH PRIVATE KEY-----` through `/proc/<pid>/cmdline`, mode `-r--r--r--`.
- **Preconditions:** The user takes the raw-PEM path, and another local user is polling `/proc` (multi-user host or shared CI runner). History exposure needs no other user at all.
- **Impact:** Disclosure of the plaintext private key.
- **Remediation:** Remove raw-value input. Accept a file path, or `-` for stdin. Fail if the path doesn't exist (this also fixes Q-06).
- **Regression test:** `resolveKeyInput("not-a-file")` must return an error; `--key -` must read stdin.

## S-03 — Fixed `.tmp` path: symlink following and inherited permissions
- **File:** `vault/vault.go:104-128`
- **Explanation:** `Save` writes `path+".tmp"` with `os.WriteFile` (`O_CREATE|O_TRUNC`, no `O_EXCL`, no `O_NOFOLLOW`), then renames it over the vault. The `0600` mode only applies when the file is newly created.
- **Evidence (CONFIRMED, test P1/P2):**
  - P1: with a symlink `vault.vssh.tmp → victim.txt`, `Save` returned `nil`. `victim.txt` was overwritten with 96 bytes of ciphertext, and **`vault.vssh` became a symlink to the victim file**.
  - P2: a pre-existing `0644` `.tmp` left the final vault at `-rw-r--r--`.
- **Preconditions:** The attacker can create files in the vault's directory. The default is the **CWD** (`cmd/cmd.go:19`), so running sshman in `/tmp`, a shared project tree or a group-writable directory qualifies. In sticky `/tmp`, `fs.protected_symlinks` blocks following *another user's* symlink, which reduces but does not remove the risk (group-writable directories aren't sticky).
- **Impact:** Arbitrary overwrite of any file the user can write (integrity / DoS). The vault ends up readable by the attacker, enabling offline guessing (S-04, S-12). The attacker can later swap the vault behind the symlink.
- **Remediation:** Use `os.CreateTemp(dir, ".vault-*")` (O_EXCL, random name, 0600), `Fchmod(0600)`, `Sync`, `Rename`, then fsync the directory. Refuse a vault path that is a symlink or not owned by the current user.
- **Regression test:** Tests P1 and P2 from the evidence log, inverted: `Save` must not touch the symlink target, and the final vault mode must be `0600`.

## S-04 — Empty / whitespace-only vault password accepted
- **File:** `cmd/cmd.go:21-33` (`TrimSpace`, line 28), `:93-104` (`init`)
- **Explanation:** There is no minimum length or strength check. `TrimSpace` turns `"   "` into `""`, and also silently changes passphrases with leading or trailing spaces.
- **Evidence:** Test P4: `Save(path, "", …)` and `Load(path, "")` succeeded and returned `Key="SECRET"`.
- **Preconditions:** The user picks an empty or trivial password (no friction stops them). The attacker obtains the vault file (S-03, backups, synced folders).
- **Impact:** Instant decryption of every stored private key.
- **Remediation:** Enforce a minimum length (e.g. at least 12 characters) and reject empty input in `init`. Keep whitespace as entered rather than trimming. Optionally estimate strength (e.g. zxcvbn) without adding heavy dependencies.
- **Regression test:** `init` with `""` or `"   "` must fail. A password with surrounding spaces must round-trip exactly.

## S-05 — TOFU `accept-new` overrides stricter user policy
- **File:** `sshutil/ssh.go:44`
- **Evidence:** Lab T1: the first connect printed `Permanently added '[127.0.0.1]:2222'` with no prompt. T4: with the user config set to `StrictHostKeyChecking yes`, `ssh -G -o StrictHostKeyChecking=accept-new …` resolved to `accept-new`, because command-line options take precedence.
- **Impact:** A first-connection MITM is silently pinned. The cryptographic damage is limited: public-key signatures are bound to the session ID, so the key can't be relayed. Combined with S-01, though, a MITM receives a forwarded agent. Typed commands and secrets in the session are exposed to the MITM.
- **Remediation:** Don't override the user's policy. Remove the option, or only set it when the user hasn't configured one. Show the host-key fingerprint on first use, and optionally pin it in the entry (`Entry.HostKey`) and pass it via a dedicated `UserKnownHostsFile`.
- **Regression test:** Assert that the ssh arguments don't contain `StrictHostKeyChecking`, or (with a pinned key) that the connection fails against an sshd with a mismatched key.

## S-06 — ssh option injection via leading `-` in user field
- **File:** `sshutil/ssh.go:18` (`validUserRe` allows a leading `-`), `:89-93`, `:120`; `model/entry.go:17`
- **Explanation:** `Addr()` = `user@host` is passed as a positional argument with no `--` before it. `ValidateEntry` accepted `-Fevil`, `-Jattacker` and `-v` (test P6). `ssh -Fevil@host` parses as `-F evil@host`, a config file relative to the CWD. The regex blocks `=`, `/` and spaces, so `-oProxyCommand=…` is rejected.
- **Evidence:** CODE-SUPPORTED. `ssh -G … -Fevil@127.0.0.1` consumed the destination as an option argument (usage error). A full exploit would need a planted `evil@host` config file containing `ProxyCommand`.
- **Preconditions:** The attacker gets a malicious user value into an entry (social engineering), *and* can plant a file in the victim's CWD.
- **Remediation:** Reject a leading `-` in user and host. Insert `--` before the destination in both ssh invocations.
- **Regression test:** `ValidateEntry` rejects `-x` for both user and host. The arg slice contains `--` immediately before the destination.

## S-07 — Unconstrained in-process agent
- **File:** `sshutil/ssh.go:55-87`
- **Explanation:** `agent.AddedKey{PrivateKey: rawKey}` has no `LifetimeSecs` and no `ConfirmBeforeUse`. The socket directory is created 0700 by `MkdirTemp`, so only the same uid or root can connect. That is good, but any same-uid process can sign with the key during the session. Note GO-2026-5005 ("key constraints not enforced in x/crypto/ssh/agent", fixed in v0.52.0): constraints only help once x/crypto is upgraded.
- **Remediation:** Upgrade x/crypto. Use a read-only agent wrapper that implements only `List` and `Sign` and refuses `Add`, `Remove`, `Lock` and extensions. Optionally set `ConfirmBeforeUse`.
- **Regression test:** An agent client against the socket: `Add` and `RemoveAll` return errors; `List` returns exactly one key.

## S-08 — Reachable known vulnerabilities (deps / toolchain)
- `govulncheck ./...` (scratch copy, Go 1.24.7, x/crypto v0.45.0, exit 3) found **9 reachable vulnerabilities**:
  - x/crypto (fixed in v0.52.0):
    - GO-2026-5033: client panic
    - GO-2026-5018: RSA/DSA parameter DoS via `NewSignerFromKey`
    - GO-2026-5006: agent constraints dropped when forwarding
    - GO-2026-5005: key constraints not enforced
  - stdlib (fixed in go1.24.8 to go1.25.13):
    - GO-2026-5972 and GO-2025-4011: asn1
    - GO-2025-4009: pem
    - GO-2025-4007: x509
    - GO-2026-4971: net (Windows NUL)
- **Exploitability:** low. Most traces go through parsing the user's *own* vault key (`ParseRawPrivateKey`). The SSH protocol is handled by OpenSSH, not x/crypto's client. The realistic impact is local DoS.
- **Remediation:** Bump `golang.org/x/crypto` to ≥ v0.52.0 and the Go toolchain to a supported patch release. Add `govulncheck` to CI.

## S-09 — Tracked, non-reproducible prebuilt binary
- **Evidence:** `git ls-files` includes `sshman` (7.9 MB) even though `.gitignore` lists it. `go version -m sshman`: `go1.23.0`, module path `github.com/SpikeTheDragon40k/sshman`, x/crypto **v0.39.0**, `vcs.revision=cdab5ae…`, **`vcs.modified=true`** (built from an uncommitted tree). `govulncheck -mode=binary`: 6 vulnerabilities, including GO-2026-5020 and GO-2026-5013 in x/crypto/ssh and GO-2025-3956 in `exec.LookPath`. Because `HEAD` doesn't build (Q-01), this binary is the only runnable artifact a user sees.
- **Impact:** The binary's provenance can't be verified and it carries known vulnerabilities. There is **no evidence of malicious content**, and none was looked for by disassembly.
- **Remediation:** `git rm --cached sshman`. Publish release builds from CI with checksums, provenance and signing (e.g. GoReleaser + cosign / SLSA).

## S-10 — Insecure vault permissions / location not detected
- **Files:** `vault/vault.go:96-102`, `cmd/cmd.go:19`
- **Evidence:** Test P3: a vault `chmod 0666` loaded with no warning. The default vault path is CWD-relative, so the vault's location (and its directory's permissions) depends on where the user runs the command.
- **Remediation:** Default to `$XDG_CONFIG_HOME/sshman/vault.vssh` (or `os.UserConfigDir()`) with a 0700 directory. On load, warn or refuse if the file is group- or world-accessible or owned by another uid (Unix).

## S-11 — Secret lifecycle in memory
- **Files:** `cmd/cmd.go:28-31`, `vault/vault.go:36,43,73,87`, `model/entry.go` (`Key string`)
- **Explanation:**
  - `readPassword` zeroes the byte slice *after* copying it into an immutable `string`, so the copy survives.
  - `deriveKey` converts the password with `[]byte(password)`, creating another copy.
  - `zeroBytes(plaintext)` after `json.Unmarshal` doesn't touch the decoded strings.
  - `ParseRawPrivateKey` produces big-int / ed25519 copies.
  - There is no `mlock` and core dumps aren't disabled.
- **Impact:** Bounded by T2/T7 (same-uid or root memory access), which sshman can't stop anyway. LOW / defense in depth. The Go GC limits what can be done.
- **Remediation:** Keep secrets as `[]byte` end to end (`Entry.Key []byte` with a custom JSON codec), zero them on exit paths, call `unix.Prctl(PR_SET_DUMPABLE,0)` and set `RLIMIT_CORE=0` on Linux, and document the limitation. Don't over-invest in this.

## S-13 — `sendkey` appends unvalidated trailing lines
- **File:** `sshutil/ssh.go:104-127`
- **Explanation:** `ssh.ParseAuthorizedKey` validates the *first* key and returns `rest`. The code ignores `rest` and appends the whole `TrimSpace(PubKey)`, so additional lines go into the remote `authorized_keys` too, including option-bearing ones such as `command="…"` or `from=`. The single-quote escaping (`'"'"'`) is correct for POSIX shells. **No remote command injection was found.** The append is also not idempotent (it duplicates lines).
- **Remediation:** Re-marshal with `ssh.MarshalAuthorizedKey(pub)` plus the comment, and reject a non-empty `rest`. Make the append idempotent (`grep -qxF … || echo … >>`).

## S-14 — Passphrase-protected keys unsupported
- **Evidence:** Test F: an `ssh-keygen -N <pass>` key gave `failed to parse private key: ssh: this private key is passphrase protected` at **connect** time. `add` accepted it without complaint.
- **Impact:** Users must strip the passphrase to use sshman, and the README workflow (`--key ~/.ssh/myserver.key`) leaves that plaintext file on disk. This contradicts the "no keys saved as separate files" goal.
- **Remediation:** Parse on `add` (Q-06). Support `ParseRawPrivateKeyWithPassphrase` with a prompt on import, then store the decrypted key inside the vault. Recommend that users securely delete the source file.

## S-12 — Vault format lacks version / KDF parameters (INFO)
- **File:** `vault/vault.go:14-23`
- **Analysis:** Argon2id t=2, m=64 MiB, p=4 meets the OWASP minimum guidance and sits a little below RFC 9106's second recommended profile (t=3, m=64 MiB). The parameters are hard-coded, and the file layout `salt‖nonce‖ct` has no magic number or version, so they can never be raised without breaking existing vaults. The unauthenticated header is not exploitable: changing the salt changes the key and GCM fails. See 05 §3.
- **Remediation:** Use a versioned header `magic|ver|t|m|p|salt|nonce`, passed as GCM additional data. Keep backward-compatible reading. Add a `passwd` command that re-encrypts with current parameters.

---

## Evidence log (commands run; synthetic keys only)

Environment: Linux 6.18, Go 1.24.7, OpenSSH (Ubuntu 24.04 packages). Scratch copy at `$SCRATCH/copy`, with `go.mod` module line changed to `github.com/SpikeTheDragon40k/sshman` **in the copy only**.

| Test | Command / harness | Result |
|---|---|---|
| P1 | `vault/poc_audit_test.go:TestPoC_SymlinkTmp` | `Save err=<nil>; victim overwritten=true (len=96); vault is symlink=true -> ".../victim.txt"` |
| P2 | `TestPoC_TmpModeInherited` | `vault mode after Save with pre-existing 0644 .tmp: -rw-r--r--` |
| P3 | `TestPoC_LoadInsecurePerms` | `Load of 0666 vault err=<nil>` |
| P4 | `TestPoC_EmptyPassword` | `Save("") err=<nil>; Load("") err=<nil>; recovered key="SECRET"` |
| P5 | `TestPoC_ConcurrentSave` (200 rounds × 4 goroutines) | `vault unreadable afterwards in 1 rounds; Save errors=77` (the race-detector failure came from the harness's own counter, not app code) |
| P6 | `cmd/poc_audit_test.go:TestPoC_ArgInjectionUser` | `-Fevil`, `-Jattacker`, `-v` accepted; `-oProxyCommand=x` rejected |
| P7 | `TestPoC_KeyTypoStoredAsKey` | `key="~/.ssh/id_ed25519_typo" ValidateEntry=<nil>` |
| P8 | `TestPoC_DuplicateNames` | `FindByName -> h1; DeleteByName removed 2 entries` |
| T1 | `sshutil.Connect` → localhost sshd:2222, empty `~/.ssh` | `Permanently added…`, then `Permission denied (publickey,password)`, exit 255 |
| A/B | Replicated agent + ssh with `IdentitiesOnly=yes` vs `=no` | A: `Permission denied`; B: `AUTH_OK` (isolates the cause of Q-02) |
| C/E | `ForwardAgent yes`; E used the real `Connect` with a matching `~/.ssh/id_ed25519.pub` | Remote `ssh-add -l` → `256 SHA256:xhR90ES7… (ED25519)` |
| T4 | `ssh -G -o StrictHostKeyChecking=accept-new` with user config `yes` | `stricthostkeychecking accept-new` |
| F | Connect with a passphrase-protected key | `ssh: this private key is passphrase protected` |
| H | `sh -c 'sleep 3' x --key "$(cat key)"` + read `/proc/$P/cmdline` | PEM header present; file mode `-r--r--r--` |

The lab user, sshd, keys and known_hosts were removed after testing.
