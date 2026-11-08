# 05 — SSH & Cryptography Review

## 1. Vault encryption (`vault/vault.go`)

| Property | Implementation | Assessment |
|---|---|---|
| Cipher | AES-256-GCM (`aes.NewCipher` with a 32-byte key, `cipher.NewGCM`) | ✅ Authenticated encryption |
| Key derivation | `argon2.IDKey(pw, salt, t=2, m=64 MiB, p=4, 32)` | ✅ Argon2id; meets the OWASP minimum, slightly below RFC 9106's second profile (t=3) |
| Salt | 16 random bytes from `crypto/rand`, **regenerated on every save** | ✅ |
| Nonce | 12 random bytes per save | ✅ The key is unique per save (fresh salt), so random-nonce collision risk is moot |
| AAD | none | ⚠ INFO. The header isn't authenticated, but changing salt or nonce only causes decryption to fail. Not exploitable. Should be added together with a versioned header (S-12) |
| Format | `salt(16) ‖ nonce(12) ‖ ciphertext+tag` | ⚠ No magic number, version or parameters, so no crypto agility (S-12) |
| Error oracle | One error for a wrong password or tampering | ✅ No padding/format oracle; GCM tag check comes first |
| Randomness | `crypto/rand.Read` with errors checked | ✅ |
| Password policy | none; `TrimSpace` | ❌ S-04 |
| Re-keying | not implemented | ⚠ Q-11 |

**Offline brute-force cost** (stolen vault): each guess needs 64 MiB and two Argon2 passes, about 0.1–0.2 s on one modern core and much more expensive on GPUs than PBKDF2 or bcrypt. Security therefore depends on password entropy. An empty password is broken instantly (S-04).

**Tampering / key substitution:** an attacker without the password can't forge a vault (GCM). An attacker who **can write** the vault file can replace it with one encrypted under their own password, but the victim's password then fails to open it. That causes denial of service, not substitution. **NOT REPRODUCED / not possible** without the password.

## 2. Key generation (`keygen/keygen.go`)

- Ed25519 is the default: `ed25519.GenerateKey(crypto/rand)`, PKCS#8 "PRIVATE KEY" PEM. ✅
- RSA: `rsa.GenerateKey(crypto/rand, bits)`, minimum 2048, no maximum, PKCS#1 "RSA PRIVATE KEY". ⚠ Recommend 3072 as the default and an allowlist {3072, 4096} (Q-10).
- ECDSA, FIDO/`sk-*` keys and certificates are NOT IMPLEMENTED.
- Private keys are stored **unencrypted inside the vault**. That is acceptable, since the vault is the protection layer. The PEM types are parseable by `ssh.ParseRawPrivateKey` (verified in lab test E for Ed25519 PKCS#8). OpenSSH tools can't always read PKCS#8 Ed25519. Exporting (when implemented) should use `ssh.MarshalPrivateKey`, the OpenSSH format.
- The public key is derived from the generated key, so it can't be mismatched. Keys imported via `add` aren't checked for a matching public key (Q-06).

## 3. Key import (`cmd/cmd.go:51-63`)

- File path or **raw string**. Raw strings leak via argv (S-02, CONFIRMED).
- There's no parsing on import, so garbage or typo paths are stored (Q-06, CONFIRMED).
- Passphrase-protected keys are accepted on import but fail at connect (S-14, CONFIRMED). The workaround pushes users towards plaintext key files.
- The source file is left in place. Documentation should tell users to delete it securely.

## 4. Authentication path (`sshutil/ssh.go:50-102`)

1. `MkdirTemp("", "sshman-*")` creates a 0700 directory with a random name. ✅ No symlink race.
2. `ParseRawPrivateKey` → `agent.NewKeyring().Add` with **no constraints** (S-07).
3. A unix socket inside the 0700 directory; the accept loop goroutine; `defer` closes the listener and removes the directory. ✅ Cleanup happens on a normal return. On SIGINT, Go's default handler kills the process **without running defers**, so the socket directory stays in `$TMPDIR`. The key stays out of it, because the socket is just an inode and the keyring dies with the process. LOW.
4. `exec.Command("ssh", args...)`, resolved via `PATH` (a planted `ssh` earlier in `PATH` would win; that is the same trust as the user's shell). The environment is inherited plus `SSH_AUTH_SOCK`. Go's `exec` deduplicates, so the last value wins. ✅
5. ssh options:
   - `StrictHostKeyChecking=accept-new`: TOFU, and it **overrides a stricter user setting** (S-05, CONFIRMED).
   - `PasswordAuthentication=no`: OK for `connect`; breaks `sendkey` (Q-04).
   - `IdentitiesOnly=yes`: **prevents the agent key from being offered**, so `connect` fails (Q-02, CONFIRMED).
   - **Missing:** `ForwardAgent=no` (S-01, CONFIRMED), `IdentityAgent=<sock>` (a user's `IdentityAgent` setting overrides `SSH_AUTH_SOCK`), and `--` before the destination (S-06).

### Host-key verification
- No Go-side host-key callback exists; OpenSSH does the verification against `~/.ssh/known_hosts`. **`ssh.InsecureIgnoreHostKey` and equivalents are not used.** ✅
- Policy: TOFU (`accept-new`). Fingerprints aren't shown or stored per entry.
- Recommendation: honour the user's policy and optionally pin `HostKey` per entry (S-05).

### Agent forwarding
- Not disabled, so it follows the user config. Forwarding the vault key was CONFIRMED in the lab (S-01). Forwarding should be off by default, and opt-in per entry at most.

### Recommended invocation (combines the fixes for Q-02, S-01, S-05 and S-06)
```
ssh -o IdentityAgent=<tmp>/agent.sock \
    -o IdentityFile=<tmp>/id.pub -o IdentitiesOnly=yes \
    -o ForwardAgent=no -o PasswordAuthentication=no \
    [-p PORT] -- user@host
```
(Use `ClearAllForwardings=yes` optionally; leave `StrictHostKeyChecking` alone unless a host key is pinned.)

## 5. `sendkey` (`sshutil/ssh.go:104-127`)
- `ParseAuthorizedKey` validates only the first line; trailing lines are appended (S-13).
- Remote command quoting `'…'"'"'…'` is correct for POSIX `sh`, `bash` and `zsh`. With `fish` as the remote login shell, `&&` is supported (fish ≥ 3.0) and single-quote rules are similar. The `csh` family would choke on the syntax, which is a functional rather than an injection problem. **No injection found** for validated keys.
- Uses the user's own credentials, not the vault key (Q-04).

## 6. Secret lifecycle

| Stage | Where the secret is | Exposure / persistence | Finding |
|---|---|---|---|
| 1 Create / import | `genkey`: heap PEM string. `add`: file read or **argv** | argv / history / `/proc` (raw mode); source file stays on disk | S-02, S-14 |
| 2 Storage | Vault ciphertext. **`.tmp` sibling** during save | Symlink / permission issues on `.tmp`; CWD location | S-03, S-10 |
| 3 Unlock | Password: tty → `[]byte` → `string` (trimmed) → `[]byte` for argon2 | Several un-zeroable copies; empty password allowed | S-04, S-11 |
| 4 Retrieval | Decrypted JSON zeroed; `Entry.Key` strings persist on the heap | GC-managed copies | S-11 |
| 5 Authentication | Parsed key in the agent keyring; socket in a 0700 tmp directory | Same-uid processes can sign; **forwarding to remote** | S-07, S-01 |
| 6 Export / backup | NOT IMPLEMENTED (only the vault file itself) | n/a | Q-11 |
| 7 Deletion | `delete` rewrites the vault without the entry. The old ciphertext is overwritten by rename (new inode); old blocks may remain on disk, but they are encrypted | Acceptable | — |
| 8 Shutdown | Process exit frees memory (not zeroed). On SIGINT, defers don't run and the empty socket directory remains | Core dumps could contain keys if enabled | S-11 |

**Logging / IPC / clipboard leakage:** there is no logging subsystem. Errors don't include key material: `ParseRawPrivateKey` and JSON errors were checked and don't echo input. The clipboard only receives `ssh user@host -p N`. There is no IPC. ✅

**Go runtime caveat:** reliable zeroization isn't achievable with `string`s and a moving GC. The recommendations in S-11 are best-effort hardening, not guarantees.
