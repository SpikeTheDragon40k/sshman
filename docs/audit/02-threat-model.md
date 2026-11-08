# 02 — Threat Model

## 1. Actual architecture (as implemented)

A single statically linked Go CLI (`urfave/cli/v2`). There is no daemon, no network listener, and no GUI, TUI or Electron (NOT APPLICABLE). The process lives for one command.

| Package | Role |
|---|---|
| `main.go` | CLI entrypoint |
| `cmd/cmd.go` | Ten subcommands; password prompt (`term.ReadPassword`); `--key` file-or-raw resolution |
| `vault/vault.go` | Argon2id KDF + AES-256-GCM; `Load` / `Save` of the vault file |
| `model/entry.go` | `Entry{Name,User,Host,Port,Key,PubKey}`; find, delete, search |
| `sshutil/ssh.go` | Input regex validation; `Connect` (in-process agent + `exec ssh`); `SendPublicKey` (`exec ssh` with a remote shell command) |
| `keygen/keygen.go` | RSA (PKCS#1 PEM) and Ed25519 (PKCS#8 PEM) generation |

## 2. Data-flow diagram

```
                    TB1 (process argv: visible to all local users via /proc, ps)
 User ──argv flags──────────────┐
  │                             ▼
  └─password (tty, no echo)─► sshman process ─────────────────────────────────────┐
                                │  cmd: readPassword → string (TrimSpace)        │
                                │  resolveKeyInput(--key): file read OR raw text │
                                ▼                                                │
                      vault.Load/Save  ──TB2 (filesystem)──► ./vault.vssh        │
                      Argon2id(pw,salt)                       ./vault.vssh.tmp   │
                      AES-256-GCM                             (CWD, 0600 on create)
                                │                                                │
                 decrypted []Entry (Go heap, plaintext PEM strings)              │
                                │                                                │
        ┌───────────────────────┴───────────────────┐                            │
        ▼ connect                                   ▼ sendkey                    │
 agent.NewKeyring() + unix socket          exec ssh -o ... user@host "<sh cmd>"  │
 $TMPDIR/sshman-XXXX/agent.sock (dir 0700)        │ uses the USER's own ssh creds │
        │  SSH_AUTH_SOCK                           ▼                             │
        ▼                                 TB4 remote host: ~/.ssh/authorized_keys
 exec ssh -o StrictHostKeyChecking=accept-new -o PasswordAuthentication=no
          -o IdentitiesOnly=yes [-p N] user@host
        │   TB3: reads ~/.ssh/config, ~/.ssh/known_hosts (user-controlled)
        ▼
 TB4 remote sshd ──(if ForwardAgent yes in user config)──► remote can use vault key
                                                                                 │
 copy: clipboard ◄── "ssh user@host -p N" (no secrets) ◄─────────────────────────┘
```

## 3. Assets

| Asset | Where it lives | Sensitivity |
|---|---|---|
| A1 Private keys (PEM) | Vault ciphertext; process heap while running; agent keyring during `connect`; **argv** if passed raw | Critical |
| A2 Vault password | tty → heap (`string`) | Critical |
| A3 Vault file | `./vault.vssh` (CWD) | High (offline brute-force target) |
| A4 Host inventory (user, host, port) | Vault; printed by `list`/`search`; clipboard | Medium |
| A5 Public keys | Vault; remote `authorized_keys` | Low (integrity matters) |
| A6 known_hosts trust | `~/.ssh/known_hosts` (written by OpenSSH on accept-new) | High (integrity) |

## 4. Threat actors

| Actor | Capability | In scope |
|---|---|---|
| T1 Other unprivileged local user | Read `/proc/*/cmdline`; write to shared directories (`/tmp`, group-writable project dirs) | Yes |
| T2 Same-uid malware | Read and write everything the user can, ptrace, read the agent socket | Partly. sshman cannot defend against it; noted only |
| T3 Network attacker (MITM) | Intercept first connection to a new host | Yes |
| T4 Compromised or malicious remote server | Root on a host the user connects to | Yes |
| T5 Thief of the vault file / backup | Offline guessing | Yes |
| T6 Supply-chain attacker | Tampered binary or dependency | Yes |
| T7 root / physical access | Memory dumps | Out of scope (noted) |

## 5. Trust boundaries

- **TB1 argv / environment:** command-line flags are visible to other users (`/proc/<pid>/cmdline` is `-r--r--r--`; CONFIRMED). Shell history persists them.
- **TB2 filesystem:** the vault and its fixed `.tmp` sibling in the CWD; trust depends on directory permissions.
- **TB3 OpenSSH client + user config:** sshman hands authentication to `/usr/bin/ssh` (resolved via `PATH`), which also obeys `~/.ssh/config`.
- **TB4 remote host:** receives agent signing requests and, if forwarding is on, a forwarded agent channel.
- **TB5 clipboard:** receives only `ssh user@host -p N` (no secrets).

## 6. Attack surfaces

1. CLI flags (`--key`, `--user`, `--host`, `--vault`, `--bits`)
2. Vault file and temp-file path
3. Agent unix socket during `connect`
4. `ssh` subprocess: argument vector, environment, user ssh_config, `PATH` lookup
5. Remote shell command in `sendkey`
6. Dependencies (`x/crypto`, stdlib) and the committed prebuilt binary

## 7. Threat scenarios

| ID | Scenario | Actor | Finding | Status |
|---|---|---|---|---|
| TS-1 | User runs `sshman add --key "$(cat id)"`; another local user polls `/proc/*/cmdline` and captures the PEM | T1 | S-02 | CONFIRMED |
| TS-2 | User has `Host * ForwardAgent yes`; connects to a compromised box; remote root uses the forwarded vault key to reach other servers | T4 | S-01 | CONFIRMED (lab) |
| TS-3 | First connect to a new host via a hostile network; `accept-new` silently pins the attacker's key, even if the user's config says `StrictHostKeyChecking yes` | T3 | S-05 | CONFIRMED (`ssh -G`) |
| TS-4 | Vault kept in a shared or group-writable dir; attacker pre-creates `vault.vssh.tmp` as a symlink to a user file, or as a 0666 file; the next `Save` overwrites the target or leaves the vault readable | T1 | S-03 | CONFIRMED |
| TS-5 | User sets an empty or whitespace password; a stolen vault decrypts instantly | T5 | S-04 | CONFIRMED |
| TS-6 | Stolen vault with a typical human password; offline Argon2id guessing (~64 MiB and two passes per guess) | T5 | S-12 | Analysis |
| TS-7 | User downloads or runs the committed `sshman` binary, which can't be reproduced from source and was built with old toolchains | T6 | S-09 | CONFIRMED (provenance metadata) |
| TS-8 | An entry with `--user -Fx` is crafted (social engineering); ssh interprets it as an option | T1/T6 | S-06 | CODE-SUPPORTED |
| TS-9 | Two `sshman` invocations run concurrently (e.g. scripted); the vault is corrupted and every key is lost | n/a (reliability) | Q-03 | CONFIRMED |
| TS-10 | Same-uid malware connects to the agent socket during a session and signs freely | T2 | S-07 | CODE-SUPPORTED (accepted risk) |

## 8. Security model: claimed vs actual

| README claim | Actual |
|---|---|
| "keeps SSH private keys encrypted inside the vault file and loads them only in memory" | True for storage. But the key can enter via argv (S-02), the user's original key file stays on disk (S-14), and the key is exposed to any forwarded agent (S-01). |
| "Vault file permissions are set to 0600" | Only when the `.tmp` file is newly created; a pre-existing `.tmp` keeps its mode (S-03). Existing permissions are never checked (S-10). |
| "Tests and CI" done | No CI exists; `vault` tests do not compile at `HEAD` (Q-01, Q-08). |
| "SSH agent integration" listed as TODO | An in-process agent is already used by `connect`. |
