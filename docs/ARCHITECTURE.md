# Architecture

sshman is a single-process CLI. There is no daemon, no listener other than a per-session agent socket, and no network access of its own; all SSH traffic is handled by the OpenSSH `ssh` client.

```
main ──► cmd ──► app ──┬─► vault    encrypted file format, locking, atomic writes, path safety, backup
 (harden)  (flags)  (workflows)
                       ├─► sshutil  validation, key import, read-only agent, ssh / sendkey runner
                       ├─► keygen   ed25519 / RSA generation (OpenSSH format)
                       └─► model    Entry and pure helpers (no I/O)
```

| Package | Responsibility | Must not |
|---|---|---|
| `main` | Process hardening (`app.HardenProcess`), exit code | contain logic |
| `cmd` | Map urfave/cli flags onto `app`; print errors to stderr; exit codes | read files or prompt directly |
| `app` | Command workflows with injected stdin/stdout/stderr, `Prompter`, ssh options and clock; vault-path resolution; password policy; legacy-password fallback | depend on urfave/cli |
| `vault` | v1/v2 format, Argon2id + AES-GCM, `Load/Save/Create/Update/ChangePassword/Restore/Inspect`, lock file, O_NOFOLLOW, ownership/mode checks, `.bak` | import `sshutil` or know about the CLI |
| `sshutil` | `ValidateEntry`, `ParsePrivateKey`, `CanonicalAuthorizedKey`, read-only agent, `Connect`, `SendPublicKey` | touch the vault |
| `keygen` | Key generation | — |
| `model` | `Entry` (JSON schema of the vault payload), search and filter | perform I/O |

## Key flows

**Read command** (`list`, `show`, `connect`, …): `app.read` → prompt (tty) → `vault.LoadInfo` with a shared lock → decrypt → release the lock → act.

**Write command** (`add`, `update`, `delete`, …): `app.update` → prompt → `vault.Update`. The exclusive lock is held while the vault is decrypted, the change is applied, and the new vault is encrypted with a fresh salt and nonce, written to an O_EXCL temp file, fsynced, linked as the new `.bak`, renamed into place and the directory fsynced. The lock is then released. An error at any step leaves the previous vault intact.

**connect:**
1. Decrypt the entry and parse its key.
2. Create a 0700 session directory and write the public key to `id.pub` (0600).
3. Serve a read-only agent on `agent.sock` (0600).
4. Run `ssh -o IdentityAgent=<sock> -o IdentityFile=<id.pub> -o IdentitiesOnly=yes -o ForwardAgent=no … -- user@host [cmd]`.
5. Forward SIGTERM/SIGHUP to ssh; when it exits, close the listener and remove the directory.

**sendkey:** derive the canonical public-key line, then run `ssh -T -o ForwardAgent=no -o ClearAllForwardings=yes … -- user@host "sh -c '<idempotent append script>'"`. With `--via`, the same session agent as `connect` is used for the other entry's key.

## Extending

* **New entry fields:** add `omitempty`/`omitzero` fields to `model.Entry`; older vaults decode unchanged. Expose them in `app.EntryView` only if they contain no secrets.
* **New vault format version:** add a branch in `vault.decryptVault`, keep reading every older version, bump `currentVersion`, and add a fixture produced by the previous release.
* **New UI (TUI/GUI):** build on `app` with a custom `Prompter`; do not call `vault` or `sshutil` directly.
* **Agent transport:** `sshutil/platform_unix.go` serves the session agent on a 0600 unix socket, `sshutil/platform_windows.go` on an owner-only named pipe with overlapped I/O. Both return the `IdentityAgent` value; `TestSessionAgentEndpoint` and `TestConnectInprocServer` cover each platform.
