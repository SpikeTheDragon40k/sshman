# Phase 3: improvements and modernization

Improvements made after the release blockers were closed. Each one either has measured value or removes a documented pain point. All Phase 1 and Phase 2 tests still pass.

## 1. Security improvements

| Item | Value | Status |
|---|---|---|
| Versioned, upgradeable KDF (v2 header) | Parameters can be raised later without breaking vaults; `passwd` and any write upgrade old vaults | Done |
| Password rotation (`passwd`) | Rotation after suspected compromise; leaves no old-password backup | Done |
| Encrypted automatic backup + `restore` | Recovery from corruption without manual work | Done |
| Vault diagnostics (`doctor`) | Reports unsafe permissions, symlinks, outdated format and missing ssh, without asking for the password | Done |
| Error classification | Distinct exit codes, plus "not a valid vault" vs "wrong password/corrupted"; the backup hint is shown when relevant | Done |
| Group-writable directory warning | Flags a real but non-confidentiality risk without breaking umask-002 users | Done |
| Configurable Argon2id from the CLI | **Not exposed.** Users can't weaken it below the recommended parameters, and raising it per user adds little; the header already supports it. Revisit if users ask | Deferred |
| Agent confirmation policy | Evaluated, rejected (D-08) | — |

## 2. Architecture

The `cmd → app → vault, model, sshutil, keygen` layering is in place (see phase-2 §2). Dependency injection points:
- `app.App` takes `Stdin`/`Stdout`/`Stderr`, a `Prompter`, `sshutil.Options` (`SSHPath` lets tests use a wrapper), `Clipboard` and `Now`.
- `cmd.Env` takes the streams, prompter and `Getenv`, plus a `Configure` hook.

No package imports `cmd`, `model` imports nothing internal, and the vault never imports `sshutil`. The codebase stays small: no framework beyond urfave/cli, and no new third-party module.

## 3. Performance (measured, Go 1.26.10, 4 vCPU Linux container)

| Benchmark | Result | Note |
|---|---|---|
| Unlock, recommended KDF (t=3, 64 MiB, p=4), 10 entries | **57 ms/op** | Argon2id dominates, by design |
| Save (lock, encrypt, fsync, rename, backup link), recommended KDF | **68 ms/op** | |
| Decrypt a 5000-entry vault (12.7 MB), fast KDF | **81 ms/op**, 158 MB/s | JSON + AES-GCM cost at a size far beyond expected use |
| Search over 5000 entries | **0.35 ms/op** | |
| Generate ed25519 | **0.2 ms/op** | |
| Generate RSA-3072 | **~204 ms/op** (high variance) | |
| `connect` startup to remote command (integration test wall time) | **~0.25 s** per test, including sshd handshake on localhost | |

**Conclusion:** no bottleneck worth optimising. Commands cost about one KDF (~60 ms) plus ssh's own startup. Read-modify-write commands derive the key twice (load and save, fresh salt), about 120 ms; this was kept because salt reuse is the alternative. The KDF was not weakened.

## 4. CLI user experience

- Every command has `Usage` text; `connect` and `add` show `UsageText`.
- Consistent `--name/-n` and `--vault` (global and per command); `--yes/-y` for destructive commands.
- Confirmation before `delete` and `restore`.
- Script-friendly output: data-only stdout, `--json` on list/search/show, explicit exit codes.
- Actionable errors: "run chmod 600 …", "create one with sshman init", "sshman restore can recover…", and a rotation hint when a password is below policy.
- `genkey` prints the public key to stdout, so `sshman genkey … > id.pub` works.
- `list` sorts favorites first, then by name, and shows tags.

## 5. Documentation and developer experience

README (installation, security model, upgrade notes, troubleshooting), CONTRIBUTING (dev loop, checks, integration tests), SECURITY (supported versions, threat model summary), `docs/ARCHITECTURE.md`, CI, fuzz and release workflows (all started manually; see D-16) and Dependabot.

## 6. Acceptance gate

Each improvement has a test or a measurement and preserves vault/CLI compatibility. The full Phase 1 and Phase 2 suites pass. **Decision: PASS.**
