# 08 — Review Debate

> **Disclosure:** one agent simulated all seven roles **sequentially**. These are structured self-challenges, not independent reviewers. Disagreements were settled with code and with the dynamic tests from 03's evidence log.

## D-1 — Should S-01 (agent forwarding) be HIGH?
- **Security Engineer:** HIGH. Remote root can use the user's key against other hosts, which is credential misuse at scale.
- **Red Team (challenge):** It needs (a) `ForwardAgent yes` in the user config, (b) a compromised remote, and (c) `connect` working, which today requires a matching `~/.ssh/id_*.pub` (Q-02). Under default configs it doesn't trigger. Plain OpenSSH users with that config are exposed in exactly the same way, so it's an inherited-config risk.
- **Crypto/SSH Specialist:** Confirmed in the lab (test E). Note that GO-2026-5006 is irrelevant here, because forwarding is done by OpenSSH, not x/crypto.
- **Go Engineer:** The fix is three `-o` flags. No regression risk, except for users who rely on forwarding; offer a per-entry opt-in.
- **Resolution:** **MEDIUM**, CONFIRMED. Record that the severity **rises** once Q-02 is fixed without also adding `ForwardAgent=no`, so R-02 bundles both.

## D-2 — Is S-02 (argv) really MEDIUM, given that the user chooses it?
- **Red Team:** It's opt-in, and the user could just use a file.
- **Desktop/OS Engineer:** The README advertises the raw mode. `/proc/*/cmdline` is world-readable on default Linux (verified `-r--r--r--`), and shell history persists by default, which needs no attacker timing at all.
- **Resolution:** **MEDIUM**, CONFIRMED. Removing the option has almost no usability cost (stdin covers the use case).

## D-3 — Use `-F none` to fully isolate from the user's ssh_config?
- **Security Engineer:** It removes `ProxyCommand`, `ForwardAgent`, `IdentityAgent` and `LocalCommand` influence completely.
- **Architect/UX:** It breaks legitimate setups: jump hosts, `HostName` aliases, ciphers, `ControlMaster` and corporate proxies. Users would abandon the tool.
- **Resolution:** Don't use `-F none` by default. Override only the security-relevant options (`ForwardAgent`, `IdentityAgent`, `IdentityFile`, `IdentitiesOnly`). **Unresolved:** whether to also force `ClearAllForwardings=yes` (it breaks users who forward ports deliberately). Left as optional.

## D-4 — Is the S-03 symlink attack realistic?
- **Red Team:** In sticky world-writable `/tmp`, `fs.protected_symlinks=1` (default on most distros) stops the victim from following another user's symlink. In `$HOME`, there's no attacker.
- **Desktop/OS Engineer:** The default vault path is the CWD, and group-writable shared project directories aren't sticky, so the protection doesn't apply there. The inherited-mode variant (P2) doesn't need a symlink at all.
- **QA:** Both variants were reproduced (P1 and P2).
- **Resolution:** **MEDIUM**, CONFIRMED, with the preconditions stated explicitly. Not HIGH: it requires a co-located attacker with write access to the directory.

## D-5 — Q-02 rated HIGH as a *reliability* issue, not as security
- **Red Team:** A broken feature isn't a vulnerability.
- **Architect:** Agreed for classification. It still blocks release, and its fix interacts with S-01.
- **Resolution:** Kept in 04 as HIGH (engineering), not in the security count.

## D-6 — gosec G204 / G304
- **Go Engineer:** G204 is `exec.Command("ssh", args...)` with no shell, so local command injection is impossible. G304 reads a file path that the user supplied for themselves.
- **Red Team:** Checked for the remote-shell angle: in `sendkey`, the remote command embeds `PubKey`, which is validated by `ParseAuthorizedKey` and single-quote-escaped correctly. Trailing-line injection into `authorized_keys` remains (S-13), but there's no shell injection.
- **Resolution:** G204 and G304 are **FALSE POSITIVE** as injection findings. S-13 is LOW.

## D-7 — Argon2id parameters: weak?
- **Security Engineer (initial):** t=2 is below RFC 9106's recommended t=3.
- **Crypto Specialist:** RFC 9106's second recommended option is t=3, m=64 MiB. OWASP lists m=19 MiB/t=2 as a minimum. 64 MiB/t=2/p=4 is comfortably above OWASP and marginally below RFC 9106. The real weakness is that the parameters can't be upgraded.
- **Resolution:** No vulnerability. INFO (S-12), with the remediation focused on versioning.

## D-8 — Should S-09 (committed binary) be MEDIUM?
- **Security Engineer:** It's unreproducible (`vcs.modified=true`), uses old x/crypto with SSH advisories, and it's the only runnable artifact because HEAD doesn't build.
- **Red Team:** There's no evidence of tampering. The advisories affect the x/crypto *client* code paths, but sshman uses OpenSSH for transport, so most aren't reachable in practice. Inflating this would be speculative.
- **Resolution:** **LOW**, CONFIRMED (provenance facts). **Unresolved:** a full binary-to-source diff (decompile, or rebuild from `cdab5ae` and compare) was not done.

## D-9 — Same-uid agent abuse (S-07)
- **Red Team:** Same-uid malware can read the vault file and keylog the password anyway, so agent constraints add little.
- **Crypto Specialist:** True. But a read-only wrapper is cheap, and it also stops a buggy client from removing or adding keys.
- **Resolution:** LOW, accepted risk documented; P1 because it's cheap.

## D-10 — S-11 memory zeroization
- **Go Engineer:** With `string` fields and the GC, guarantees are impossible. Switching `Entry.Key` to `[]byte` touches the JSON format and every caller.
- **Architect:** The cost-benefit is poor against the stated threat model.
- **Resolution:** LOW, P3. Prioritise core-dump suppression (cheap) over a `[]byte` refactor.

## Remaining uncertainty
1. Windows `connect` behaviour (Q-13) was not tested.
2. The binary was not compared to source (D-8).
3. Whether any remote login shell other than POSIX sh / fish mis-parses the `sendkey` command was not tested.
4. Concurrency corruption (Q-03) is rare (1/200 in the lab). Its frequency under real multi-process use is unknown, but any non-zero rate means total data loss.
