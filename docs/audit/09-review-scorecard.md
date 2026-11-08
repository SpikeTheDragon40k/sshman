# 09 — Review Scorecard

Weights: Security coverage 25%, Technical correctness 25%, Evidence & reproducibility 20%, Architecture & engineering 15%, Remediation practicality 15%.
**The scores rate the quality of this review, not the security of the software.**

## Iteration 1 — Discovery (static)
Read every source file, the docs, `go.mod` history and the binary metadata. Ran `go build`/`vet`/`test` on the repo as-is. Produced 16 candidate findings (plan table F-01…F-16).

| Criterion | Score | Notes |
|---|---|---|
| Security coverage | 7 | All components and data flows mapped; secret lifecycle sketched |
| Technical correctness | 6 | Several claims rested on reading ssh semantics (IdentitiesOnly, option precedence) without testing them |
| Evidence | 4 | Only the build failure and binary metadata were confirmed |
| Architecture | 7 | Duplication, layering and docs drift identified |
| Remediation | 6 | Directional, not concrete |
| **Weighted** | **6.0** | |

## Iteration 2 — Adversarial validation (dynamic)
- Installed govulncheck, staticcheck, gosec and OpenSSH in the session (not the repo).
- Built a scratch copy with the module path fixed.
- Wrote 8 PoC tests and 2 harnesses; ran a localhost sshd lab with synthetic keys.

Results:
- **Confirmed:** Q-02 (with an IdentitiesOnly=yes/no control), S-01 (remote `ssh-add -l`), S-05, S-02 (`/proc` mode), S-03 (both variants), S-04, Q-03 (1/200 corruption), S-14, Q-05, Q-06.
- **Reclassified:** G204 and G304 as FALSE POSITIVE; Argon2 parameters from "weak" to INFO; S-09 kept at LOW.
- **New:** S-13 (trailing lines), the SIGINT cleanup gap, the `IdentityAgent` override.

| Criterion | Score | Δ reason |
|---|---|---|
| Security coverage | 8.5 | Added agent forwarding, the temp-file and TOFU precedence checks, dependency scanning |
| Technical correctness | 8.5 | Ssh-semantics claims validated with controls; false positives removed |
| Evidence | 8.5 | 15 recorded tests, with exit codes |
| Architecture | 7.5 | Concurrency data-loss quantified |
| Remediation | 7.5 | A concrete ssh invocation that fixes Q-02, S-01 and S-06 together |
| **Weighted** | **8.2** | +2.2 from dynamic evidence and false-positive elimination |

## Iteration 3 — Final verification
- Re-checked every cited line number against `HEAD`.
- Ran the red-team challenge on each MEDIUM+ finding (08). Confirmed that no Critical or High security severity is justified.
- Checked remediation interactions: R-02 must ship Q-02 and S-01 together; R-04 needs a TrimSpace compatibility fallback; R-03 needs `x/sys` only.
- Recorded what remains unvalidated.

| Criterion | Score | Δ reason |
|---|---|---|
| Security coverage | 8.5 | No change; Windows and macOS remain untested |
| Technical correctness | 9 | Compatibility pitfalls of the fixes identified |
| Evidence | 8.5 | No new dynamic tests |
| Architecture | 8 | Ordered roadmap with dependencies |
| Remediation | 8.5 | Ordering and compatibility notes |
| **Weighted** | **8.6** | +0.4 from remediation validation; no further iteration would add material value without other OS platforms |

## Remaining blind spots
- Windows and macOS were not executed (Q-13, the macOS `sun_path` limit).
- Fuzz targets were designed but not run.
- No memory or core-dump forensics.
- The committed binary was not compared to source.
- No review of the internals of `urfave/cli` or `atotto/clipboard` (the clipboard shells out to `xclip`/`xsel`/`pbcopy`, which only ever receive non-secret data).
- The roles were simulated by a single agent, so findings were not independently produced.

## Final assessment
The cryptographic storage design is correct and needs no redesign. The release blockers are a broken build, a `connect` path that doesn't authenticate, and four MEDIUM exposure paths: agent forwarding, argv key input, unsafe temp-file handling, and empty passwords. All of them have small, low-risk fixes (P0, about 2–3 developer-days in total).
