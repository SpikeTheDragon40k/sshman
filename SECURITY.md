# Security Policy

## Supported versions

Security fixes are made on the default branch and in the latest release. Vaults in older formats stay readable, so upgrading is always safe.

## Scope and threat model (summary)

sshman protects SSH private keys and connection profiles **at rest**, in an AES-256-GCM vault keyed with Argon2id. During `connect`, it limits the decrypted key to the sshman process and a read-only, session-scoped agent that is never forwarded. In scope:

* recovering vault contents without the password, or tampering with them undetected;
* sshman following symlinks or using unsafe locations or permissions;
* a remote host, ssh_config setting or crafted entry obtaining use of the vault key;
* command or option injection through entry fields or public keys;
* secrets in arguments, output, logs or files on disk.

Out of scope: malware or another process running as the same user or as root (it can read memory or keylog the password), weak vault passwords chosen despite the policy, and compromise of OpenSSH itself. See the "Security model" section of the README and `docs/remediation/` for details and accepted risks.

## Reporting a Vulnerability

If you believe you’ve found a security vulnerability in **sshman**, please report it privately and responsibly. **Do not open a public GitHub issue for security reports.**

### How to report

Preferred channels:

- **GitHub Security Advisory (recommended):**  
  1. Go to the [`sshman` repository](https://github.com/SpikeTheDragon40k/sshman).  
  2. Click on the **Security** tab.  
  3. Click **“Report a vulnerability”** and fill out the form.  

### What to include

To help me triage and fix the issue quickly, please include where possible:

- The **version/commit** of sshman you tested.
- Your **OS / environment** (e.g. Linux distro, version).
- A **clear description** of the issue and impact.
- **Steps to reproduce** and, if possible, a minimal PoC.
- Any suggested **mitigations or fixes** (optional).

### Response and updates

- I aim to **acknowledge your report within 3 business days**.
- I will **investigate and provide an initial assessment within 10 business days**, or let you know if more time is needed.
- If the report is accepted as a vulnerability:
  - I will work on a fix and, where appropriate, create a **GitHub Security Advisory** so we can coordinate privately until a patched release is available.
  - You will be **credited** in the advisory and/or release notes if you wish, or remain anonymous if you prefer.
- If the report is not considered a security vulnerability (e.g. it’s a regular bug or expected behavior), I’ll explain why and, where appropriate, direct it to the normal issue/bug process.

### Public disclosure

Please give me a reasonable amount of time to **develop and release a fix** before you disclose details publicly. I generally aim to release fixes as soon as practical, and no later than **90 days** from confirmation, unless we mutually agree otherwise.

Thank you for helping keep sshman and its users secure.
