# Contributing to sshman

🎉 Thanks for your interest in contributing to **sshman** – a secure, CLI-based SSH key manager!

We welcome all types of contributions – whether it's fixing bugs, improving documentation, adding features, or suggesting enhancements.

---

## 🚀 Getting Started

1. **Fork the repository**  
   Click the "Fork" button on GitHub, then clone your fork locally:
    ```bash
   git clone https://github.com/YOUR_USERNAME/sshman.git
   cd sshman
    ```

2. **Set up your development environment**

   * Install **Go 1.26+** (the toolchain pinned in `go.mod` is downloaded automatically)
   * Install the OpenSSH client and server if you want to run the integration tests
   * Build the app:

     ```bash
     go build -o sshman .
     ```

3. **Run the app locally**:

   ```bash
   go run . --help
   ```

---

## 🛠️ How You Can Help

Here are some ways you can contribute:

* 🧱 **Code** – New features, performance improvements, or refactoring
* 🪲 **Bug Fixes** – Help squash issues and edge cases
* 📚 **Docs** – Improve README, usage examples, and internal docs
* 🧪 **Tests** – Add or improve test coverage
* 💡 **Ideas** – Feature requests, UI/UX suggestions, CLI polish

---

## 📐 Code Style

* Use `gofmt` to format your code:

  ```bash
  gofmt -s -w .
  ```

* Keep functions focused and readable.

* Write clear commit messages (e.g., `feat: add import/export command`), and reference audit or finding IDs (e.g. `S-03`) when you fix one.

## ✅ Checks to run before opening a PR

CI runs all of these on Linux, macOS and Windows:

```bash
gofmt -l .                          # must print nothing
go vet ./...
go test ./...
go test -race ./...
go test -tags integration ./sshutil/   # starts a throwaway sshd on 127.0.0.1 with synthetic keys
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Fuzz targets (`go test ./vault/ -fuzz FuzzDecryptVault`, and the `Fuzz*` functions in `sshutil`) run nightly.

## 🔐 Security-sensitive code

* Changes to `vault/`, `sshutil/` or the password handling in `app/` need a regression test for the threat they address.
* Never log, print or write private keys, passwords or passphrases. Never add flags or environment variables that carry secrets.
* Never commit real keys, real vaults or binaries. Test vaults in `testdata/` must contain synthetic data only.
* See `docs/ARCHITECTURE.md` and `docs/remediation/DECISIONS.md` before changing the vault format or the ssh invocation.

---

## ✅ Submitting a Pull Request

1. Create a feature branch:

   ```bash
   git checkout -b feat/my-feature
   ```

2. Make your changes and commit:

   ```bash
   git commit -m "feat: short description of the change"
   ```

3. Push your branch and open a PR:

   ```bash
   git push origin feat/my-feature
   ```

4. Open a [Pull Request](https://github.com/SpikeTheDragon40k/sshman/blob/main/.github/PR_TEMPLATE/pull_request_template.md) on GitHub targeting the `main` branch.

---

## 🧭 Guidelines

* Check for open [issues](https://github.com/SpikeTheDragon40k/sshman/issues) before starting work.
* If you’re proposing a large feature, open an issue first to discuss it.
* Add tests where relevant.
* Respect the [Code of Conduct](./CODE_OF_CONDUCT.md).

---

## 🙌 Need Help?

If you're unsure how to begin or need help debugging something, feel free to open an issue or start a discussion. We’re happy to help new contributors!

---

Thanks again! You're awesome. 🔐🐉
