
## ✅ 1. Build Your Docker Image (if not yet built)

```bash
docker build -t sshman .
```

---

## ✅ 2. Run Using the `.env` File

Use Docker’s `--env-file` option to load your `.env` variables:

```bash
docker run --rm \
  --env-file .env \
  -v $(pwd)/data:/data \
  sshman sshman list
```

Replace `sshman list` with any command you'd like, e.g., `sshman add`, `sshman delete`, etc.
