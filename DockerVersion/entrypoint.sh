#!/bin/bash
set -e

VAULT_FILE="/data/vault.enc"

if [ -z "$VAULT_PASSWORD" ]; then
  echo "Error: VAULT_PASSWORD environment variable is not set."
  exit 1
fi

if [ ! -f "$VAULT_FILE" ]; then
  echo "Initializing vault..."
  printf "%s\n" "$VAULT_PASSWORD" | sshman init
fi

exec "$@"
