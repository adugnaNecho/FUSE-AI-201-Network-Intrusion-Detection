#!/usr/bin/env bash
# Run this from the extracted project directory after installing Git and GitHub CLI.
set -euo pipefail
REPO_NAME="${1:-group19-nsl-kdd-nids}"

if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI (gh) is required. Install it, then run: gh auth login" >&2
  exit 1
fi
if ! gh auth status >/dev/null 2>&1; then
  echo "Authenticate first with: gh auth login" >&2
  exit 1
fi

if [ ! -d .git ]; then
  git init -b main
fi

git add -A
if ! git diff --cached --quiet; then
  git commit -m "Prepare Group 19 Module 6 NIDS prototype portfolio"
fi

if ! git remote get-url origin >/dev/null 2>&1; then
  gh repo create "$REPO_NAME" --public --source=. --remote=origin --push
else
  git push -u origin main
fi

echo "Repository push completed. Verify visibility in a signed-out browser session."
echo "NOTE: artifacts/*.joblib is intentionally git-ignored. After training, publish the trusted artifact explicitly."
