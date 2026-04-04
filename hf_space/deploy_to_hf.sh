#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: ./deploy_to_hf.sh https://huggingface.co/spaces/<user>/<space>"
  exit 1
fi

SPACE_REPO_URL="$1"
DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR="$(mktemp -d)"

git clone "$SPACE_REPO_URL" "$TEMP_DIR"

find "$TEMP_DIR" -mindepth 1 -maxdepth 1 ! -name ".git" -exec rm -rf {} +
cp -R "$DEPLOY_DIR"/. "$TEMP_DIR"/

cd "$TEMP_DIR"
git add .
git status --short

echo
echo "Next steps:"
echo "1. Review changes above"
echo "2. Run: git commit -m 'Deploy SENTRYX HF Space'"
echo "3. Run: git push"
