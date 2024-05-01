#!/usr/bin/env bash
set -e

gpgloader

gpg --list-keys

echo "Running bump, tag, and bump..."

# Bump
perl -pi -e "s/version = \"$CURRENT_VERSION\"/version = \"$NEXT_VERSION\"/" pyproject.toml
git add .
git commit -a -m "BUMP ${NEXT_VERSION}" -s --gpg-sign=${GPG_KEY_ID}

# Tag
git tag -a "v${NEXT_VERSION}" -m "BUMP ${NEXT_VERSION}" -s --local-user=${GPG_KEY_ID}
git show --no-patch "v${NEXT_VERSION}"

# Bump
perl -pi -e "s/version = \"$NEXT_VERSION\"/version = \"$POST_VERSION\"/" pyproject.toml
git add .
git commit -a -m "BUMP ${POST_VERSION}" -s --gpg-sign=${GPG_KEY_ID}

echo "Running bump, tag, and bump... done."
