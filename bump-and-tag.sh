#!/usr/bin/env bash
set -e

gpgloader

gpg --list-keys

echo "Running bump, tag, and bump..."
set -x

# Bump
perl -pi -e "s/version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" pyproject.toml
git add .
git commit -a -m "BUMP $$NEW_VERSION}" -s --gpg-sign=${GPG_KEY_ID}

# Tag
git tag -a "$$NEW_VERSION}" -m "BUMP $$NEW_VERSION}" -s --local-user=${GPG_KEY_ID}
git show --no-patch "$$NEW_VERSION}"

# Bump
perl -pi -e "s/version = \"$NEW_VERSION\"/version = \"$POST_VERSION\"/" pyproject.toml
git add .
git commit -a -m "BUMP ${POST_VERSION}" -s --gpg-sign=${GPG_KEY_ID}

set +x

echo "Running bump, tag, and bump... done."
