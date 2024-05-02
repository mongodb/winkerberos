#!/usr/bin/env bash
set -e

gpgloader

gpg --list-keys

for filename in dist/*; do
    echo "${filename}"
    gpg --yes -v --armor -o "$filename.sig" --detach-sign "$filename"
done
