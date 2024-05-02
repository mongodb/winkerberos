#!/usr/bin/env bash
set -e

gpgloader

gpg --list-keys

rm -rf signatures
mkdir signatures
cd dist

for filename in *; do
    echo "${filename}"
    gpg --yes -v --armor -o "../signatures/$filename.sig" --detach-sign "$filename"
done
