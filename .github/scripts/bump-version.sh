#!/usr/bin/env bash
set -eu

CURRENT_VERSION=$(python setup.py --version)
sed -i "s/version = \"${CURRENT_VERSION}\"/version = \"$1\"/" pyproject.toml
