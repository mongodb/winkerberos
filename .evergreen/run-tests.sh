#!/usr/bin/bash
# Disable xtrace for security reasons (just in case it was accidentally set).
set +x
set -eu

# Fetch secrets
bash ${DRIVERS_TOOLS}/.evergreen/secrets_handling/setup-secrets.sh drivers/enterprise_auth
source secrets-export.sh

# Map secrets
export KERBEROS_SERVICE=${PRINCIPAL}
export KERBEROS_PRINCIPAL=
export KERBEROS_UPN=
export KERBEROS_USER=${SASL_USER}
export KERBEROS_DOMAIN=
export KERBEROS_PASSWORD=${SASL_PASS}
export KERBEROS_CANONICALIZE_HOSTNAME=1

# Set up env
"C:/python/Python38/python.exe" -m venv .venv
.venv/Scripts/pip install pymongo pytest
.venv/Scripts/pip install -e .

# TODO: handle xunit results
# Run tests
.venv/Scripts/pytest
