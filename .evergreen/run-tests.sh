#!/usr/bin/bash
# Disable xtrace for security reasons (just in case it was accidentally set).
set +x
set -eu

# Fetch secrets
bash ${DRIVERS_TOOLS}/.evergreen/secrets_handling/setup-secrets.sh drivers/enterprise_auth
source ${DRIVERS_TOOLS}/.evergreen/secrets_handling/secrets-export.sh

# Map secrets
export KERBEROS_SERVICE=${PRINCIPAL}
export KERBEROS_PRINCIPAL=
export KERBEROS_UPN=
export KERBEROS_USER=${SASL_USER}
export KERBEROS_DOMAIN=
export KERBEROS_PASSWORD=${SASL_PASS}

# Set up env
"C:/python/Python38/python.exe" -m venv .venv
.venv/Scripts/activate
pip install pymongo pytest
pip install -e .

# TODO: handle xunit results
# Run tests
pytest
