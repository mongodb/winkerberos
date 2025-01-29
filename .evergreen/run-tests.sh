#!/usr/bin/bash
# Disable xtrace for security reasons (just in case it was accidentally set).
set +x
set -eu

# Fetch secrets
bash ${DRIVERS_TOOLS}/.evergreen/secrets_handling/setup-secrets.sh drivers/enterprise_auth
source secrets-export.sh

# Set up env
pushd ..
git clone https://github.com/mongodb/mongo-python-driver

set -x
"C:/python/Python39/python.exe" -m venv .venv
dos2unix -q .venv/Scripts/activate
. .venv/Scripts/activate
pip install "./mongo-python-driver[test]"
pip install -e ./src

export CLIENT_PEM="$DRIVERS_TOOLS/.evergreen/x509gen/client.pem"
export CA_PEM="$DRIVERS_TOOLS/.evergreen/x509gen/ca.pem"
export GSSAPI_PASS=${SASL_PASS}
export GSSAPI_CANONICALIZE="true"
export GSSAPI_HOST=${SASL_HOST}
export GSSAPI_PORT=${SASL_PORT}
export GSSAPI_PRINCIPAL=${PRINCIPAL}
pushd ./mongo-python-driver
pytest -W default -m auth
popd
popd
