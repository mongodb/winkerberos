#!/usr/bin/bash
# Disable xtrace for security reasons (just in case it was accidentally set).
set +x
set -eu

# Fetch secrets
bash ${DRIVERS_TOOLS}/.evergreen/secrets_handling/setup-secrets.sh drivers/enterprise_auth
source secrets-export.sh

# Set up env
git clone -b winkerberos-test https://github.com/blink1073/mongo-python-driver

set -x
"C:/python/Python38/python.exe" -m venv .venv
dos2unix -q .venv/Scripts/activate
. .venv/Scripts/activate
pip install "./mongo-python-driver[test]"
pip install -e .

cd ./mongo-python-driver
TEST_ENTERPRISE_AUTH=1 bash ./.evergreen/run-tests.sh
