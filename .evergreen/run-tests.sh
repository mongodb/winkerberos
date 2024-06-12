#!/usr/bin/bash
# Disable xtrace for security reasons (just in case it was accidentally set).
set +x

klist

exit 0

# Fetch secrets
bash ${DRIVERS_TOOLS}/.evergreen/secrets_handling/setup-secrets.sh drivers/enterprise_auth
source ${DRIVERS_TOOLS}/.evergreen/setup-secrets.sh

# Map secrets
export KERBEROS_SERVICE=${}
export KERBEROS_PRINCIPAL=${PRINCIPAL}
export KERBEROS_UPN=${}
export KERBEROS_USER=${}
export KERBEROS_DOMAIN=${}
export KERBEROS_PASSWORD=${SASL_PASS}

export GSSAPI_HOST=${SASL_HOST}
export GSSAPI_PORT=${SASL_PORT}

# _SPN = os.environ.get("KERBEROS_SERVICE")
# _PRINCIPAL = os.environ.get("KERBEROS_PRINCIPAL")
# _UPN = os.environ.get("KERBEROS_UPN")
# _USER = os.environ.get("KERBEROS_USER")
# _DOMAIN = os.environ.get("KERBEROS_DOMAIN")
# _PASSWORD = os.environ.get("KERBEROS_PASSWORD")

# Set up env
"C:/python/Python38/python.exe" -m venv .venv
.venv/bin/activate
pip install pymongo pytest
pip install -e .

# TODO: handle xunit results
# Run tests
pytest
