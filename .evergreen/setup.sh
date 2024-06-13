#!/usr/bin/bash

set -eux

# Get the current unique version of this checkout
# shellcheck disable=SC2154
if [ "${is_patch}" = "true" ]; then
    # shellcheck disable=SC2154
    CURRENT_VERSION=$(git describe)-patch-${version_id}
else
    CURRENT_VERSION=latest
fi

# Python has cygwin path problems on Windows.
DRIVERS_TOOLS="$(dirname "$(pwd)")/drivers-tools"
DRIVERS_TOOLS=$(cygpath -m $DRIVERS_TOOLS)
PROJECT_DIRECTORY="$(pwd)"
PROJECT_DIRECTORY=$(cygpath -m $PROJECT_DIRECTORY)
export PROJECT_DIRECTORY
export DRIVERS_TOOLS

export MONGO_ORCHESTRATION_HOME="$DRIVERS_TOOLS/.evergreen/orchestration"
export MONGODB_BINARIES="$DRIVERS_TOOLS/mongodb/bin"
# shellcheck disable=SC2154
export UPLOAD_BUCKET="${project}"

cat <<EOT > expansion.yml
CURRENT_VERSION: "$CURRENT_VERSION"
DRIVERS_TOOLS: "$DRIVERS_TOOLS"
MONGO_ORCHESTRATION_HOME: "$MONGO_ORCHESTRATION_HOME"
MONGODB_BINARIES: "$MONGODB_BINARIES"
UPLOAD_BUCKET: "$UPLOAD_BUCKET"
PROJECT_DIRECTORY: "$PROJECT_DIRECTORY"
EOT

# Bootstrap mongo-orchestration
git clone https://github.com/mongodb-labs/drivers-evergreen-tools.git ${DRIVERS_TOOLS}
cat <<EOT > ${DRIVERS_TOOLS}/.env
CURRENT_VERSION="$CURRENT_VERSION"
DRIVERS_TOOLS="$DRIVERS_TOOLS"
MONGO_ORCHESTRATION_HOME="$MONGO_ORCHESTRATION_HOME"
MONGODB_BINARIES="$MONGODB_BINARIES"
UPLOAD_BUCKET="$UPLOAD_BUCKET"
PROJECT_DIRECTORY="$PROJECT_DIRECTORY"
EOT
