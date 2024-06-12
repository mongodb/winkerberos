#!/usr/bin/bash

set -eux

# Get the current unique version of this checkout
if [ "${is_patch}" = "true" ]; then
    CURRENT_VERSION=$(git describe)-patch-${version_id}
else
    CURRENT_VERSION=latest
fi

export DRIVERS_TOOLS="$(dirname $(pwd))/drivers-tools"
export PROJECT_DIRECTORY="$(pwd)"

# Python has cygwin path problems on Windows. Detect prospective mongo-orchestration home directory
if [ "Windows_NT" = "$OS" ]; then # Magic variable in cygwin
    export DRIVERS_TOOLS=$(cygpath -m $DRIVERS_TOOLS)
    export PROJECT_DIRECTORY=$(cygpath -m $PROJECT_DIRECTORY)
fi

export MONGO_ORCHESTRATION_HOME="$DRIVERS_TOOLS/.evergreen/orchestration"
export MONGODB_BINARIES="$DRIVERS_TOOLS/mongodb/bin"
export UPLOAD_BUCKET="${project}"

cat <<EOT > expansion.yml
CURRENT_VERSION: "$CURRENT_VERSION"
DRIVERS_TOOLS: "$DRIVERS_TOOLS"
MONGO_ORCHESTRATION_HOME: "$MONGO_ORCHESTRATION_HOME"
MONGODB_BINARIES: "$MONGODB_BINARIES"
UPLOAD_BUCKET: "$UPLOAD_BUCKET"
PROJECT_DIRECTORY: "$PROJECT_DIRECTORY"
EOT

cat <<EOT > ${DRIVERS_TOOLS}/.env
CURRENT_VERSION="$CURRENT_VERSION"
DRIVERS_TOOLS="$DRIVERS_TOOLS"
MONGO_ORCHESTRATION_HOME="$MONGO_ORCHESTRATION_HOME"
MONGODB_BINARIES="$MONGODB_BINARIES"
UPLOAD_BUCKET="$UPLOAD_BUCKET"
PROJECT_DIRECTORY="$PROJECT_DIRECTORY"
EOT

# Bootstrap mongo-orchestration
git clone https://github.com/mongodb-labs/drivers-evergreen-tools.git ${DRIVERS_TOOLS}
bash ${DRIVERS_TOOLS}/.evergreen/setup.sh
    MONGODB_VERSION=latest \
    TOPOLOGY=server \
    bash ${DRIVERS_TOOLS}/.evergreen/run-orchestration.sh
