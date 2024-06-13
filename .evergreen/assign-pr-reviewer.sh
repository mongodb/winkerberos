#!/bin/bash

set -x
export CONFIG=$PROJECT_DIRECTORY/.github/reviewers.txt
export SCRIPT="$DRIVERS_TOOLS/.evergreen/github_app/assign-reviewer.sh"
bash $SCRIPT -p $CONFIG -h ${github_commit} -o "mongodb" -n "winkerberos"
echo '{"results": [{ "status": "PASS", "test_file": "Build", "log_raw": "Test completed"  } ]}' > ${PROJECT_DIRECTORY}/test-results.json
