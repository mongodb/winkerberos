#!/usr/bin/env bash
set -eu

echo "Fetch secrets..."
SECRETS_FILE=/tmp/secret-value.json
echo "$(aws secretsmanager get-secret-value --secret-id ${AWS_SECRET_ID} --query SecretString --output text)" > $SECRETS_FILE
# Ensure sensitive secrets are masked in logs.
ARTIFACTORY_USER=$(cat $SECRETS_FILE | jq -r '."artifactory-username"')
ARTIFACTORY_PASSWORD=$(cat $SECRETS_FILE | jq -r '."artifactory-password"')
echo "::add-mask::$ARTIFACTORY_PASSWORD"
GRS_CONFIG_USER1_USERNAME=$(cat $SECRETS_FILE | jq -r '."garasign-username"')
echo "::add-mask::$GRS_CONFIG_USER1_USERNAME"
GRS_CONFIG_USER1_PASSWORD=$(cat $SECRETS_FILE | jq -r '."garasign-password"')
echo "::add-mask::$GRS_CONFIG_USER1_PASSWORD"
GPG_PUBLIC_URL=$(cat $SECRETS_FILE | jq -r '."gpg-public-url"')
GPG_KEY_ID=$(cat $SECRETS_FILE | jq -r '."gpg-key-id"')
AWS_BUCKET=$(cat $SECRETS_FILE | jq -r '."release-assets-bucket"')
echo "::add-mask::$AWS_BUCKET"
rm $SECRETS_FILE
echo "Fetch secrets... done."

echo "::group::Set up artifactory"
echo $ARTIFACTORY_PASSWORD | podman login -u $ARTIFACTORY_USER --password-stdin $ARTIFACTORY_REGISTRY
podman pull $ARTIFACTORY_REGISTRY/$ARTIFACTORY_IMAGE
echo "::endgroup::"

echo "Set up envfile for artifactory image"
GARASIGN_ENVFILE=/tmp/envfile
cat << EOF > $GARASIGN_ENVFILE
GRS_CONFIG_USER1_USERNAME=$GRS_CONFIG_USER1_USERNAME
GRS_CONFIG_USER1_PASSWORD=$GRS_CONFIG_USER1_PASSWORD
EOF

echo "Set up output directories"
export RELEASE_ASSETS=/tmp/release-assets
mkdir $RELEASE_ASSETS
echo "$GITHUB_RUN_ID" > $RELEASE_ASSETS/release_run_id.txt
export S3_ASSETS=/tmp/s3-assets
mkdir $S3_ASSETS

echo "Set up global variables"
cat <<EOF >> $GITHUB_ENV
AWS_BUCKET=$AWS_BUCKET
GPG_KEY_ID=$GPG_KEY_ID
GPG_PUBLIC_URL=$GPG_PUBLIC_URL
GARASIGN_ENVFILE=$GARASIGN_ENVFILE
ARTIFACTORY_IMAGE=$ARTIFACTORY_IMAGE
ARTIFACTORY_REGISTRY=$ARTIFACTORY_REGISTRY
RELEASE_ASSETS=$RELEASE_ASSETS
S3_ASSETS=$S3_ASSETS
EOF

echo "Set up git config"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git config user.name "github-actions[bot]"
