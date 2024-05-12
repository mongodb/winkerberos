#!/usr/bin/env bash
set -eu

echo "Fetch secrets"
SECRETS_FILE=/tmp/secret-value.json
echo "$(aws secretsmanager get-secret-value --secret-id ${AWS_SECRET_ID} --query SecretString --output text)" > $SECRETS_FILE
ARTIFACTORY_USER=$(cat $SECRETS_FILE | jq -r '."artifactory-username"')
ARTIFACTORY_PASSWORD=$(cat $SECRETS_FILE | jq -r '."artifactory-password"')
GRS_CONFIG_USER1_USERNAME=$(cat $SECRETS_FILE | jq -r '."garasign-username"')
GRS_CONFIG_USER1_PASSWORD=$(cat $SECRETS_FILE | jq -r '."garasign-password"')
GPG_PUBLIC_URL=$(cat $SECRETS_FILE | jq -r '."gpg-public-url"')
GPG_KEY_ID=$(cat $SECRETS_FILE | jq -r '."gpg-key-id"')
AWS_BUCKET=$(cat $SECRETS_FILE | jq -r '."release-assets-bucket"')
rm $SECRETS_FILE

echo "Set up artifactory"
echo $ARTIFACTORY_PASSWORD | podman login -u $ARTIFACTORY_USER  --password-stdin $ARTIFACTORY_REGISTRY
podman pull $ARTIFACTORY_REGISTRY/$ARTIFACTORY_IMAGE

echo "Set up envfile for artifactory image"
GARASIGN_ENVFILE=/tmp/envfile
cat << EOF > $GARASIGN_ENVFILE
GRS_CONFIG_USER1_USERNAME=$GRS_CONFIG_USER1_USERNAME
GRS_CONFIG_USER1_PASSWORD=$GRS_CONFIG_USER1_PASSWORD
EOF

echo "Set up global variables"
AWS_BUCKET_FILE=/tmp/aws_bucket.txt
echo $AWS_BUCKET > $AWS_BUCKET_FILE
echo "AWS_BUCKET_FILE=$AWS_BUCKET_FILE" >> $GITHUB_ENV
echo "GPG_KEY_ID=$GPG_KEY_ID" >> $GITHUB_ENV
echo "GPG_PUBLIC_URL=$GPG_PUBLIC_URL" >> $GITHUB_ENV
echo "GARASIGN_ENVFILE=$GARASIGN_ENVFILE" >> $GITHUB_ENV
echo "ARTIFACTORY_IMAGE=$ARTIFACTORY_IMAGE" >> $GITHUB_ENV
echo "ARTIFACTORY_REGISTRY=$ARTIFACTORY_REGISTRY" >> $GITHUB_ENV
rm $SECRETS_FILE

echo "Set up git config"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git config user.name "github-actions[bot]"
