#!/usr/bin/env bash

set -eu

echo "Show public outputs"
echo "$GITHUB_RUN_ID" > release_run_id.txt
ls -ltr signatures/*
cat papertrail.txt
cat release_run_id.txt

if [ "$DRY_RUN" == "false" ]; then
    echo "Uploading Release Reports"
    AWS_BUCKET=$(cat $AWS_BUCKET_FILE)
    TARGET=s3://$AWS_BUCKET/${PRODUCT_NAME}/${VERSION}
    aws s3 cp ./signatures $TARGET --recursive
    aws s3 cp papertrail.txt $TARGET

    echo "Creating draft release with attached files"
    gh release create ${VERSION} --draft --verify-tag --title ${VERSION} --notes ""
    gh release upload ${VERSION} signatures/*.sig
    gh release upload ${VERSION} release_run_id.txt
else
    echo "Dry run, not uploading to s3 or creating GitHub Release"
fi
