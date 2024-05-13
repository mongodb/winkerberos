#!/usr/bin/env bash

set -eux

echo "Show public outputs"
ls -ltr $RELEASE_ASSETS

if [ "$DRY_RUN" == "false" ]; then
    echo "Uploading Release Reports"
    TARGET=s3://${AWS_BUCKET}/${PRODUCT_NAME}/${VERSION}
    aws s3 cp $S3_ASSETS $TARGET --recursive

    echo "Creating draft release with attached files"
    gh release create ${VERSION} --draft --verify-tag --title ${VERSION} --notes ""
    gh release upload ${VERSION} $RELEASE_ASSETS/*.*
else
    echo "Dry run, not uploading to s3 or creating GitHub Release"
fi
