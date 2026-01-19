#!/usr/bin/env bash
set -euo pipefail

RECEIVER_STACK_NAME="ses-inbound-handler"
FORWARDER_STACK_NAME="ses-inbound-forwarder"

TEMPLATE_DIR=$(mktemp -d)
trap 'rm -rf "${TEMPLATE_DIR}"' EXIT

echo "Deploying ${RECEIVER_STACK_NAME}..."
python receiver.py > "${TEMPLATE_DIR}/receiver.json"
aws cloudformation deploy \
    --stack-name "${RECEIVER_STACK_NAME}" \
    --template-file "${TEMPLATE_DIR}/receiver.json" \
    --capabilities CAPABILITY_IAM

FORWARDER_PARAMS=(
    "EventBusName=\$${RECEIVER_STACK_NAME}-EventBusName"
    "BucketArn=\$${RECEIVER_STACK_NAME}-BucketArn"
)
if [[ -n "${DESTINATION_EMAIL_ADDRESS:-}" ]]; then
    FORWARDER_PARAMS+=("DestinationEmailAddress=${DESTINATION_EMAIL_ADDRESS}")
fi

echo "Deploying ${FORWARDER_STACK_NAME}..."
python forwarder.py > "${TEMPLATE_DIR}/forwarder.json"
aws cloudformation deploy \
    --stack-name "${FORWARDER_STACK_NAME}" \
    --template-file "${TEMPLATE_DIR}/forwarder.json" \
    --capabilities CAPABILITY_IAM \
    --parameter-overrides "${FORWARDER_PARAMS[@]}"

echo "Deployment complete!"
