#!/usr/bin/env bash
###############################################################################
# DVLY / streaming-reporting — store the OCI API private key in AWS SSM
# Parameter Store (SecureString).
#
# The tenant Lambdas authenticate to OCI with Signature v1 (RSA-SHA256). The
# signing key never lives in the OCI vault; it is stored base64-encoded in SSM
# and fetched once per Lambda container at cold start.
#
# A parameter already exists in account 223778538359 at /dvly/oci/private-key
# (shared with the billing services). Only run this to rotate the key.
#
# Usage:
#   ./store-oci-key.sh ~/keys/aws@dvlysolutions.com-*.pem [/dvly/oci/private-key]
###############################################################################
set -euo pipefail

PRIV_KEY="${1:?usage: store-oci-key.sh <path-to-private-pem> [ssm-param-name]}"
SSM_NAME="${2:-/dvly/oci/private-key}"
REGION="${AWS_REGION:-us-east-1}"

[[ -f "${PRIV_KEY}" ]] || { echo "ERROR: not found: ${PRIV_KEY}"; exit 1; }
command -v aws >/dev/null 2>&1 || { echo "ERROR: missing aws CLI"; exit 1; }

BASE64_VALUE=$(base64 < "${PRIV_KEY}" | tr -d '\n')

echo "==> Storing SecureString to ssm:${SSM_NAME} (region ${REGION})"
aws ssm put-parameter \
  --name "${SSM_NAME}" \
  --type SecureString \
  --value "${BASE64_VALUE}" \
  --key-id "alias/aws/ssm" \
  --region "${REGION}" \
  --overwrite

echo "==> Stored. The Lambda reads this via OCI_KEY_SSM_NAME=${SSM_NAME}."
