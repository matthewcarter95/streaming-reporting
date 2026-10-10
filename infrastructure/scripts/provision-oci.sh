#!/usr/bin/env bash
###############################################################################
# DVLY / streaming-reporting — grant the AWS Lambda's OCI user permission to
# read AND manage secrets in the vault compartment.
#
# The OCI user used by the Lambdas (aws@dvlysolutions.com) is a member of the
# `SecretsRetriever` group and already has read access to `secret-bundles` in
# the `usps` compartment. This script additionally allows it to:
#   - manage secrets          (create / add versions for per-tenant creds)
#   - use the vault KMS key   (encrypt new secret versions)
#
# It creates (or updates) a policy named $POLICY_NAME in $OCI_COMPARTMENT_OCID.
# Idempotent: safe to re-run.
#
# Prereqs: `oci` CLI configured against an identity that can manage policies in
# the compartment (e.g. the tenancy admin, NOT the AWS Lambda user itself).
# Usage:   ./provision-oci.sh
###############################################################################
set -euo pipefail

OCI_REGION="${OCI_REGION:-us-ashburn-1}"
OCI_COMPARTMENT_OCID="${OCI_COMPARTMENT_OCID:-ocid1.compartment.oc1..aaaaaaaazssozixdqdrir4ynihqy45igxoxnsh4gssv3dexlnw5npu3464zq}"
OCI_GROUP="${OCI_GROUP:-SecretsRetriever}"
OCI_KEY_ID="${OCI_KEY_ID:-ocid1.key.oc1.iad.ejtifep6aahfs.abuwcljrrcg6wmk7uzbh36ojifr4pzoofoycytwg4fbt2e4jmp36ch42xuuq}"
POLICY_NAME="${POLICY_NAME:-StreamingReportingSecrets}"

command -v oci >/dev/null 2>&1 || { echo "ERROR: missing oci CLI"; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "ERROR: missing jq"; exit 1; }

STATEMENTS=$(cat <<JSON
[
  "Allow group ${OCI_GROUP} to read secret-bundles in compartment id ${OCI_COMPARTMENT_OCID}",
  "Allow group ${OCI_GROUP} to manage secrets in compartment id ${OCI_COMPARTMENT_OCID}",
  "Allow group ${OCI_GROUP} to use keys in compartment id ${OCI_COMPARTMENT_OCID} where target.key.id='${OCI_KEY_ID}'"
]
JSON
)

echo "==> Compartment: ${OCI_COMPARTMENT_OCID}"
echo "==> Group:       ${OCI_GROUP}"
echo "==> Key:         ${OCI_KEY_ID}"
echo "==> Policy:      ${POLICY_NAME}"

POLICY_ID=$(oci iam policy list \
  --compartment-id "${OCI_COMPARTMENT_OCID}" --all \
  --query "data[?name=='${POLICY_NAME}'].id | [0]" --raw-output 2>/dev/null || true)

if [[ -z "${POLICY_ID}" || "${POLICY_ID}" == "null" ]]; then
  echo "==> Creating policy ${POLICY_NAME}"
  oci iam policy create \
    --compartment-id "${OCI_COMPARTMENT_OCID}" \
    --name "${POLICY_NAME}" \
    --description "Streaming-reporting Lambdas: read/manage OCI Vault secrets" \
    --statements "${STATEMENTS}" \
    --output json >/dev/null
  echo "    created."
else
  echo "==> Updating existing policy ${POLICY_NAME} (${POLICY_ID})"
  oci iam policy update \
    --policy-id "${POLICY_ID}" \
    --statements "${STATEMENTS}" \
    --force \
    --output json >/dev/null
  echo "    updated."
fi

echo
echo "Done. The AWS Lambda OCI user can now manage secrets in compartment ${OCI_COMPARTMENT_OCID}."
