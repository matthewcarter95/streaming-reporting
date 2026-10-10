#!/usr/bin/env bash
###############################################################################
# DVLY / streaming-reporting — create the static OCI Vault secrets that the
# tenant Lambdas read at runtime:
#
#   streaming-reporting-teams-api-key   Auth0 Teams API key (Bearer token)
#   streaming-reporting-persona-api-key Persona API key
#
# These were previously stored in AWS Secrets Manager (account 204352680806).
# Their VALUES must be supplied here; they are never committed.
#
# After running, copy the printed OCIDs into infrastructure/cdk.json:
#   "teamsApiKeySecretOcid":   "<teams secret ocid>"
#   "personaApiKeySecretOcid": "<persona secret ocid>"
#
# Prereqs: `oci` CLI configured with permission to create secrets in the vault
# (run ./provision-oci.sh first, or use the tenancy admin).
#
# Usage (env vars):
#   TEAMS_API_KEY=... PERSONA_API_KEY=... ./create-oci-secrets.sh
# Usage (files):
#   TEAMS_API_KEY_FILE=~/teams.key PERSONA_API_KEY_FILE=~/persona.key ./create-oci-secrets.sh
###############################################################################
set -euo pipefail

OCI_REGION="${OCI_REGION:-us-ashburn-1}"
OCI_COMPARTMENT_OCID="${OCI_COMPARTMENT_OCID:-ocid1.compartment.oc1..aaaaaaaazssozixdqdrir4ynihqy45igxoxnsh4gssv3dexlnw5npu3464zq}"
OCI_VAULT_OCID="${OCI_VAULT_OCID:-ocid1.vault.oc1.iad.ejtifep6aahfs.abuwcljrig36ycuvdgfprja562y5teby4alcoi7vu7jrerzcko4gw43da3ea}"
OCI_KEY_ID="${OCI_KEY_ID:-ocid1.key.oc1.iad.ejtifep6aahfs.abuwcljrrcg6wmk7uzbh36ojifr4pzoofoycytwg4fbt2e4jmp36ch42xuuq}"

TEAMS_SECRET_NAME="${TEAMS_SECRET_NAME:-streaming-reporting-teams-api-key}"
PERSONA_SECRET_NAME="${PERSONA_SECRET_NAME:-streaming-reporting-persona-api-key}"

command -v oci >/dev/null 2>&1 || { echo "ERROR: missing oci CLI"; exit 1; }

read_value() {
  # read_value <env-var-name> <file-env-var-name>
  local inline="${!1:-}"
  local file_var="${2}"
  local file="${!file_var:-}"
  if [[ -n "${inline}" ]]; then printf '%s' "${inline}"; return; fi
  if [[ -n "${file}" ]]; then cat "${file}"; return; fi
  echo "ERROR: set ${1} or ${file_var}" >&2
  exit 1
}

# Create the secret, or add a new version if one with the same name exists.
# Echoes the secret OCID.
upsert_secret() {
  local name="$1" value="$2" description="$3"
  local b64
  b64=$(printf '%s' "${value}" | base64 | tr -d '\n')

  local existing
  existing=$(oci vault secret list \
    --compartment-id "${OCI_COMPARTMENT_OCID}" --vault-id "${OCI_VAULT_OCID}" --all \
    --query "data[?\"secret-name\"=='${name}'].id | [0]" --raw-output 2>/dev/null || true)

  if [[ -n "${existing}" && "${existing}" != "null" ]]; then
    echo "==> Updating existing secret ${name} (${existing})" >&2
    oci vault secret update-base64 \
      --secret-id "${existing}" \
      --secret-content-content "${b64}" \
      --force --output json >/dev/null
    printf '%s' "${existing}"
  else
    echo "==> Creating secret ${name}" >&2
    oci vault secret create-base64 \
      --compartment-id "${OCI_COMPARTMENT_OCID}" \
      --vault-id "${OCI_VAULT_OCID}" \
      --key-id "${OCI_KEY_ID}" \
      --secret-name "${name}" \
      --description "${description}" \
      --secret-content-content "${b64}" \
      --query 'data.id' --raw-output
  fi
}

TEAMS_VALUE=$(read_value TEAMS_API_KEY TEAMS_API_KEY_FILE)
PERSONA_VALUE=$(read_value PERSONA_API_KEY PERSONA_API_KEY_FILE)

TEAMS_OCID=$(upsert_secret "${TEAMS_SECRET_NAME}" "${TEAMS_VALUE}" "Auth0 Teams API key for streaming-reporting")
PERSONA_OCID=$(upsert_secret "${PERSONA_SECRET_NAME}" "${PERSONA_VALUE}" "Persona API key for streaming-reporting")

echo
echo "Add these to infrastructure/cdk.json:"
echo "  \"teamsApiKeySecretOcid\":   \"${TEAMS_OCID}\","
echo "  \"personaApiKeySecretOcid\": \"${PERSONA_OCID}\","
