#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="${ROOT_DIR}/terraform"
TFVARS_FILE="${TF_DIR}/terraform.tfvars"
USE_LOCAL_DOCKER="false"
PLAN_ONLY="false"

usage() {
  cat <<EOF
Usage: ./scripts/deploy.sh [options]

Turnkey multi-stage deployment for the Autonomous Google Cloud WAF Auditor:
  Stage 1: Bootstrap dedicated WAF Host Project (or attach existing), enable APIs & create Artifact Registry
  Stage 2: Build and push the WAF Auditor container image via Cloud Build (or --local-docker)
  Stage 3: Converge full Terraform stack (BigQuery, GCS, Scope IAM, CAI Feeds, Cloud Run, Scheduler)

Options:
  --tfvars <path>    Path to terraform.tfvars file (default: terraform/terraform.tfvars)
  --local-docker     Build and push container image using local Docker instead of Cloud Build
  --plan-only        Run terraform init & plan without applying changes
  -h, --help         Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tfvars)
      TFVARS_FILE="$2"
      shift 2
      ;;
    --local-docker)
      USE_LOCAL_DOCKER="true"
      shift
      ;;
    --plan-only)
      PLAN_ONLY="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ! -f "${TFVARS_FILE}" ]]; then
  echo "Error: tfvars file not found at ${TFVARS_FILE}" >&2
  echo "Copy terraform/terraform.tfvars.example to terraform/terraform.tfvars and fill in your values." >&2
  exit 1
fi

TFVARS_FILE="$(cd "$(dirname "${TFVARS_FILE}")" && pwd)/$(basename "${TFVARS_FILE}")"

for cmd in terraform gcloud; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Error: Required CLI '${cmd}' not found in PATH." >&2
    exit 1
  fi
done

echo "==> Initializing Terraform in ${TF_DIR} ..."
terraform -chdir="${TF_DIR}" init

if [[ "${PLAN_ONLY}" == "true" ]]; then
  terraform -chdir="${TF_DIR}" plan -var-file="${TFVARS_FILE}"
  exit 0
fi

echo "==> Stage 1: Bootstrapping WAF Compliance Host Project, APIs & Artifact Registry ..."
terraform -chdir="${TF_DIR}" apply -auto-approve \
  -var-file="${TFVARS_FILE}" \
  -target=random_id.project_suffix \
  -target=google_project.waf_compliance \
  -target=google_project_service.required_apis \
  -target=google_artifact_registry_repository.waf_auditor

PROJECT_ID="$(terraform -chdir="${TF_DIR}" output -raw compliance_project_id)"
REGION="$(terraform -chdir="${TF_DIR}" output -raw region)"
IMAGE_URI="$(terraform -chdir="${TF_DIR}" output -raw artifact_registry_image)"

echo "==> Stage 2: Building and pushing container image ${IMAGE_URI} ..."
if [[ "${USE_LOCAL_DOCKER}" == "true" ]]; then
  gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet
  docker build -t "${IMAGE_URI}" "${ROOT_DIR}"
  docker push "${IMAGE_URI}"
else
  gcloud builds submit "${ROOT_DIR}" \
    --project="${PROJECT_ID}" \
    --tag="${IMAGE_URI}"
fi

echo "==> Stage 3: Applying full WAF Auditor infrastructure stack ..."
terraform -chdir="${TF_DIR}" apply -auto-approve -var-file="${TFVARS_FILE}"

SERVICE_URI="$(terraform -chdir="${TF_DIR}" output -raw cloud_run_service_uri)"
SCOPE="$(terraform -chdir="${TF_DIR}" output -raw canonical_scope)"
BQ_DATASET="$(terraform -chdir="${TF_DIR}" output -raw bigquery_dataset)"
GCS_BUCKET="$(terraform -chdir="${TF_DIR}" output -raw gcs_artifact_bucket)"

cat <<EOF

================================================================================
WAF Auditor Deployment Complete!
================================================================================
  Compliance Host Project : ${PROJECT_ID}
  Target Audit Scope      : ${SCOPE}
  Cloud Run Service URL   : ${SERVICE_URI}
  BigQuery Dataset        : ${BQ_DATASET}
  GCS Artifact Bucket     : gs://${GCS_BUCKET}
================================================================================
EOF
