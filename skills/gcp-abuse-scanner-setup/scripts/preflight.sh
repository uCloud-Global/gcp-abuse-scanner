#!/usr/bin/env bash
# preflight.sh — READ-ONLY readiness check for gcp-abuse-scanner.
#
# Usage:
#   bash preflight.sh --scanner-project ID [--impersonate SA_EMAIL] [--org ORG_ID] [--project ID ...]
#
# Checks: gcloud installed + authenticated, GOOGLE_APPLICATION_CREDENTIALS type,
# impersonation token minting, scanner-project APIs, per-project APIs, org enumeration.
# Never enables APIs, grants roles, or creates keys. Exit 0 = all required checks passed.

set -uo pipefail

SCANNER_PROJECT=""; IMPERSONATE=""; ORG_ID=""; PROJECTS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --scanner-project) SCANNER_PROJECT="$2"; shift 2 ;;
    --impersonate)     IMPERSONATE="$2"; shift 2 ;;
    --org)             ORG_ID="$2"; shift 2 ;;
    --project)         PROJECTS+=("$2"); shift 2 ;;
    -h|--help)         sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 64 ;;
  esac
done

FAIL=0
ok()   { echo "✅ $*"; }
warn() { echo "⚠️  $*"; }
bad()  { echo "❌ $*"; FAIL=1; }

ORG_APIS="cloudasset.googleapis.com cloudbilling.googleapis.com billingbudgets.googleapis.com orgpolicy.googleapis.com"
PROJECT_APIS="serviceusage.googleapis.com iam.googleapis.com compute.googleapis.com container.googleapis.com run.googleapis.com aiplatform.googleapis.com apikeys.googleapis.com recommender.googleapis.com"

IMP_FLAG=()
[[ -n "$IMPERSONATE" ]] && IMP_FLAG=(--impersonate-service-account="$IMPERSONATE")

# 1. Tooling
if command -v gcp-abuse-scanner >/dev/null 2>&1; then
  ok "CLI: $(gcp-abuse-scanner version 2>/dev/null)"
else
  bad "gcp-abuse-scanner not on PATH (pipx install gcp-abuse-scanner)"
fi
if ! command -v gcloud >/dev/null 2>&1; then
  bad "gcloud not installed — remaining checks need it"; exit 1
fi

# 2. Active identity
ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | head -1)
[[ -n "$ACCOUNT" ]] && ok "gcloud active account: $ACCOUNT" || bad "No active gcloud account (gcloud auth login / gcloud auth application-default login)"

# 3. GOOGLE_APPLICATION_CREDENTIALS type (the CLI treats it as an SA key file)
if [[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]; then
  GAC_TYPE=$(python3 -c 'import json,os,sys; print(json.load(open(os.environ["GOOGLE_APPLICATION_CREDENTIALS"])).get("type",""))' 2>/dev/null || echo "unreadable")
  if [[ "$GAC_TYPE" == "service_account" ]]; then
    warn "GOOGLE_APPLICATION_CREDENTIALS is an SA key file — works, but prefer impersonation"
  elif [[ -n "$IMPERSONATE" ]]; then
    ok "GOOGLE_APPLICATION_CREDENTIALS type '$GAC_TYPE' is fine because --impersonate-service-account takes precedence"
  else
    bad "GOOGLE_APPLICATION_CREDENTIALS type '$GAC_TYPE' will be loaded as an SA key and fail — use --impersonate-service-account or unset it"
  fi
fi

# 4. Impersonation
if [[ -n "$IMPERSONATE" ]]; then
  if gcloud auth print-access-token "${IMP_FLAG[@]}" >/dev/null 2>&1; then
    ok "Can impersonate $IMPERSONATE"
  else
    bad "Cannot impersonate $IMPERSONATE (caller needs roles/iam.serviceAccountTokenCreator on it)"
  fi
fi

enabled_apis() {  # $1 = project
  gcloud services list --enabled --project="$1" --format='value(config.name)' "${IMP_FLAG[@]}" 2>/dev/null
}

check_apis() {  # $1 = project, $2 = label, $3 = api list, $4 = severity fn for missing
  local enabled missing=()
  if ! enabled=$(enabled_apis "$1") || [[ -z "$enabled" ]]; then
    bad "$2 $1: cannot list enabled services (no access, or serviceusage disabled)"; return
  fi
  for api in $3; do grep -qx "$api" <<<"$enabled" || missing+=("$api"); done
  if [[ ${#missing[@]} -eq 0 ]]; then ok "$2 $1: all APIs enabled"
  else "$4" "$2 $1: missing ${missing[*]}"; fi
}

# 5. Scanner project APIs (required)
if [[ -n "$SCANNER_PROJECT" ]]; then
  check_apis "$SCANNER_PROJECT" "Scanner project" "$ORG_APIS" bad
else
  warn "No --scanner-project given — skipping org-level API check"
fi

# 6. Org enumeration (what ScopeResolver does for --org)
if [[ -n "$ORG_ID" ]]; then
  if N=$(gcloud asset search-all-resources --scope="organizations/$ORG_ID" \
        --asset-types=cloudresourcemanager.googleapis.com/Project --format='value(name)' \
        "${IMP_FLAG[@]}" 2>/dev/null | wc -l | tr -d ' ') && [[ "$N" -gt 0 ]]; then
    ok "Org $ORG_ID: Cloud Asset enumeration works ($N projects visible)"
  else
    bad "Org $ORG_ID: Cloud Asset search failed (cloudasset API in scanner project + roles/cloudasset.viewer at org)"
  fi
fi

# 7. Target project APIs (missing ones = coverage gaps, not hard failures)
for p in "${PROJECTS[@]+"${PROJECTS[@]}"}"; do
  check_apis "$p" "Target project" "$PROJECT_APIS" warn
done

echo
if [[ $FAIL -eq 0 ]]; then echo "Preflight passed."; else echo "Preflight found blocking issues (❌)."; fi
exit $FAIL
