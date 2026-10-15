#!/usr/bin/env bash
# preflight.sh — READ-ONLY readiness check for gcp-abuse-scanner.
#
# Usage:
#   bash preflight.sh --scanner-project ID [--impersonate SA_EMAIL] [--org ORG_ID] [--project ID ...]
#   bash preflight.sh --project ID [--impersonate SA_EMAIL] --coverage
#
# Checks: gcloud installed + authenticated, GOOGLE_APPLICATION_CREDENTIALS type,
# impersonation token minting, scanner-project APIs, per-project APIs, org enumeration.
# Never enables APIs, grants roles, or creates keys. Exit 0 = all required checks passed.
#
# --coverage additionally probes one representative read call per collector and reports the
# checks that would be skipped. Use it to answer "do these IAM roles actually cover the
# assessment?" (e.g. SOP's Viewer + Security Reviewer): any ❌ in that section means the
# corresponding findings can come back empty without the scan failing.

set -uo pipefail

SCANNER_PROJECT=""; IMPERSONATE=""; ORG_ID=""; PROJECTS=(); COVERAGE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --scanner-project) SCANNER_PROJECT="$2"; shift 2 ;;
    --impersonate)     IMPERSONATE="$2"; shift 2 ;;
    --org)             ORG_ID="$2"; shift 2 ;;
    --project)         PROJECTS+=("$2"); shift 2 ;;
    --coverage)        COVERAGE=1; shift ;;
    -h|--help)         sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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

# 8. Role/coverage probe (--coverage) — one read call per collector
#    A failure here does NOT make the scan fail: it makes it silently incomplete.
GAPS=0
probe() {  # $1 = collector, $2 = checks at risk, $3.. = command
  local collector="$1" checks="$2"; shift 2
  if "$@" >/dev/null 2>&1; then
    ok "coverage/$collector: readable (checks: $checks)"
  else
    GAPS=$((GAPS + 1))
    bad "coverage/$collector: NOT readable → $checks would be silently empty"
  fi
}

if [[ $COVERAGE -eq 1 ]]; then
  echo
  echo "─ Coverage probe (read-only, one call per collector) ─────────────"
  if [[ ${#PROJECTS[@]} -eq 0 ]]; then
    warn "No --project given — coverage probe needs at least one target project"
  else
    P="${PROJECTS[0]}"
    probe api_keys   "GEM-001..GEM-006, GEM-010" gcloud services api-keys list --project="$P" --format="value(name)" "${IMP_FLAG[@]}"
    probe iam        "CM-040..CM-046, GEM-020..GEM-023" gcloud asset search-all-iam-policies --scope="projects/$P" --format="value(resource)" --limit=1 "${IMP_FLAG[@]}"
    probe iam        "CMN-004 (service accounts)" gcloud iam service-accounts list --project="$P" --format="value(email)" "${IMP_FLAG[@]}"
    probe network    "CM-003, CM-004, CM-008, CM-050" gcloud compute firewall-rules list --project="$P" --format="value(name)" "${IMP_FLAG[@]}"
    probe compute    "CM-001, CM-005, CM-006, CM-007, CM-009" gcloud compute instances list --project="$P" --format="value(name)" "${IMP_FLAG[@]}"
    probe gke        "CM-020..CM-026" gcloud container clusters list --project="$P" --format="value(name)" "${IMP_FLAG[@]}"
    probe cloud_run  "CM-030, CM-031" gcloud run services list --project="$P" --format="value(metadata.name)" "${IMP_FLAG[@]}"
    probe vertex_ai  "GEM-030" gcloud ai endpoints list --project="$P" --region=us-central1 --format="value(name)" "${IMP_FLAG[@]}"
    probe quota      "GEM-040, GEM-041" gcloud alpha services quota list --service=aiplatform.googleapis.com --consumer="projects/$P" --format="value(name)" "${IMP_FLAG[@]}"
    probe recommender "CM-045" gcloud recommender recommendations list --project="$P" --recommender=google.iam.policy.Recommender --location=global --format="value(name)" "${IMP_FLAG[@]}"
    probe org_policy "CM-002, CM-011, GEM-050, CMN-005" gcloud resource-manager org-policies list --project="$P" --format="value(constraint)" "${IMP_FLAG[@]}"
    echo
    if [[ $GAPS -eq 0 ]]; then
      ok "Coverage probe: every collector readable with the current identity"
    else
      warn "$GAPS collector(s) unreadable → the assessment cannot be approved automatically"
      cat <<'EOF'
     Each ❌ above is a silent hole, not an error: the scan exits 0 with no findings for it.
     Roles that are easy to miss when granting only Viewer:
       - API keys        → roles/serviceusage.apiKeysViewer (or roles/apikeys.viewer)
       - IAM bindings    → roles/cloudasset.viewer + roles/iam.securityReviewer
       - Firewalls/VMs   → roles/compute.viewer
       - GKE / Cloud Run → roles/container.clusterViewer, roles/run.viewer
       - Vertex AI       → roles/aiplatform.viewer
       - Quotas          → roles/serviceusage.serviceUsageConsumer (or browser + quota viewer)
       - Recommender     → roles/recommender.iamViewer
       - Billing/budgets → roles/billing.viewer on the billing account (NOT a project role)
     Either grant the missing reader role or accept the gap in writing — never both silently.
EOF
    fi
  fi
fi

echo
if [[ $FAIL -eq 0 ]]; then echo "Preflight passed."; else echo "Preflight found blocking issues (❌)."; fi
exit $FAIL
