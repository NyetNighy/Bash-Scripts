#!/bin/bash

# Cloud Resource Enumerator
# Enumerate AWS/GCP/Azure — S3 buckets, open databases, IAM policies, metadata service
# Usage: ./cloud_enum.sh <provider> [-o output_dir] [-j]
# Providers: aws, gcp, azure, all
# Requires: awscli, curl, jq
# Disclaimer: For authorized testing only

set -euo pipefail

PROVIDER="${1:-all}"
OUTPUT_DIR=""
JSON_OUTPUT=false
REGION="us-east-1"

RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' BLUE='\033[0;34m' CYAN='\033[0;36m' NC='\033[0m'
log()   { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"; }
warn()  { echo -e "${YELLOW}[-] $1${NC}"; }
found() { echo -e "${GREEN}[✓] $1${NC}"; }
fail()  { echo -e "${RED}[!] $1${NC}"; }

usage() {
    head -4 "$0" | cut -c4-
    echo ""
    echo "Providers: aws | gcp | azure | all"
    echo ""
    echo "Options:"
    echo "  -o, --output DIR    Output directory"
    echo "  -r, --region REG    AWS region (default: us-east-1)"
    echo "  -j, --json          JSON output"
    echo "  -h, --help          Show this help"
    echo ""
    echo "Example:"
    echo "  $0 aws -o cloud_audit -r eu-west-1 -j"
    echo "  $0 all -o full_cloud_enum"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        -r|--region) REGION="$2"; shift 2 ;;
        -j|--json) JSON_OUTPUT=true; shift ;;
        -h|--help) usage ;;
        *) PROVIDER="$1"; shift ;;
    esac
done

[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="cloud_enum_${PROVIDER}_$(date +%Y-%m-%d)"
mkdir -p "$OUTPUT_DIR"

LOG_FILE="$OUTPUT_DIR/cloud_enum.log"
FINDINGS_FILE="$OUTPUT_DIR/findings.txt"
JSON_FILE="$OUTPUT_DIR/results.json"
S3_FILE="$OUTPUT_DIR/s3_buckets.txt"
IAM_FILE="$OUTPUT_DIR/iam_policies.txt"

log "Starting cloud enumeration: $PROVIDER"

# ═══════════════════════════════════════════════════════════
# AWS enumeration
# ═══════════════════════════════════════════════════════════
enum_aws() {
    log "═══ AWS Enumeration ═══"

    # ─── S3 buckets ───
    log "Enumerating S3 buckets..."
    > "$S3_FILE"
    S3_COUNT=0

    if command -v aws >/dev/null 2>&1; then
        # List all buckets
        buckets=$(aws s3api list-buckets 2>/dev/null | jq -r '.Buckets[].Name' || true)

        if [[ -n "$buckets" ]]; then
            for bucket in $buckets; do
                echo "$bucket" >> "$S3_FILE"
                ((S3_COUNT++))

                # Check bucket policy and acl
                log "  Checking: $bucket"

                # Bucket policy
                policy=$(aws s3api get-bucket-policy --bucket "$bucket" 2>/dev/null | jq -r '.Policy' || echo "")

                # Check public access
                block=$(aws s3api get-bucket-block-public-access-configuration --bucket "$bucket" 2>/dev/null || echo "")

                if echo "$policy" | grep -qi "Principal\":\"*\|public\|anonymous\|\"Effect\": \"Allow\", \"Principal\": *"; then
                    found "  PUBLIC BUCKET: $bucket"
                    echo "AWS_S3_PUBLIC|$bucket|Policy allows public access" >> "$FINDINGS_FILE"
                fi

                # List bucket contents
                objects=$(aws s3api list-objects --bucket "$bucket" --max-items 20 2>/dev/null | jq -r '.Contents[].Key' || true)
                if [[ -n "$objects" ]]; then
                    log "    Contents preview: $(echo $objects | head -5)"
                fi

                # Check for open ACL
                acl=$(aws s3api get-bucket-acl --bucket "$bucket" 2>/dev/null || echo "")
                if echo "$acl" | grep -qi "urihttp://acs.amazonaws.com/groups/global/AllUsers\|GroupAllUsers"; then
                    found "  OPEN ACL: $bucket — all users can read"
                    echo "AWS_S3_OPEN_ACL|$bucket|AllUsers read access" >> "$FINDINGS_FILE"
                fi

                # Check versioning
                versioning=$(aws s3api get-bucket-versioning --bucket "$bucket" 2>/dev/null | jq -r '.Status' || echo "N/A")
                log "    Versioning: $versioning"

                # Check encryption
                encryption=$(aws s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null | jq -r '.ServerSideEncryptionConfiguration.Rules[].ServerSideEncryptionByDefault.SSEAlgorithm' 2>/dev/null || echo "NOT SET")
                if [[ "$encryption" == "NOT SET" ]]; then
                    warn "  No encryption: $bucket"
                    echo "AWS_S3_NO_ENCRYPT|$bucket" >> "$FINDINGS_FILE"
                fi

                # Check static website hosting
                website=$(aws s3api get-bucket-website --bucket "$bucket" 2>/dev/null | jq -r '.IndexDocument.Suffix' 2>/dev/null || echo "")
                [[ -n "$website" ]] && log "    Website hosting enabled: $bucket/$website"
            done

            found "  Found $S3_COUNT S3 buckets"
        else
            warn "  No S3 buckets found or AWS credentials not configured"
        fi

        # ─── IAM enumeration ───
        log "Enumerating IAM policies..."
        > "$IAM_FILE"
        IAM_COUNT=0

        policies=$(aws iam list-policies --scope Local --max-items 50 2>/dev/null | jq -r '.Policies[].Arn' || true)
        if [[ -n "$policies" ]]; then
            for policy_arn in $policies; do
                ((IAM_COUNT++))
                echo "$policy_arn" >> "$IAM_FILE"

                # Get policy version
                version=$(aws iam get-policy --policy-arn "$policy_arn" 2>/dev/null | jq -r '.Policy.DefaultVersionId' || echo "")

                if [[ -n "$version" ]]; then
                    doc=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$version" 2>/dev/null | jq -r '.PolicyVersion.Document' || echo "")

                    # Check for dangerous actions
                    if echo "$doc" | grep -qiE '"Action": ".*\*"|"Action": "sts:AssumeRole"|"Action": "iam:*"|"Action": "s3:GetObject.*\*,.*\"Resource\".*\*"'; then
                        found "  WIDE IAM POLICY: $policy_arn"
                        echo "AWS_IAM_WIDE_POLICY|$policy_arn" >> "$FINDINGS_FILE"
                    fi
                fi
            done
            log "  Found $IAM_COUNT IAM policies"
        fi

        # ─── EC2 security groups ───
        log "Enumerating EC2 security groups..."
        ec2_sgs=$(aws ec2 describe-security-groups --region "$REGION" 2>/dev/null | jq -r '.SecurityGroups[] | "\(.GroupId)|\(.GroupName)|\(.IpPermissions[].IpRanges[]?.CidrIp // \"none\")"' || true)

        if [[ -n "$ec2_sgs" ]]; then
            echo "$ec2_sgs" | while IFS='|' read -r sg_id sg_name cidr; do
                if [[ "$cidr" == "0.0.0.0/0" ]]; then
                    found "  OPEN SG: $sg_id ($sg_name) — 0.0.0.0/0 allowed"
                    echo "AWS_EC2_OPEN_SG|$sg_id|$sg_name|0.0.0.0/0" >> "$FINDINGS_FILE"
                fi
            done
        fi

        # ─── SQS / SNS / Lambda ───
        log "Checking other AWS services..."

        for svc in sqs sns lambda; do
            case "$svc" in
                sqs)
                    queues=$(aws sqs list-queues --region "$REGION" 2>/dev/null | jq -r '.QueueUrls[]' || true)
                    [[ -n "$queues" ]] && log "  SQS queues found: $(echo $queues | wc -l)"
                    ;;
                sns)
                    topics=$(aws sns list-topics --region "$REGION" 2>/dev/null | jq -r '.Topics[].TopicArn' || true)
                    [[ -n "$topics" ]] && log "  SNS topics found: $(echo $topics | wc -l)"
                    ;;
                lambda)
                    funcs=$(aws lambda list-functions --region "$REGION" 2>/dev/null | jq -r '.Functions[].FunctionName' || true)
                    [[ -n "$funcs" ]] && log "  Lambda functions found: $(echo $funcs | wc -l)"
                    ;;
            esac
        done

    else
        warn "AWS CLI not configured"
        log "  Run: aws configure (or set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY env vars)"
    fi

    # ─── AWS Metadata service (SSRF target) ───
    log "Testing metadata service accessibility..."
    metadata_test=$(curl -s --max-time 5 "http://169.254.169.254/latest/meta-data/" -H "User-Agent: curl" 2>/dev/null || echo "")

    if [[ -n "$metadata_test" ]]; then
        found "  METADATA SERVICE ACCESSIBLE (SSRF vector!)"
        echo "AWS_METADATA_ACCESS|169.254.169.254|Exposed via SSRF" >> "$FINDINGS_FILE"
        log "  Available endpoints:"
        curl -s --max-time 5 "http://169.254.169.254/latest/meta-data/" 2>/dev/null | head -10
    else
        log "  Metadata service not accessible (good — but may be network restricted)"
    fi

    # ─── S3 bucket enumeration via DNS pattern ───
    log "Brute-forcing common S3 bucket names..."
    common_names=(
        "$PROVIDER-backup" "$PROVIDER-assets" "$PROVIDER-prod" "$PROVIDER-dev"
        "prod-$PROVIDER" "dev-$PROVIDER" "staging-$PROVIDER"
        "$PROVIDER-logs" "$PROVIDER-media" "$PROVIDER-static"
        "www-$PROVIDER" "api-$PROVIDER" "data-$PROVIDER"
    )

    for name in "${common_names[@]}"; do
        result=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "https://$name.s3.amazonaws.com" 2>/dev/null || echo "000")
        if [[ "$result" == "200" || "$result" == "307" ]]; then
            found "  S3 bucket found: $name.s3.amazonaws.com (HTTP $result)"
            echo "AWS_S3_BRUTE|$name.s3.amazonaws.com|HTTP $result" >> "$FINDINGS_FILE"
        fi
    done
}

# ═══════════════════════════════════════════════════════════
# GCP enumeration
# ═══════════════════════════════════════════════════════════
enum_gcp() {
    log "═══ GCP Enumeration ═══"

    # GCP metadata service
    log "Testing GCP metadata service..."
    gcp_metadata=$(curl -s --max-time 5 -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/" 2>/dev/null || echo "")

    if [[ -n "$gcp_metadata" ]]; then
        found "  GCP METADATA ACCESSIBLE (SSRF vector!)"
        echo "GCP_METADATA_ACCESS|metadata.google.internal|Exposed" >> "$FINDINGS_FILE"
        log "  Service accounts accessible:"
        echo "$gcp_metadata"
    else
        log "  GCP metadata service not accessible"
    fi

    # ─── GCS buckets ───
    log "Enumerating GCS buckets..."

    if command -v gsutil >/dev/null 2>&1; then
        buckets=$(gsutil ls 2>/dev/null || true)
        if [[ -n "$buckets" ]]; then
            for bucket in $buckets; do
                found "  GCS bucket: $bucket"
                echo "GCP_GCS|$bucket" >> "$FINDINGS_FILE"

                # Check IAM
                iam=$(gsutil iam get "gs://$bucket" 2>/dev/null || echo "")
                if echo "$iam" | grep -qi "allUsers\|allAuthenticatedUsers"; then
                    found "  PUBLIC GCS bucket: $bucket"
                    echo "GCP_GCS_PUBLIC|$bucket" >> "$FINDINGS_FILE"
                fi

                # List contents
                objects=$(gsutil ls "gs://$bucket/**" 2>/dev/null | head -5 || true)
                [[ -n "$objects" ]] && log "    Contents: $(echo $objects | head -3)"
            done
        fi
    else
        warn "  gsutil not configured"
    fi

    # ─── BigQuery datasets ───
    log "Checking BigQuery datasets..."
    if command -v bq >/dev/null 2>&1; then
        datasets=$(bq ls --project_id="$(gcloud config get project 2>/dev/null)" 2>/dev/null | grep -v "^---+" || true)
        [[ -n "$datasets" ]] && log "  BigQuery datasets: $(echo $datasets | wc -l)"
    fi
}

# ═══════════════════════════════════════════════════════════
# Azure enumeration
# ═══════════════════════════════════════════════════════════
enum_azure() {
    log "═══ Azure Enumeration ═══"

    # Azure metadata service
    log "Testing Azure metadata service..."
    azure_metadata=$(curl -s --max-time 5 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null || echo "")

    if [[ -n "$azure_metadata" ]]; then
        found "  AZURE METADATA ACCESSIBLE (SSRF vector!)"
        echo "AZURE_METADATA_ACCESS|169.254.169.254|Exposed" >> "$FINDINGS_FILE"
        # Parse subscription ID
        sub_id=$(echo "$azure_metadata" | jq -r '.subscriptionId' 2>/dev/null || echo "unknown")
        log "  Subscription ID: $sub_id"
        echo "AZURE_SUBSCRIPTION|$sub_id" >> "$FINDINGS_FILE"
    else
        log "  Azure metadata service not accessible"
    fi

    # ─── Azure Blob Storage ───
    log "Checking Azure Blob Storage..."

    storage_accounts=$(az storage account list 2>/dev/null | jq -r '.[].name' || true)
    if [[ -n "$storage_accounts" ]]; then
        for account in $storage_accounts; do
            found "  Azure Storage account: $account"
            echo "AZURE_STORAGE|$account" >> "$FINDINGS_FILE"

            # Check blob containers
            containers=$(az storage container list --account-name "$account" --auth-mode login 2>/dev/null | jq -r '.[].name' || true)
            for container in $containers; do
                # Check public access
                perms=$(az storage container show --account-name "$account" --name "$container" 2>/dev/null | jq -r '.properties.publicAccess' || echo "None")
                if [[ "$perms" != "None" ]]; then
                    found "  PUBLIC BLOB: $account/$container (public: $perms)"
                    echo "AZURE_BLOB_PUBLIC|$account/$container|$perms" >> "$FINDINGS_FILE"
                fi
            done
        done
    else
        warn "  No Azure storage accounts found or not authenticated"
    fi

    # ─── Azure AD apps ───
    log "Checking Azure AD applications..."
    if command -v az >/dev/null 2>&1; then
        apps=$(az ad app list --query '[].appId' -o tsv 2>/dev/null | head -20 || true)
        [[ -n "$apps" ]] && log "  Azure AD apps found: $(echo $apps | wc -w)"
    fi
}

# ═══════════════════════════════════════════════════════════
# JSON output
# ═══════════════════════════════════════════════════════════
generate_json() {
    local PROVIDER="$1"
    local FINDINGS="$FINDINGS_FILE"
    local S3="$S3_FILE"
    local IAM="$IAM_FILE"

    {
        echo "{"
        echo "  \"provider\": \"$PROVIDER\","
        echo "  \"timestamp\": \"$(date -I)\","
        echo "  \"findings\": ["
        while IFS='|' read -r type resource detail; do
            [[ -z "$type" ]] && continue
            echo "    {\"type\": \"$type\", \"resource\": \"$resource\", \"detail\": \"$detail\"},"
        done < "$FINDINGS_FILE" | sed '$ s/,$//'
        echo "  ]"
        echo "}"
    } > "$JSON_FILE"
}

# ═══════════════════════════════════════════════════════════
# Run selected provider(s)
# ═══════════════════════════════════════════════════════════
> "$FINDINGS_FILE"

case "$PROVIDER" in
    aws)
        enum_aws
        ;;
    gcp)
        enum_gcp
        ;;
    azure)
        enum_azure
        ;;
    all)
        enum_aws
        enum_gcp
        enum_azure
        ;;
    *)
        fail "Unknown provider: $PROVIDER"
        usage
        ;;
esac

[[ "$JSON_OUTPUT" == "true" ]] && generate_json "$PROVIDER"

# ─── Summary ───
FINDINGS_COUNT=$(wc -l < "$FINDINGS_FILE" 2>/dev/null || echo 0)
S3_COUNT=$(wc -l < "$S3_FILE" 2>/dev/null || echo 0)
IAM_COUNT=$(wc -l < "$IAM_FILE" 2>/dev/null || echo 0)

log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "Cloud Enum Complete — $PROVIDER"
echo -e "${GREEN}[✓]${NC} S3 buckets found:   $S3_COUNT"
echo -e "${GREEN}[✓]${NC} IAM policies:        $IAM_COUNT"
echo -e "${YELLOW}[!]${NC} Total findings:      $FINDINGS_COUNT"
echo ""
echo -e "  Findings:  ${YELLOW}$FINDINGS_FILE${NC}"
echo -e "  S3 buckets: ${CYAN}$S3_FILE${NC}"
echo -e "  IAM:       ${CYAN}$IAM_FILE${NC}"
[[ "$JSON_OUTPUT" == "true" ]] && echo -e "  JSON:      ${BLUE}$JSON_FILE${NC}"
echo ""

if [[ "$FINDINGS_COUNT" -gt 0 ]]; then
    warn "Review findings — potential data exposure detected"
    warn "Metadata service access = SSRF pivot point"
fi

log "Enum complete — use only with authorization"