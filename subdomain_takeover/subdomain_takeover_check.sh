#!/bin/bash

# Subdomain Takeover Checker
# Detects dangling DNS entries that can be claimed on third-party services
# Usage: ./subdomain_takeover_check.sh <domain> [-o output_dir] [-j] [-f]
# Requires: curl, dig, aws, nslookup
# Disclaimer: For authorized testing only

set -euo pipefail

DOMAIN="${1:-}"
OUTPUT_DIR=""
JSON_OUTPUT=false
VERBOSE=false

RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' BLUE='\033[0;34m' NC='\033[0m'
log()   { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"; }
warn()  { echo -e "${YELLOW}[-] $1${NC}"; }
found() { echo -e "${GREEN}[✓] $1${NC}"; }
info()  { echo -e "${YELLOW}[*] $1${NC}"; }

usage() {
    head -5 "$0" | cut -c4-
    echo ""
    echo "Options:"
    echo "  -o, --output DIR   Output directory"
    echo "  -j, --json         JSON output"
    echo "  -v, --verbose      Verbose output"
    echo "  -h, --help         Show this help"
    echo ""
    echo "Example:"
    echo "  $0 example.com -o takeover_results -j"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        -j|--json) JSON_OUTPUT=true; shift ;;
        -v|--verbose) VERBOSE=true; shift ;;
        -h|--help) usage ;;
        *) DOMAIN="$1"; shift ;;
    esac
done

[[ -z "$DOMAIN" ]] && usage

[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="takeover_${DOMAIN}_$(date +%Y-%m-%d)"
mkdir -p "$OUTPUT_DIR"

LOG_FILE="$OUTPUT_DIR/takeover_scan.log"
TAKEOVER_FILE="$OUTPUT_DIR/takeovers.txt"
RAW_SUBS="$OUTPUT_DIR/subdomains_raw.txt"
JSON_FILE="$OUTPUT_DIR/results.json"

> "$TAKEOVER_FILE"
log "Starting subdomain takeover scan: $DOMAIN"

# ─── Service fingerprints ───
declare -A FINGERPRINTS=(
    ["aws"]="The specified bucket either does not exist or is not accessible"
    ["github"]="There isn't a GitHub Pages site here."
    ["heroku"]="No such app"
    ["gitlab"]="The page could not be found"
    ["bitbucket"]="Repository not found"
    ["jetbrains"]="is not a registered domain"
    ["cloudfront"]="ERROR: The request could not be satisfied"
    ["fastly"]="Fastly error: unknown domain"
    ["azure"]="The web server returned a not found error"
    ["digitalocean"]="Domain not found"
    ["rackcdn"]="does not exist"
    ["shopify"]="isn't a valid Shopify subdomain"
    ["wpengine"]="The requested domain is not configured"
    ["ghost"]="The thing you were looking for is no longer here"
    ["tumblr"]="There's nothing here."
    ["uservoice"]="UserVoice subdomain"
    ["surge"]="project does not exist"
    ["netlify"]="Not Found — Netlify"
    ["vercel"]="The requested URL was not found"
    ["render"]="Service Not Found"
    ["cloudflare"]="Origin DNS error"
    ["favicon"]="NXDOMAIN"
)

declare -A CNAME_RECORDS=()

log "Fetching subdomains..."

# Get subdomains from existing sources
if command -v assetfinder >/dev/null 2>&1; then
    assetfinder --subs-only "$DOMAIN" 2>/dev/null >> "$RAW_SUBS" || true
fi

if command -v subfinder >/dev/null 2>&1; then
    subfinder -silent -d "$DOMAIN" 2>/dev/null >> "$RAW_SUBS" || true
fi

if command -v amass >/dev/null 2>&1; then
    amass enum -passive -d "$DOMAIN" 2>/dev/null | while read -r sub; do
        echo "$sub" >> "$RAW_SUBS"
    done || true
fi

# Also grep from existing DNS enum if available
if [[ -f "$OUTPUT_DIR/../dnsrecon_full.txt" ]]; then
    grep -oE '[a-zA-Z0-9][-a-zA-Z0-9]*\.'"$DOMAIN" "$OUTPUT_DIR/../dnsrecon_full.txt" 2>/dev/null >> "$RAW_SUBS" || true
fi

# Sort + deduplicate
sort -u "$RAW_SUBS" -o "$RAW_SUBS" 2>/dev/null || true

SUB_COUNT=$(wc -l < "$RAW_SUBS" 2>/dev/null || echo 0)
log "Found $SUB_COUNT subdomains to check"

# ─── Resolve CNAMEs ───
log "Resolving CNAME records..."
CNAME_TEMP="$OUTPUT_DIR/cname_records.txt"
> "$CNAME_TEMP"

while IFS= read -r sub; do
    [[ -z "$sub" ]] && continue

    cname=$(dig +short CNAME "$sub" 2>/dev/null | grep -v '^$' | head -1)

    if [[ -n "$cname" ]]; then
        echo "$sub|$cname" >> "$CNAME_TEMP"
        CNAME_RECORDS["$sub"]="$cname"
        [[ "$VERBOSE" == "true" ]] && info "  $sub → $cname"
    fi
done < "$RAW_SUBS"

CNAME_COUNT=$(wc -l < "$CNAME_TEMP" 2>/dev/null || echo 0)
log "Resolved $CNAME_COUNT CNAME records"

# ─── Check each CNAME for takeover exposure ───
log "Checking for takeover opportunities..."

TAKEOVER_COUNT=0

while IFS='|' read -r sub cname; do
    [[ -z "$sub" || -z "$cname" ]] && continue

    # Normalize trailing dot
    cname="${cname%.}"

    for service in "${!FINGERPRINTS[@]}"; do
        if echo "$cname" | grep -qi "$service"; then
            fingerprint="${FINGERPRINTS[$service]}"
            
            # Check if the subdomain itself resolves or returns the fingerprint
            response=$(curl -s --max-time 10 -H "User-Agent: Mozilla/5.0" "https://$sub" 2>/dev/null)
            http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://$sub" 2>/dev/null || echo "000")

            if echo "$response" | grep -qi "$fingerprint" || [[ "$http_code" == "404" || "$http_code" == "NXDOMAIN" || "$http_code" == "500" ]]; then
                echo "$sub|$cname|$service|POTENTIAL" >> "$TAKEOVER_FILE"
                found "POTENTIAL: $sub → $cname ($service)"
                ((TAKEOVER_COUNT++))
                break
            fi

            # Also check HTTP
            http_response=$(curl -s --max-time 10 -H "User-Agent: Mozilla/5.0" "http://$sub" 2>/dev/null || echo "")
            if echo "$http_response" | grep -qi "$fingerprint"; then
                echo "$sub|$cname|$service|POTENTIAL" >> "$TAKEOVER_FILE"
                found "POTENTIAL: $sub → $cname ($service)"
                ((TAKEOVER_COUNT++))
                break
            fi
        fi
    done

    # Check for dangling bare CNAMEs (no A record resolution)
    for dangling in "herokuapp.com" "github.io" "gitlab.io" "bitbucket.io" "azurewebsites.net" "cloudapp.net" "amazonaws.com" "elasticbeanstalk.com"; do
        if echo "$cname" | grep -qi "$dangling"; then
            # Service is up but subdomain may not be assigned
            if [[ "$http_code" == "404" || "$http_code" == "000" || "$http_code" == "403" ]]; then
                service_name=$(echo "$dangling" | cut -d. -f1)
                echo "$sub|$cname|$service_name|DANGLING" >> "$TAKEOVER_FILE"
                warn "DANGLING: $sub → $cname (unclaimed)"
                ((TAKEOVER_COUNT++))
            fi
        fi
    done

done < "$CNAME_TEMP"

# ─── NS lookup for bare domains ───
log "Checking naked domain takeovers..."
for sub in "$DOMAIN" "www" "cdn" "api" "mail" "admin"; do
    a_record=$(dig +short A "$sub" 2>/dev/null | grep -v '^$' | head -1)
    
    if [[ -z "$a_record" || "$a_record" == *"NXDOMAIN"* || "$a_record" == *"SERVFAIL"* ]]; then
        # Domain has no A — could be pointed to a service
        cname=$(dig +short CNAME "$sub" 2>/dev/null | head -1)
        if [[ -n "$cname" ]]; then
            cname="${cname%.}"
            info "  $sub → $cname (no A record, relying on CNAME)"
        else
            warn "  $sub has no A or CNAME — investigate manually"
            echo "$sub||NONE|UNRESOLVED" >> "$TAKEOVER_FILE"
        fi
    fi
done

# ─── Cloud tag check for AWS ───
log "Checking AWS-specific takeover vectors..."
aws_elb_check() {
    local sub=$1
    local cname=$2
    if echo "$cname" | grep -qi "elb\|amazonaws\|cloudfront\|fastly"; then
        # Check if ELB DNS name resolves
        elb_host=$(echo "$cname" | tr '[:upper:]' '[:lower:]')
        if ! dig +short "$elb_host" >/dev/null 2>&1; then
            warn "  ELB orphaned: $sub → $elb_host"
            echo "$sub|$cname|aws-elb|ORPHANED" >> "$TAKEOVER_FILE"
        fi
    fi
}
export -f aws_elb_check

# ─── JSON output ───
if [[ "$JSON_OUTPUT" == "true" ]]; then
    log "Generating JSON report..."
    {
        echo "{"
        echo "  \"domain\": \"$DOMAIN\","
        echo "  \"timestamp\": \"$(date -I)\","
        echo "  \"stats\": {"
        echo "    \"total_subdomains\": $SUB_COUNT,"
        echo "    \"cname_records\": $CNAME_COUNT,"
        echo "    \"potential_takeovers\": $TAKEOVER_COUNT"
        echo "  },"
        echo "  \"takeovers\": ["
        while IFS='|' read -r sub cname service status; do
            [[ -z "$sub" ]] && continue
            echo "    {"
            echo "      \"subdomain\": \"$sub\","
            echo "      \"cname\": \"$cname\","
            echo "      \"service\": \"$service\","
            echo "      \"status\": \"$status\""
            echo "    },"
        done < "$TAKEOVER_FILE" | sed '$ s/,$//'
        echo "  ]"
        echo "}"
    } > "$JSON_FILE"
    log "JSON written to: $JSON_FILE"
fi

# ─── Summary ───
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "Subdomain Takeover Scan Complete"
echo -e "${GREEN}[✓]${NC} Total subdomains:  $SUB_COUNT"
echo -e "${GREEN}[✓]${NC} CNAME records:     $CNAME_COUNT"
echo -e "${YELLOW}[!]${NC} Potential takeovers: $TAKEOVER_COUNT"
echo ""
echo -e "  Results:  ${YELLOW}$TAKEOVER_FILE${NC}"
echo -e "  Raw subs: ${YELLOW}$RAW_SUBS${NC}"
echo -e "  Log:      $LOG_FILE"
[[ "$JSON_OUTPUT" == "true" ]] && echo -e "  JSON:     ${BLUE}$JSON_FILE${NC}"
echo ""

if [[ "$TAKEOVER_COUNT" -gt 0 ]]; then
    info "Review potential takeovers — some may require manual verification"
    info "Confirmed takeovers can lead to: credential theft, phishing, data interception"
fi

log "Scan complete — use only with authorization"