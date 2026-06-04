#!/bin/bash

# OSINT Email Harvester for Specific Domain
# Kali Linux Bash Script
# Usage: ./email_harvester.sh example.com [options]
# Options:
#   -d, --delay SECONDS     Delay between requests (default: 0)
#   -o, --output DIR       Output directory (default: emails_<domain>)
#   -j, --json             Output results as JSON
#   -f, --filter-subdomain  Only include emails from this subdomain
#   -r, --rate-limit       Enable automatic rate-limit backoff
#   -h, --help             Show this help
# Requirements: dnsenum, theHarvester, sublist3r, assetfinder, amass, gau, httpx, curl, jq
# Disclaimer: For ethical OSINT only. Respect robots.txt, rate limits, and laws.

set -euo pipefail

DOMAIN=""
OUTPUT_DIR=""
JSON_OUTPUT=false
FILTER_SUBDOMAIN=""
RATE_LIMIT=false
DELAY=0
THREADS=10
TIMEOUT=30

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Help
show_help() {
    grep "^# Usage:" "$0" | sed 's/^# //'
    echo ""
    echo "Options:"
    grep -A1 "^\s*-" "$0" | grep -E "^\s+-| Description" | paste - - | column -t -s $'\t'
}

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--delay) DELAY="$2"; shift 2 ;;
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        -j|--json) JSON_OUTPUT=true; shift ;;
        -f|--filter-subdomain) FILTER_SUBDOMAIN="$2"; shift 2 ;;
        -r|--rate-limit) RATE_LIMIT=true; shift ;;
        -h|--help) show_help; exit 0 ;;
        *) DOMAIN="$1"; shift ;;
    esac
done

if [[ -z "$DOMAIN" ]]; then
    echo -e "${RED}Usage: $0 <domain> [-d delay] [-o output_dir] [-j] [-f subdomain] [-r]${NC}"
    echo "Example: $0 example.com -d 2 -j -f staff"
    exit 1
fi

[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="emails_${DOMAIN}"
SAFE_DOMAIN=$(echo "$DOMAIN" | tr -cd 'a-zA-Z0-9.-' | tr '[:upper:]' '[:lower:]')
mkdir -p "$OUTPUT_DIR"

LOG_FILE="$OUTPUT_DIR/harvest.log"
RAW_EMAILS="$OUTPUT_DIR/raw_emails.txt"
UNIQUE_EMAILS="$OUTPUT_DIR/unique_emails.txt"
VALID_EMAILS="$OUTPUT_DIR/valid_emails.txt"
SUBDOMAIN_FILE="$OUTPUT_DIR/subdomains.txt"
JSON_FILE="$OUTPUT_DIR/results.json"

# Rate-limit state
declare -A RATE_LIMIT_STATE
rate_limit_active=false

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "${BLUE}$msg${NC}" | tee -a "$LOG_FILE"
}

rate_limit_backoff() {
    local wait_time="${1:-5}"
    log "${YELLOW}[RATE LIMIT] Sleeping ${wait_time}s before retry...${NC}"
    sleep "$wait_time"
}

apply_delay() {
    [[ "$DELAY" -gt 0 ]] && sleep "$DELAY"
}

extract_domain_emails() {
    local input="$1"
    local output="$2"
    grep -Eio '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' "$input" 2>/dev/null | grep -i "$DOMAIN" >> "$output" || true
}

json_add_array() {
    local key="$1"
    local value="$2"
    local first="${3:-false}"
    if [[ "$first" == "true" ]]; then
        echo "  \"$key\": [" | tee -a "$JSON_FILE"
    else
        echo "  \"$key\": [" | tee -a "$JSON_FILE"
    fi
}

json_email_entry() {
    local email="$1"
    local source="$2"
    local subdomain="${3:-}"
    local line="    {\"email\": \"$email\", \"source\": \"$source\""
    [[ -n "$subdomain" ]] && line+=", \"subdomain\": \"$subdomain\""
    echo "$line},"
}

# ─── JSON header ───
init_json() {
    echo "{" > "$JSON_FILE"
    echo "  \"domain\": \"$DOMAIN\", " >> "$JSON_FILE"
    echo "  \"timestamp\": \"$(date -I)\", " >> "$JSON_FILE"
    echo "  \"raw_count\": 0, " >> "$JSON_FILE"
    echo "  \"unique_count\": 0, " >> "$JSON_FILE"
    echo "  \"valid_count\": 0, " >> "$JSON_FILE"
    echo "  \"emails\": [], " >> "$JSON_FILE"
    echo "  \"subdomains\": []" >> "$JSON_FILE"
    echo "}" >> "$JSON_FILE"
}

update_json_field() {
    local key="$1"
    local value="$2"
    sed -i "s/\"$key\": [0-9]*/\"$key\": $value/" "$JSON_FILE" 2>/dev/null || true
}

# ═══════════════════════════════════════════════════════════
# PHASE 1: Subdomain enumeration
# ═══════════════════════════════════════════════════════════
log "Phase 1: Subdomain enumeration"
SUB_DOMAINS=()

log "  [dnsenum]"
dnsenum --dnsserver 8.8.8.8,1.1.1.1 "$DOMAIN" -f /usr/share/dnsenum/dns.txt -w -r 2>/dev/null | tee "$OUTPUT_DIR/dnsenum.txt" | grep -oE '[a-z0-9.-]+\.'"$DOMAIN" | sort -u >> "$SUBDOMAIN_FILE" &
SUB_DOMAINS+=($!)

log "  [sublist3r]"
sublist3r -d "$DOMAIN" -o "$OUTPUT_DIR/sublist3r.txt" -t 20 -v 2>/dev/null | grep -oE '[a-z0-9.-]+\.'"$DOMAIN" | sort -u >> "$SUBDOMAIN_FILE" || true

log "  [assetfinder]"
assetfinder --subs-only "$DOMAIN" >> "$SUBDOMAIN_FILE" 2>/dev/null || true

log "  [amass]"
amass enum -passive -d "$DOMAIN" -o "$OUTPUT_DIR/amass.txt" 2>/dev/null || true
cat "$OUTPUT_DIR/amass.txt" >> "$SUBDOMAIN_FILE" 2>/dev/null || true

wait

# Deduplicate subdomains
sort -u "$SUBDOMAIN_FILE" -o "$SUBDOMAIN_FILE" 2>/dev/null || true
SUB_COUNT=$(wc -l < "$SUBDOMAIN_FILE" 2>/dev/null || echo 0)
log "  Found $SUB_COUNT subdomains"

# ═══════════════════════════════════════════════════════════
# PHASE 2: theHarvester + LinkedIn enumeration
# ═══════════════════════════════════════════════════════════
log "Phase 2: theHarvester + LinkedIn"

log "  [theHarvester - all sources]"
apply_delay
theHarvester -d "$DOMAIN" -b all -f "$OUTPUT_DIR/theharvester.html" -l 500 -t "$THREADS" 2>/dev/null | tee "$OUTPUT_DIR/theharvester.txt" || true

log "  [LinkedIn enumeration via Google dorks]"
apply_delay
# LinkedIn company/employee dorks
for dork in \
    "site:linkedin.com \"@${DOMAIN}\"" \
    "site:linkedin.com/in \"${DOMAIN}\"" \
    "site:linkedin.com/company \"${DOMAIN}\""; do
    log "    Dorking: $dork"
    apply_delay
    curl -s "https://www.google.com/search?q=$(echo "$dork" | sed 's/ /+/g')" \
        -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
        --cookie "CONSENT=YES" 2>/dev/null | \
        grep -oE '[a-zA-Z0-9._%-]+@'"$DOMAIN" | sort -u >> "$RAW_EMAILS" || true
done

log "  [LinkedIn via Hunter.io]"
apply_delay
if [[ -n "${HUNTER_API_KEY:-}" ]]; then
    curl -s "https://api.hunter.io/v2/domain-search?domain=${DOMAIN}&api_key=${HUNTER_API_KEY}" | \
        jq -r '.data.email[] | "\(.value),\(.type)"' 2>/dev/null | while IFS=',' read -r email type; do
        echo "$email" >> "$RAW_EMAILS"
    done || true
fi

# LinkedIn via Snov.io (if API key set)
apply_delay
if [[ -n "${SNOV_API_KEY:-}" ]]; then
    curl -s "https://api.snov.io/domain-emails?domain=${DOMAIN}&access_token=${SNOV_API_KEY}" | \
        jq -r '.[].email' 2>/dev/null >> "$RAW_EMAILS" || true
fi

# ═══════════════════════════════════════════════════════════
# PHASE 3: GitHub recon
# ═══════════════════════════════════════════════════════════
log "Phase 3: GitHub recon"

log "  [GitHub user search]"
apply_delay
curl -s -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/search/users?q=%40${DOMAIN}&per_page=30" | \
    jq -r '.items[].login' 2>/dev/null | while read -r user; do
        log "    Fetching repos for: $user"
        apply_delay
        curl -s "https://api.github.com/users/$user/repos?per_page=50&type=public" | \
            jq -r '.[].html_url' 2>/dev/null >> "$OUTPUT_DIR/github_repos.txt" || true
    done

log "  [GitHub code search for emails]"
apply_delay
curl -s "https://api.github.com/search/code?q=%40${DOMAIN}&per_page=50" | \
    jq -r '.items[].html_url' 2>/dev/null | while read -r url; do
        apply_delay
        curl -s "$url" 2>/dev/null | grep -oE '[a-z0-9._%-]+@'"$DOMAIN" >> "$RAW_EMAILS" || true
    done

# ═══════════════════════════════════════════════════════════
# PHASE 4: Breach data (h8mail)
# ═══════════════════════════════════════════════════════════
log "Phase 4: Breach data [h8mail]"
if command -v h8mail >/dev/null 2>&1; then
    apply_delay
    echo "@$DOMAIN" | h8mail -o "$OUTPUT_DIR/h8mail.txt" --no-hibp-reporter 2>/dev/null || true
else
    log "  h8mail not found, skipping"
fi

# ═══════════════════════════════════════════════════════════
# PHASE 5: Web scraping (gau, wayback, JS)
# ═══════════════════════════════════════════════════════════
log "Phase 5: Web scraping"

log "  [gau]"
apply_delay
command -v gau >/dev/null && gau "$DOMAIN" > "$OUTPUT_DIR/gau.txt" || true

log "  [waybackurls]"
apply_delay
command -v waybackurls >/dev/null && waybackurls "$DOMAIN" >> "$OUTPUT_DIR/gau.txt" || true

log "  [httpx - filtering live URLs]"
apply_delay
if command -v httpx >/dev/null; then
    cat "$OUTPUT_DIR/gau.txt" | httpx -silent -mc 200 -t 50 -o "$OUTPUT_DIR/live_urls.txt" 2>/dev/null || true
fi

log "  [JS file email extraction]"
apply_delay
if command -v gau >/dev/null; then
    gau "$DOMAIN" | grep -i '\.js$' | while read -r js_url; do
        apply_delay
        curl -s --max-time 10 "$js_url" 2>/dev/null | \
            grep -oE '[a-z0-9._%-]+@'"$DOMAIN" >> "$RAW_EMAILS" || true
    done
fi

# ═══════════════════════════════════════════════════════════
# PHASE 6: Social / Paste sites
# ═══════════════════════════════════════════════════════════
log "Phase 6: Social & Paste recon"

for site_dork in \
    "site:pastebin.com \"@${DOMAIN}\"" \
    "site:github.com \"@${DOMAIN}\"" \
    "site:gitlab.com \"@${DOMAIN}\""; do
    log "    Dorking: $site_dork"
    apply_delay
    curl -s "https://www.google.com/search?q=$(echo "$site_dork" | sed 's/ /+/g')" \
        -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
        --cookie "CONSENT=YES" 2>/dev/null | \
        grep -oE '[a-z0-9._%-]+@'"$DOMAIN" | sort -u >> "$RAW_EMAILS" || true
done

# ═══════════════════════════════════════════════════════════
# PHASE 7: Aggregate + extract + deduplicate
# ═══════════════════════════════════════════════════════════
log "Phase 7: Aggregating and extracting emails"

# Extract from all sources
extract_domain_emails "$OUTPUT_DIR/dnsenum.txt" "$RAW_EMAILS"
extract_domain_emails "$OUTPUT_DIR/sublist3r.txt" "$RAW_EMAILS"
extract_domain_emails "$OUTPUT_DIR/assetfinder.txt" "$RAW_EMAILS"
extract_domain_emails "$OUTPUT_DIR/amass.txt" "$RAW_EMAILS"
extract_domain_emails "$OUTPUT_DIR/theharvester.txt" "$RAW_EMAILS"
extract_domain_emails "$OUTPUT_DIR/h8mail.txt" "$RAW_EMAILS"
extract_domain_emails "$OUTPUT_DIR/gau.txt" "$RAW_EMAILS"
extract_domain_emails "$OUTPUT_DIR/js_emails.txt" "$RAW_EMAILS"
extract_domain_emails "$OUTPUT_DIR/github_emails.txt" "$RAW_EMAILS"
extract_domain_emails "$OUTPUT_DIR/github_repos.txt" "$RAW_EMAILS"

# Sort + deduplicate
sort -u "$RAW_EMAILS" -o "$UNIQUE_EMAILS" 2>/dev/null || true

# Filter by subdomain if requested
if [[ -n "$FILTER_SUBDOMAIN" ]]; then
    log "  Filtering by subdomain: $FILTER_SUBDOMAIN"
    grep "@${FILTER_SUBDOMAIN}." "$UNIQUE_EMAILS" > "$OUTPUT_DIR/filtered_emails.txt" || true
    FILTER_COUNT=$(wc -l < "$OUTPUT_DIR/filtered_emails.txt" 2>/dev/null || echo 0)
    log "  Found $FILTER_COUNT emails matching subdomain"
fi

# ═══════════════════════════════════════════════════════════
# PHASE 8: Validate emails (syntax + MX)
# ═══════════════════════════════════════════════════════════
log "Phase 8: Validating emails (MX check)"

INPUT_EMAILS="$UNIQUE_EMAILS"
[[ -f "$OUTPUT_DIR/filtered_emails.txt" ]] && INPUT_EMAILS="$OUTPUT_DIR/filtered_emails.txt"

> "$VALID_EMAILS"
while IFS= read -r email; do
    email=$(echo "$email" | tr -d '\r' | xargs)
    [[ -z "$email" ]] && continue

    # Rate-limit detection
    if [[ "$RATE_LIMIT" == "true" ]]; then
        if host -t MX "${email##*@}" >/dev/null 2>&1; then
            rate_limit_active=false
        else
            # Could be rate-limited, back off
            rate_limit_backoff 5
        fi
    else
        host -t MX "${email##*@}" >/dev/null 2>&1 || continue
    fi

    echo "$email"
done < "$INPUT_EMAILS" > "$VALID_EMAILS"

# ═══════════════════════════════════════════════════════════
# PHASE 9: Build JSON output
# ═══════════════════════════════════════════════════════════
if [[ "$JSON_OUTPUT" == "true" ]]; then
    log "Phase 9: Building JSON output"

    INIT_COUNT=$(wc -l < "$RAW_EMAILS" 2>/dev/null || echo 0)
    UNIQUE_COUNT=$(wc -l < "$UNIQUE_EMAILS" 2>/dev/null || echo 0)
    VALID_COUNT=$(wc -l < "$VALID_EMAILS" 2>/dev/null || echo 0)

    # Build JSON
    {
        echo "{"
        echo "  \"domain\": \"$DOMAIN\","
        echo "  \"timestamp\": \"$(date -I)\","
        echo "  \"config\": {"
        echo "    \"delay\": $DELAY,"
        echo "    \"filter_subdomain\": \"$FILTER_SUBDOMAIN\","
        echo "    \"rate_limit\": $RATE_LIMIT"
        echo "  },"
        echo "  \"stats\": {"
        echo "    \"raw\": $INIT_COUNT,"
        echo "    \"unique\": $UNIQUE_COUNT,"
        echo "    \"valid\": $VALID_COUNT,"
        echo "    \"subdomains_found\": $(wc -l < "$SUBDOMAIN_FILE" 2>/dev/null || echo 0)"
        echo "  },"
        echo "  \"subdomains\": ["
        while IFS= read -r sub; do
            echo "    \"$sub\","
        done < "$SUBDOMAIN_FILE" | sed '$ s/,$//'
        echo "  ],"
        echo "  \"emails\": ["
        while IFS= read -r email; do
            email=$(echo "$email" | tr -d '\r' | xargs)
            [[ -z "$email" ]] && continue
            local subdomain="${email##*@}"
            echo "    {"
            echo "      \"address\": \"$email\","
            echo "      \"subdomain\": \"$subdomain\","
            echo "      \"valid\": true"
            echo "    },"
        done < "$VALID_EMAILS" | sed '$ s/,$//'
        echo "  ]"
        echo "}"
    } > "$JSON_FILE"

    log "  JSON written to: $JSON_FILE"
fi

# ═══════════════════════════════════════════════════════════
# FINAL STATS
# ═══════════════════════════════════════════════════════════
TOTAL=$(wc -l < "$RAW_EMAILS" 2>/dev/null || echo 0)
UNIQUE=$(wc -l < "$UNIQUE_EMAILS" 2>/dev/null || echo 0)
VALID=$(wc -l < "$VALID_EMAILS" 2>/dev/null || echo 0)

log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "Harvest complete!"
echo -e "${GREEN}[✓]${NC} Total raw:     $TOTAL"
echo -e "${GREEN}[✓]${NC} Unique emails:  $UNIQUE"
echo -e "${GREEN}[✓]${NC} Valid (MX):    $VALID"
echo -e "${GREEN}[✓]${NC} Subdomains:    $SUB_COUNT"
echo ""
echo -e "  Raw:       ${YELLOW}$RAW_EMAILS${NC}"
echo -e "  Unique:    ${YELLOW}$UNIQUE_EMAILS${NC}"
echo -e "  Valid:     ${GREEN}$VALID_EMAILS${NC}"
[[ "$JSON_OUTPUT" == "true" ]] && echo -e "  JSON:      ${CYAN}$JSON_FILE${NC}"
echo -e "  Log:       $LOG_FILE"
echo ""
log "Pro tips:"
echo "  - Check $SUBDOMAIN_FILE for more targets"
echo "  - Use -f <subdomain> to filter emails by subdomain"
echo "  - Use -r to enable automatic rate-limit backoff"
echo "  - Use -d <seconds> to add delay between requests"
echo "  - Use -j for machine-readable JSON output"