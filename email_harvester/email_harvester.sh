#!/bin/bash

# OSINT Email Harvester for Specific Domain
# Kali Linux Bash Script
# Usage: ./email_harvester.sh <domain> [options]
# Options:
#   -d, --delay SECONDS     Delay between requests (default: 0)
#   -o, --output DIR        Output directory (default: emails_<domain>)
#   -j, --json             Output results as JSON
#   -f, --filter-subdomain Only include emails from this subdomain
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

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

show_help() {
    head -14 "$0" | tail -12
    echo ""
    echo "Options:"
    grep "^\s*-" "$0" | while read -r line; do
        echo "  $line"
    done
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

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

apply_delay() {
    [[ "$DELAY" -gt 0 ]] && sleep "$DELAY"
}

rate_limit_backoff() {
    log "${YELLOW}[RATE LIMIT] Sleeping ${1}s before retry...${NC}"
    sleep "$1"
}

strip_ansi() {
    sed 's/\x1b\[[0-9;]*m//g'
}

extract_domain_emails() {
    local input="$1"
    local output="$2"
    [[ -f "$input" ]] || return
    strip_ansi "$input" 2>/dev/null | \
        grep -Eio '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' | \
        grep -i "$DOMAIN" >> "$output" || true
}

# ═══════════════════════════════════════════════════════════
# PHASE 1: Subdomain enumeration
# ═══════════════════════════════════════════════════════════
log "Phase 1: Subdomain enumeration"

log "  [dnsenum]"
(dnsenum --dnsserver 8.8.8.8,1.1.1.1 "$DOMAIN" -f /usr/share/dnsenum/dns.txt -w -r 2>/dev/null || true) | \
    strip_ansi | grep -oE '[a-z0-9.-]+\.'"$DOMAIN" | sort -u >> "$SUBDOMAIN_FILE" &

log "  [sublist3r]"
(sublist3r -d "$DOMAIN" -o "$OUTPUT_DIR/sublist3r.txt" -t 20 -v 2>/dev/null || true) | \
    strip_ansi | grep -oE '[a-z0-9.-]+\.'"$DOMAIN" | sort -u >> "$SUBDOMAIN_FILE" || true

log "  [assetfinder]"
(assetfinder --subs-only "$DOMAIN" 2>/dev/null || true) >> "$SUBDOMAIN_FILE" || true

log "  [amass]"
(amass enum -passive -d "$DOMAIN" -o "$OUTPUT_DIR/amass.txt" 2>/dev/null || true)
[[ -f "$OUTPUT_DIR/amass.txt" ]] && cat "$OUTPUT_DIR/amass.txt" >> "$SUBDOMAIN_FILE" || true

wait

sort -u "$SUBDOMAIN_FILE" -o "$SUBDOMAIN_FILE" 2>/dev/null || true
SUB_COUNT=$(wc -l < "$SUBDOMAIN_FILE" 2>/dev/null || echo 0)
log "  Found $SUB_COUNT subdomains"

# ═══════════════════════════════════════════════════════════
# PHASE 2: theHarvester + LinkedIn
# ═══════════════════════════════════════════════════════════
log "Phase 2: theHarvester + LinkedIn"

log "  [theHarvester]"
apply_delay
theHarvester -d "$DOMAIN" -b all -f "$OUTPUT_DIR/theharvester.html" -l 500 -t "$THREADS" 2>&1 | \
    strip_ansi | tee "$OUTPUT_DIR/theharvester.txt" || \
    log "  theHarvester completed with warnings"

log "  [LinkedIn Google dorks]"
for dork in \
    "site:linkedin.com \"@${DOMAIN}\"" \
    "site:linkedin.com/in \"${DOMAIN}\"" \
    "site:linkedin.com/company \"${DOMAIN}\""; do
    log "    Dorking: $dork"
    apply_delay
    result=$(curl -s "https://www.google.com/search?q=$(echo "$dork" | sed 's/ /+/g')" \
        -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
        --cookie "CONSENT=YES" 2>/dev/null | \
        strip_ansi | grep -oE '[a-zA-Z0-9._%-]+@'"$DOMAIN" | sort -u)
    [[ -n "$result" ]] && echo "$result" >> "$RAW_EMAILS" || true
done

log "  [LinkedIn via Hunter.io]"
apply_delay
if [[ -n "${HUNTER_API_KEY:-}" ]]; then
    result=$(curl -s "https://api.hunter.io/v2/domain-search?domain=${DOMAIN}&api_key=${HUNTER_API_KEY}" | \
        jq -r '.data.email[] | .value' 2>/dev/null)
    [[ -n "$result" ]] && echo "$result" >> "$RAW_EMAILS" || true
else
    log "    HUNTER_API_KEY not set, skipping"
fi

# ═══════════════════════════════════════════════════════════
# PHASE 3: GitHub recon
# ═══════════════════════════════════════════════════════════
log "Phase 3: GitHub recon"

log "  [GitHub user search]"
apply_delay
response=$(curl -s -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/search/users?q=%40${DOMAIN}&per_page=30")

if echo "$response" | jq -e '.items' >/dev/null 2>&1; then
    echo "$response" | jq -r '.items[].login' 2>/dev/null | while read -r user; do
        log "    Fetching repos for: $user"
        apply_delay
        repos_response=$(curl -s "https://api.github.com/users/$user/repos?per_page=50&type=public")
        if echo "$repos_response" | jq -e '.[]' >/dev/null 2>&1; then
            echo "$repos_response" | jq -r '.[].html_url' 2>/dev/null >> "$OUTPUT_DIR/github_repos.txt" || true
        fi
    done
else
    log "    GitHub rate limit or error, skipping"
fi

log "  [GitHub code search]"
apply_delay
code_response=$(curl -s "https://api.github.com/search/code?q=%40${DOMAIN}&per_page=50")
if echo "$code_response" | jq -e '.items' >/dev/null 2>&1; then
    echo "$code_response" | jq -r '.items[].html_url' 2>/dev/null | while read -r url; do
        apply_delay
        curl -s --max-time 15 "$url" 2>/dev/null | \
            strip_ansi | grep -oE '[a-z0-9._%-]+@'"$DOMAIN" >> "$RAW_EMAILS" || true
    done
else
    log "    GitHub code search rate-limited or error, skipping"
fi

# ═══════════════════════════════════════════════════════════
# PHASE 4: Breach data
# ═══════════════════════════════════════════════════════════
log "Phase 4: Breach data [h8mail]"
if command -v h8mail >/dev/null 2>&1; then
    apply_delay
    echo "@$DOMAIN" | h8mail -o "$OUTPUT_DIR/h8mail.txt" --no-hibp-reporter 2>/dev/null || true
else
    log "  h8mail not found, skipping"
fi

# ═══════════════════════════════════════════════════════════
# PHASE 5: Web scraping
# ═══════════════════════════════════════════════════════════
log "Phase 5: Web scraping"

log "  [gau]"
apply_delay
command -v gau >/dev/null && gau "$DOMAIN" > "$OUTPUT_DIR/gau.txt" || touch "$OUTPUT_DIR/gau.txt"

log "  [waybackurls]"
apply_delay
command -v waybackurls >/dev/null && waybackurls "$DOMAIN" >> "$OUTPUT_DIR/gau.txt" || true

log "  [httpx - filtering live URLs]"
apply_delay
if command -v httpx >/dev/null && [[ -s "$OUTPUT_DIR/gau.txt" ]]; then
    httpx -silent -mc 200 -t 50 -o "$OUTPUT_DIR/live_urls.txt" < "$OUTPUT_DIR/gau.txt" 2>/dev/null || true
fi

log "  [JS file email extraction]"
apply_delay
if command -v gau >/dev/null; then
    gau "$DOMAIN" 2>/dev/null | grep -i '\.js$' | while read -r js_url; do
        apply_delay
        curl -s --max-time 10 "$js_url" 2>/dev/null | \
            strip_ansi | grep -oE '[a-z0-9._%-]+@'"$DOMAIN" >> "$RAW_EMAILS" || true
    done
fi

# ═══════════════════════════════════════════════════════════
# PHASE 6: Paste / Social
# ═══════════════════════════════════════════════════════════
log "Phase 6: Social & Paste recon"

for site_dork in \
    "site:pastebin.com \"@${DOMAIN}\"" \
    "site:github.com \"@${DOMAIN}\""; do
    log "    Dorking: $site_dork"
    apply_delay
    result=$(curl -s "https://www.google.com/search?q=$(echo "$site_dork" | sed 's/ /+/g')" \
        -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
        --cookie "CONSENT=YES" 2>/dev/null | \
        strip_ansi | grep -oE '[a-zA-Z0-9._%-]+@'"$DOMAIN" | sort -u)
    [[ -n "$result" ]] && echo "$result" >> "$RAW_EMAILS" || true
done

# ═══════════════════════════════════════════════════════════
# PHASE 7: Aggregate + deduplicate
# ═══════════════════════════════════════════════════════════
log "Phase 7: Aggregating and extracting emails"

: > "$RAW_EMAILS"

extract_domain_emails "$OUTPUT_DIR/dnsenum.txt" "$RAW_EMAILS"
extract_domain_emails "$OUTPUT_DIR/sublist3r.txt" "$RAW_EMAILS"
extract_domain_emails "$OUTPUT_DIR/assetfinder.txt" "$RAW_EMAILS"
extract_domain_emails "$OUTPUT_DIR/amass.txt" "$RAW_EMAILS"
extract_domain_emails "$OUTPUT_DIR/theharvester.txt" "$RAW_EMAILS"
extract_domain_emails "$OUTPUT_DIR/h8mail.txt" "$RAW_EMAILS"
extract_domain_emails "$OUTPUT_DIR/gau.txt" "$RAW_EMAILS"
extract_domain_emails "$OUTPUT_DIR/js_emails.txt" "$RAW_EMAILS"
extract_domain_emails "$OUTPUT_DIR/github_repos.txt" "$RAW_EMAILS"

sort -u "$RAW_EMAILS" -o "$UNIQUE_EMAILS" 2>/dev/null || true

if [[ -n "$FILTER_SUBDOMAIN" ]]; then
    log "  Filtering by subdomain: $FILTER_SUBDOMAIN"
    grep "@${FILTER_SUBDOMAIN}." "$UNIQUE_EMAILS" > "$OUTPUT_DIR/filtered_emails.txt" || true
    FILTER_COUNT=$(wc -l < "$OUTPUT_DIR/filtered_emails.txt" 2>/dev/null || echo 0)
    log "  Found $FILTER_COUNT emails matching subdomain"
fi

# ═══════════════════════════════════════════════════════════
# PHASE 8: Validate (MX check)
# ═══════════════════════════════════════════════════════════
log "Phase 8: Validating emails (MX check)"

INPUT_EMAILS="$UNIQUE_EMAILS"
[[ -f "$OUTPUT_DIR/filtered_emails.txt" ]] && INPUT_EMAILS="$OUTPUT_DIR/filtered_emails.txt"

: > "$VALID_EMAILS"
while IFS= read -r email; do
    email=$(echo "$email" | tr -d '\r' | xargs)
    [[ -z "$email" ]] && continue
    if host -t MX "${email##*@}" >/dev/null 2>&1; then
        echo "$email"
    else
        [[ "$RATE_LIMIT" == "true" ]] && rate_limit_backoff 3
    fi
done < "$INPUT_EMAILS" > "$VALID_EMAILS"

# ═══════════════════════════════════════════════════════════
# PHASE 9: JSON output
# ═══════════════════════════════════════════════════════════
if [[ "$JSON_OUTPUT" == "true" ]]; then
    log "Phase 9: Building JSON output"

    RAW_COUNT=$(wc -l < "$RAW_EMAILS" 2>/dev/null || echo 0)
    UNIQUE_COUNT=$(wc -l < "$UNIQUE_EMAILS" 2>/dev/null || echo 0)
    VALID_COUNT=$(wc -l < "$VALID_EMAILS" 2>/dev/null || echo 0)
    SUB_COUNT=$(wc -l < "$SUBDOMAIN_FILE" 2>/dev/null || echo 0)

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
        echo "    \"raw\": $RAW_COUNT,"
        echo "    \"unique\": $UNIQUE_COUNT,"
        echo "    \"valid\": $VALID_COUNT,"
        echo "    \"subdomains\": $SUB_COUNT"
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
RAW_TOTAL=$(wc -l < "$RAW_EMAILS" 2>/dev/null || echo 0)
UNIQUE_TOTAL=$(wc -l < "$UNIQUE_EMAILS" 2>/dev/null || echo 0)
VALID_TOTAL=$(wc -l < "$VALID_EMAILS" 2>/dev/null || echo 0)

log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "Harvest complete!"
echo -e "${GREEN}[✓]${NC} Total raw:     $RAW_TOTAL"
echo -e "${GREEN}[✓]${NC} Unique emails:  $UNIQUE_TOTAL"
echo -e "${GREEN}[✓]${NC} Valid (MX):    $VALID_TOTAL"
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