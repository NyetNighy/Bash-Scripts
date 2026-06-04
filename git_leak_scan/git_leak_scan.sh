#!/bin/bash

# Git Secret Leak Scanner
# Scan repositories for committed secrets, API keys, credentials, and sensitive data
# Usage: ./git_leak_scan.sh <repo_url|path> [-o output_dir] [-j] [-r]
# Requires: git, grep, jq, curl
# Disclaimer: For authorized security testing only

set -euo pipefail

TARGET="${1:-}"
OUTPUT_DIR=""
JSON_OUTPUT=false
RECURSIVE=false
DEEP_MODE=false

RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' BLUE='\033[0;34m' CYAN='\033[0;36m' NC='\033[0m'
log()   { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"; }
warn()  { echo -e "${YELLOW}[-] $1${NC}"; }
found() { echo -e "${GREEN}[✓] $1${NC}"; }
fail()  { echo -e "${RED}[!] $1${NC}"; }

usage() {
    head -4 "$0" | cut -c4-
    echo ""
    echo "Options:"
    echo "  -o, --output DIR   Output directory"
    echo "  -j, --json         JSON output"
    echo "  -r, --recursive    Recursive clone (for GitHub org scanning)"
    echo "  -d, --deep         Deep scan (include binary files, large blobs)"
    echo "  -h, --help         Show this help"
    echo ""
    echo "Example:"
    echo "  $0 https://github.com/user/repo -o leak_scan"
    echo "  $0 /path/to/local/repo -j"
    echo "  $0 https://github.com/org --recursive -o org_scan"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        -j|--json) JSON_OUTPUT=true; shift ;;
        -r|--recursive) RECURSIVE=true; shift ;;
        -d|--deep) DEEP_MODE=true; shift ;;
        -h|--help) usage ;;
        *) TARGET="$1"; shift ;;
    esac
done

[[ -z "$TARGET" ]] && usage

# Determine if it's a URL or local path
if [[ "$TARGET" =~ ^https?:// ]] || [[ "$TARGET" =~ ^git@ ]]; then
    REMOTE=true
    SAFE_NAME=$(echo "$TARGET" | sed 's/.*[\/:]//; s/\.git$//' | tr -cd 'a-zA-Z0-9_-')
else
    REMOTE=false
    if [[ ! -d "$TARGET" ]]; then
        fail "Not a directory: $TARGET"
        exit 1
    fi
    SAFE_NAME=$(basename "$TARGET")
fi

[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="git_leak_${SAFE_NAME}_$(date +%Y-%m-%d)"
mkdir -p "$OUTPUT_DIR"

LOG_FILE="$OUTPUT_DIR/scan.log"
LEAKS_FILE="$OUTPUT_DIR/leaks.txt"
REPO_DIR="$OUTPUT_DIR/repo_clone"
JSON_FILE="$OUTPUT_DIR/results.json"
COMMIT_LOG="$OUTPUT_DIR/commit_history.txt"

log "Starting Git leak scan: $TARGET"

# ═══════════════════════════════════════════════════════════
# Regex patterns for secrets
# ═══════════════════════════════════════════════════════════

declare -a SECRET_PATTERNS=(
    # AWS
    "(?i)AKIA[0-9A-Z]{16}"
    "(?i)aws[_-]?access[_-]?key[_-]?id"
    "(?i)aws[_-]?secret[_-]?access[_-]?key"
    "eyJ[A-Za-z0-9+/=]{40,}"

    # Generic API keys
    "(?i)api[_-]?key[\s:=]+['\"]?[a-zA-Z0-9]{20,}"
    "(?i)apikey[\s:=]+['\"]?[a-zA-Z0-9]{20,}"
    "(?i)secret[_-]?key[\s:=]+['\"]?[a-zA-Z0-9]{20,}"
    "(?i)bearer[\s]+[a-zA-Z0-9._-]{20,}"

    # Private keys
    "-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"

    # Database connection strings
    "(?i)(mysql|postgres|mongodb|redis):\/\/[^\s]+:[^\s]+@[^\s]+"
    "mongodb(\+srv)?:\/\/[^:\s]+:[^@\s]+@[^:\/\s]+"
    "(?i)connection[_-]?string[\s:=]+['\"]?[a-zA-Z0-9:/\?=&%;_-]{20,}"

    # JWT tokens
    "eyJ[A-Za-z0-9+/=]{50,}"

    # Slack tokens
    "xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"

    # GitHub tokens
    "gh[pousr]_[A-Za-z0-9]{36,}"
    "[a-f0-9]{40}"

    # Passwords in config
    "(?i)password[\s:=]+['\"][^'\"]{8,}"
    "(?i)passwd[\s:=]+['\"][^'\"]{8,}"
    "(?i)db[_-]?pass[\s:=]+['\"][^'\"]{8,}"

    # HMAC keys
    "(?i)hmac[_-]?key[\s:=]+['\"]?[a-zA-Z0-9]{20,}"

    # Azure
    "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"

    # Google API
    "AIza[0-9A-Za-z_-]{35}"

    # Stripe
    "sk_live_[0-9a-zA-Z]{24,}"
    "pk_live_[0-9a-zA-Z]{24,}"

    # Twilio
    "SK[0-9a-fA-F]{32}"
)

declare -a SUSPICIOUS_FILES=(
    ".env" ".env.local" ".env.development" ".env.production" ".env.backup"
    "config/database.yml" "config/secrets.yml" "config/credentials.yml"
    "secrets.json" "credentials.json" "keys.json" "tokens.json"
    "settings.py" "settings.gradle" "build.gradle"
    "*.pem" "*.key" "*.p12" "*.jks" "*.keystore"
    "wp-config.php" "configuration.php" "settings.php"
    "id_rsa" "id_dsa" "id_ecdsa" "id_ed25519" "*.ppk"
    ".netrc" "netrc" ".git-credentials" ".gitignore"
    "docker-compose.yml" "docker-compose.yaml" "Dockerfile"
    "deploy_key" "deploy_token" "service_key"
)

# ═══════════════════════════════════════════════════════════
# Clone repo if remote
# ═══════════════════════════════════════════════════════════
if [[ "$REMOTE" == "true" ]]; then
    log "Cloning repository..."

    if [[ "$RECURSIVE" == "true" && "$TARGET" =~ github ]]; then
        # GitHub org scan
        log "  Recursive mode — cloning all repos"
        gh repo clone "$TARGET" -- --recurse-submodules "$REPO_DIR" 2>/dev/null || \
        git clone --mirror "$TARGET" "$REPO_DIR" 2>/dev/null || {
            fail "Failed to clone repository"
            exit 1
        }
    else
        git clone --depth 100 "$TARGET" "$REPO_DIR" 2>/dev/null || {
            fail "Failed to clone repository"
            exit 1
        }
    fi
else
    REPO_DIR="$TARGET"
    log "Scanning local repository: $REPO_DIR"
fi

# Check it's actually a git repo
if [[ ! -d "$REPO_DIR/.git" ]] && [[ ! -d "$REPO_DIR" ]]; then
    fail "Not a git repository: $REPO_DIR"
    exit 1
fi

# ═══════════════════════════════════════════════════════════
# Phase 1: Full git history scan (all branches)
# ═══════════════════════════════════════════════════════════
log "Phase 1: Scanning full git history (all branches)"

> "$LEAKS_FILE"
LEAK_COUNT=0

git_log() {
    git -C "$REPO_DIR" log --all --oneline --pretty=format:"%H|%an|%ae|%ai|%s" 2>/dev/null || true
}

# Scan every commit
git_log | while IFS='|' read -r commit_hash author email date message; do
    [[ -z "$commit_hash" ]] && continue

    # Get diff for this commit
    files_changed=$(git -C "$REPO_DIR" diff-tree --no-commit-id --name-only -r "$commit_hash" 2>/dev/null || true)

    for file in $files_changed; do
        # Skip binary files (unless deep mode)
        if [[ "$DEEP_MODE" != "true" ]] && [[ "$file" =~ \.(png|jpg|jpeg|gif|ico|zip|tar|gz|rar|pdf|exe|dll|so|class)$ ]]; then
            continue
        fi

        # Get file content at this commit
        content=$(git -C "$REPO_DIR" show "$commit_hash:$file" 2>/dev/null || true)
        [[ -z "$content" ]] && continue

        for pattern in "${SECRET_PATTERNS[@]}"; do
            if echo "$content" | grep -EQ "$pattern" 2>/dev/null; then
                matches=$(echo "$content" | grep -Eo "$pattern" | head -5 | tr '\n' ' ')
                echo "$commit_hash|$file|$pattern|$matches" >> "$LEAKS_FILE"
                found "  LEAK in $file (commit $commit_hash): $matches"
                ((LEAK_COUNT++))
            fi
        done
    done
done

# ═══════════════════════════════════════════════════════════
# Phase 2: Current state scan (working tree)
# ═══════════════════════════════════════════════════════════
log "Phase 2: Scanning current working tree"

# Scan for suspicious files
for pattern in "${SUSPICIOUS_FILES[@]}"; do
    if [[ "$pattern" =~ \*\. ]]; then
        ext=$(echo "$pattern" | tr -d '*')
        # Glob pattern — escape properly
        find "$REPO_DIR" -type f -name "*$ext" 2>/dev/null | while read -r filepath; do
            [[ -f "$filepath" ]] || continue
            # Skip .git directory
            [[ "$filepath" =~ /\.git/ ]] && continue

            content=$(cat "$filepath" 2>/dev/null || true)
            [[ -z "$content" ]] && continue

            for secret_pattern in "${SECRET_PATTERNS[@]}"; do
                if echo "$content" | grep -EQ "$secret_pattern" 2>/dev/null; then
                    matches=$(echo "$content" | grep -Eo "$secret_pattern" | head -3 | tr '\n' ' ')
                    echo "WORKING|$filepath|$secret_pattern|$matches" >> "$LEAKS_FILE"
                    found "  CURRENT LEAK: $filepath"
                    ((LEAK_COUNT++))
                fi
            done
        done
    else
        # Exact file match
        find "$REPO_DIR" -type f -name "$pattern" 2>/dev/null | while read -r filepath; do
            [[ "$filepath" =~ /\.git/ ]] && continue
            content=$(cat "$filepath" 2>/dev/null || true)
            for secret_pattern in "${SECRET_PATTERNS[@]}"; do
                if echo "$content" | grep -EQ "$secret_pattern" 2>/dev/null; then
                    matches=$(echo "$content" | grep -Eo "$secret_pattern" | head -3 | tr '\n' ' ')
                    echo "WORKING|$filepath|$secret_pattern|$matches" >> "$LEAKS_FILE"
                    found "  CURRENT LEAK: $filepath"
                    ((LEAK_COUNT++))
                fi
            done
        done
    fi
done

# ═══════════════════════════════════════════════════════════
# Phase 3: Branch comparison (stale secrets in old branches)
# ═══════════════════════════════════════════════════════════
log "Phase 3: Comparing branches for leaked secrets"

git -C "$REPO_DIR" branch -a 2>/dev/null | while read -r branch; do
    branch=$(echo "$branch" | sed 's/^\s*//; s/^\*//' | xargs)
    [[ -z "$branch" || "$branch" =~ \(detached\) ]] && continue

    branch=${branch#remotes/}
    branch=${branch#origin/}

    # Get files from this branch vs main/master
    for compare in "main" "master" "develop"; do
        diff_files=$(git -C "$REPO_DIR" diff "$compare...$branch" --name-only 2>/dev/null || true)
        for file in $diff_files; do
            [[ -z "$file" ]] && continue

            # Check if this branch has secrets that main doesn't
            branch_content=$(git -C "$REPO_DIR" show "$branch:$file" 2>/dev/null || true)
            main_content=$(git -C "$REPO_DIR" show "main:$file" 2>/dev/null || echo "__FILE_NOT_IN_MAIN__")

            if [[ "$branch_content" != "$main_content" ]] && [[ "$main_content" != "__FILE_NOT_IN_MAIN__" ]]; then
                for pattern in "${SECRET_PATTERNS[@]}"; do
                    if echo "$branch_content" | grep -EQ "$pattern" 2>/dev/null; then
                        matches=$(echo "$branch_content" | grep -Eo "$pattern" | head -3 | tr '\n' ' ')
                        echo "BRANCH|$branch|$file|$pattern|$matches" >> "$LEAKS_FILE"
                        found "  Secret in branch $branch: $file"
                        ((LEAK_COUNT++))
                    fi
                done
            fi
        done
    done
done 2>/dev/null || true

# ═══════════════════════════════════════════════════════════
# Phase 4: GitHub-specific scanning (if remote)
# ═══════════════════════════════════════════════════════════
if [[ "$REMOTE" == "true" && "$TARGET" =~ github ]]; then
    log "Phase 4: GitHub-specific secret scanning"

    # GitHub Advanced Security secrets
    if gh auth status >/dev/null 2>&1; then
        log "  Using GitHub Advanced Security API..."
        gh api "repos/$(echo $TARGET | sed 's/.*github.com\///; s/\/.*//; s/\//\//')/secret-scanning/alerts" 2>/dev/null | \
            jq -r '.[] | "\(.name)|\(..state)|\(..秘境.secret_type)"' >> "$LEAKS_FILE" || true
    fi

    # Also check GitHub commit history via API
    owner_repo=$(echo "$TARGET" | sed 's/.*github.com\///; s/\.git$//')
    commits_url="https://api.github.com/repos/$owner_repo/commits?per_page=100"

    for secret_pattern in "${SECRET_PATTERNS[@]}"; do
        # Search code via GitHub API
        search_result=$(curl -s -H "Accept: application/vnd.github.v3+json" \
            "https://api.github.com/search/code?q=$secret_pattern+repo:$owner_repo&per_page=30" 2>/dev/null | \
            jq -r '.items[].path' 2>/dev/null || true)

        if [[ -n "$search_result" ]]; then
            echo "GITHUB|$secret_pattern|$search_result" >> "$LEAKS_FILE"
            found "  GitHub search hit: $search_result"
            ((LEAK_COUNT++))
        fi
    done
fi

# ═══════════════════════════════════════════════════════════
# Phase 5: Commit history log
# ═══════════════════════════════════════════════════════════
log "Phase 5: Generating commit history"
git -C "$REPO_DIR" log --all --oneline --pretty=format:"%H|%an|%ae|%ai|%s" > "$COMMIT_LOG" 2>/dev/null || true

# ═══════════════════════════════════════════════════════════
# JSON output
# ═══════════════════════════════════════════════════════════
if [[ "$JSON_OUTPUT" == "true" ]]; then
    log "Generating JSON output..."

    TOTAL_COMMITS=$(git -C "$REPO_DIR" rev-list --all --count 2>/dev/null || echo 0)
    TOTAL_FILES=$(git -C "$REPO_DIR" ls-files 2>/dev/null | wc -l || echo 0)
    BRANCH_COUNT=$(git -C "$REPO_DIR" branch -a 2>/dev/null | wc -l || echo 0)

    {
        echo "{"
        echo "  \"target\": \"$TARGET\","
        echo "  \"timestamp\": \"$(date -I)\","
        echo "  \"stats\": {"
        echo "    \"leaks_found\": $LEAK_COUNT,"
        echo "    \"total_commits\": $TOTAL_COMMITS,"
        echo "    \"total_files\": $TOTAL_FILES,"
        echo "    \"branches\": $BRANCH_COUNT"
        echo "  },"
        echo "  \"leaks\": ["
        while IFS='|' read -r location file pattern matches; do
            [[ -z "$location" ]] && continue
            echo "    {"
            echo "      \"location\": \"$location\","
            echo "      \"file\": \"$file\","
            echo "      \"pattern\": \"$pattern\","
            echo "      \"matches\": \"$matches\""
            echo "    },"
        done < "$LEAKS_FILE" | sed '$ s/,$//'
        echo "  ]"
        echo "}"
    } > "$JSON_FILE"
fi

# ═══════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════
TOTAL_COMMITS=$(git -C "$REPO_DIR" rev-list --all --count 2>/dev/null || echo 0)
TOTAL_FILES=$(git -C "$REPO_DIR" ls-files 2>/dev/null | wc -l || echo 0)

log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "Git Leak Scan Complete — $TARGET"
echo -e "${RED}[!]${NC} Leaks found:       $LEAK_COUNT"
echo -e "${GREEN}[✓]${NC} Total commits:    $TOTAL_COMMITS"
echo -e "${GREEN}[✓]${NC} Total files:      $TOTAL_FILES"
echo ""
echo -e "  Leaks:    ${RED}$LEAKS_FILE${NC}"
echo -e "  Commits:  ${CYAN}$COMMIT_LOG${NC}"
echo -e "  JSON:     ${BLUE}$JSON_FILE${NC}"
echo ""

if [[ "$LEAK_COUNT" -gt 0 ]]; then
    warn "Review $LEAKS_FILE — secrets may be exposed in commit history"
    warn "Remediation: git filter-branch or BFG Repo-Cleaner to rewrite history"
    warn "ALWAYS rotate any keys/passwords found — they are compromised"
fi

log "Scan complete — use only with authorization"