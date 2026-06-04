#!/bin/bash

# Usage: ./username_osint_variations.sh <base_username> [proxy]
# Example: ./username_osint_variations.sh johndoe http://127.0.0.1:8080

BASE_USERNAME=$1
PROXY=$2

if [ -z "$BASE_USERNAME" ]; then
    echo "Usage: $0 <base_username> [proxy]"
    exit 1
fi

# Optional proxy
if [ ! -z "$PROXY" ]; then
    echo "Using proxy: $PROXY"
    PROXY_OPT="-x $PROXY"
else
    PROXY_OPT=""
fi

# List of platforms (expand as needed)
SITES=(
    "https://www.instagram.com/{u}/"
    "https://twitter.com/{u}"
    "https://www.facebook.com/{u}"
    "https://www.reddit.com/user/{u}"
    "https://github.com/{u}"
    "https://www.linkedin.com/in/{u}"
    "https://www.tiktok.com/@{u}"
    "https://www.pinterest.com/{u}/"
    "https://soundcloud.com/{u}"
    "https://www.spotify.com/user/{u}"
    "https://www.youtube.com/@{u}"
    "https://medium.com/@{u}"
    "https://www.twitch.tv/{u}"
    "https://steamcommunity.com/id/{u}"
)

# Generate username variations
generate_variations() {
    local base="$1"
    local variations=()

    # Original
    variations+=("$base")

    # Common number suffixes
    for num in 1 12 123 007 69 420 666 88 99 00 01 02 03 1234 2020 2021 2022 2023 2024 2025; do
        variations+=("${base}${num}")
        variations+=("${base}_${num}")
        variations+=("${base}-${num}")
    done

    # Year suffixes (current + recent)
    for year in {2015..2026}; do
        variations+=("${base}${year}")
        variations+=("${base}_${year}")
    done

    # Common words
    for word in official real the real_ official_ pro admin dev x y z vip elite king queen boss; do
        variations+=("${base}_${word}")
        variations+=("${base}${word}")
        variations+=("${word}${base}")
        variations+=("${word}_${base}")
    done

    # Separators
    variations+=("${base}_")
    variations+=("${base}__")
    variations+=("${base}_official")
    variations+=("the${base}")
    variations+=("${base}dotcom")

    # Dots and dashes
    if [[ "$base" == *" "* ]]; then
        nospace=$(echo "$base" | tr -d ' ')
        variations+=("$nospace")
        variations+=("${nospace}_")
    fi
    variations+=("${base// /.}")   # space -> dot
    variations+=("${base// /-}")   # space -> dash
    variations+=("${base// /_}")   # space -> underscore

    # Simple leetspeak (light)
    variations+=("${base/o/0}")
    variations+=("${base/O/0}")
    variations+=("${base/a/@}")
    variations+=("${base/e/3}")
    variations+=("${base/i/1}")
    variations+=("${base/s/5}")

    # Remove duplicates and return
    printf "%s\n" "${variations[@]}" | sort -u
}

echo "Base username: $BASE_USERNAME"
echo "Generating variations and checking availability..."
echo "-------------------------------------------------"

# Generate list of usernames to check
mapfile -t USERNAMES < <(generate_variations "$BASE_USERNAME")

FOUND_COUNT=0

for USERNAME in "${USERNAMES[@]}"; do
    echo "Testing: $USERNAME"
    for SITE_TEMPLATE in "${SITES[@]}"; do
        URL=${SITE_TEMPLATE//\{u\}/$USERNAME}
        RESPONSE=$(curl $PROXY_OPT -s -o /dev/null -w "%{http_code}" --max-time 10 --head "$URL" 2>/dev/null)

        if [ "$RESPONSE" == "200" ]; then
            echo "  [+] FOUND on $(echo $URL | awk -F[/:] '{print $4}')"
            ((FOUND_COUNT++))
        elif [ "$RESPONSE" == "404" ]; then
            : # Silent for not found
        elif [ "$RESPONSE" == "000" ]; then
            echo "  [!] Timeout/Error on $URL (proxy/blocked?)"
        else
            echo "  [?] $RESPONSE on $URL (may exist)"
        fi
    done
    echo "-------------------------------------------------"
done

echo "Scan complete. Found $FOUND_COUNT profiles across variations."
