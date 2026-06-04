#!/bin/bash

# Usage: ./username_osint.sh <username> [proxy]
# Example: ./username_osint.sh john_doe http://127.0.0.1:8080
# Proxy format: http://host:port or socks5://host:port (optional auth: http://user:pass@host:port)

USERNAME=$1
PROXY=$2

if [ -z "$USERNAME" ]; then
    echo "Usage: $0 <username> [proxy]"
    exit 1
fi

# List of sites with {u} placeholder for username
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
    "https://www.roblox.com/users/profile?username={u}"
    "https://myspace.com/{u}"
    "https://vimeo.com/{u}"
    "https://www.discogs.com/user/{u}"
    "https://www.last.fm/user/{u}"
    "https://bitbucket.org/{u}/"
)

echo "Checking username: $USERNAME"
if [ ! -z "$PROXY" ]; then
    echo "Using proxy: $PROXY"
    PROXY_OPT="-x $PROXY"
else
    PROXY_OPT=""
fi

for SITE in "${SITES[@]}"; do
    URL=${SITE//\{u\}/$USERNAME}
    echo -n "Checking $URL ... "
    
    RESPONSE=$(curl $PROXY_OPT -s -o /dev/null -w "%{http_code}" --max-time 10 "$URL")
    
    if [ "$RESPONSE" == "200" ]; then
        echo "FOUND"
    elif [ "$RESPONSE" == "404" ]; then
        echo "Not found"
    elif [ "$RESPONSE" == "000" ]; then
        echo "Timeout/Error (possible block or bad proxy)"
    else
        echo "Other ($RESPONSE - may exist but restricted)"
    fi
done

echo "Done."
