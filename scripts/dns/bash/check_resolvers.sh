#!/bin/bash
# External dependencies:
# - dig (from the dnsutils package) for testing DNS resolution
# - xargs for parallel processing
# - grep for filtering out empty lines and comments

RESOLVERS_FILE="resolvers.txt"
OUTPUT_FILE="working_resolvers.txt"
TEST_DOMAIN="google.com"
THREADS=10

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -i FILE   Input file with resolver IPs (default: resolvers.txt)"
    echo "  -o FILE   Output file for working resolvers (default: working_resolvers.txt)"
    echo "  -d DOMAIN Domain to test resolution (default: google.com)"
    echo "  -t THREADS Number of parallel threads (default: 10)"
    echo "  -h        Display this help message"
    exit 1
}

while getopts ":i:o:d:t:h" opt; do
    case "$opt" in
        i) RESOLVERS_FILE="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        d) TEST_DOMAIN="$OPTARG" ;;
        t) THREADS="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [[ ! -f $RESOLVERS_FILE ]]; then
    echo "Error: File '$RESOLVERS_FILE' not found!"
    exit 1
fi

# To clear contents of existing file {OUTPUT_FILE}
> "$OUTPUT_FILE"

check_resolver() {
    local resolver_ip="$1"
    dig @"$resolver_ip" "$TEST_DOMAIN" +short > /dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo "$resolver_ip" >> "$OUTPUT_FILE"
        echo "✅ $resolver_ip is working."
    else
        echo "❌ $resolver_ip failed."
    fi
}

export -f check_resolver
export TEST_DOMAIN OUTPUT_FILE

# Filter comment (starting with #) and empty lines and do xargs
grep -v '^\(#\|$\)' "$RESOLVERS_FILE" | xargs -n 1 -P "$THREADS" bash -c 'check_resolver "$0"' 

echo "Testing complete. Working resolvers saved to '$OUTPUT_FILE'."