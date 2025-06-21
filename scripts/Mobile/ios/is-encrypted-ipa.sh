#!/bin/bash

set -euo pipefail

usage() {
    echo "Usage: $0 <path_to_ipa>"
    exit 1
}

for cmd in otool unzip; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd not found. Please install it."
        exit 1
    fi
done

if [[ $# -ne 1 ]]; then
    usage
fi

IPA_FILE="$1"

# Check if file exists and is a valid IPA
if [[ ! -f "$IPA_FILE" || "${IPA_FILE##*.}" != "ipa" ]]; then
    echo "Error: Invalid or missing IPA file - $IPA_FILE"
    exit 1
fi

# Temporary directory for extraction
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

echo "Extracting IPA to temporary directory..."
FILE_TYPE=$(file "$IPA_FILE")
if echo "$FILE_TYPE" | grep -q "Zip archive data"; then
    info "Detected .ipa as valid .zip archive"
    unzip -q "$IPA_FILE" -d "$TEMP_DIR" || fail "Failed to unzip IPA"
elif echo "$FILE_TYPE" | grep -q "gzip compressed data"; then
    info "Detected .ipa as gzip-compressed (tar.gz)"
    tar -xzf "$IPA_FILE" -C "$TEMP_DIR" || fail "Failed to extract gzip archive"
else
    fail "Unsupported IPA format: $FILE_TYPE"
fi

# Find the app binary
APP_PATH=$(find "$TEMP_DIR/Payload" -type d -name "*.app" | head -n 1)
if [[ -z "$APP_PATH" ]]; then
    echo "Error: Unable to find .app directory in IPA."
    exit 1
fi

BINARY_NAME=$(basename "$APP_PATH" .app)
BINARY_PATH="$APP_PATH/$BINARY_NAME"

if [[ ! -f "$BINARY_PATH" ]]; then
    echo "Error: App binary not found at $BINARY_PATH."
    exit 1
fi

echo "Performing encryption status check using otool..."
if ! OT_OUTPUT=$(otool -l "$BINARY_PATH" 2>/dev/null); then
    echo "Error: Failed to analyze binary using otool."
    exit 1
fi

# Extract the cryptid value
CRYPTID=$(echo "$OT_OUTPUT" | awk '/LC_ENCRYPTION_INFO/,/cryptid/' | grep -m1 cryptid | awk '{print $2}')

if [[ -z "$CRYPTID" ]]; then
    echo "Error: Unable to determine encryption status. cryptid not found."
    exit 1
fi

# Print encryption status
if [[ "$CRYPTID" == "1" ]]; then
    echo "✅ Result: The IPA is encrypted (cryptid = 1)."
elif [[ "$CRYPTID" == "0" ]]; then
    echo "✅ Result: The IPA is not encrypted (cryptid = 0)."
else
    echo "Error: Unexpected cryptid value: $CRYPTID"
    exit 1
fi
