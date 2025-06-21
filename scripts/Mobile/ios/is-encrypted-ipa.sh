#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# ========== CONFIG ==========
REQUIRED_TOOLS=(file unzip tar otool jq)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
# ============================

json() {
    jq -n --arg key "$1" --arg val "$2" '{$key: $val}'
}

error_exit() {
    jq -n --arg error "$1" '{"error": $error}'
    exit 1
}

check_required_tools() {
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            error_exit "Missing required tool: $tool"
        fi
    done
}

# ========== MAIN ==========
main() {
    [[ $# -ne 1 ]] && error_exit "Usage: $0 <path_to_ipa>"

    IPA_FILE="$1"
    [[ ! -f "$IPA_FILE" ]] && error_exit "IPA file not found: $IPA_FILE"

    FILE_TYPE=$(file -b "$IPA_FILE")

    if echo "$FILE_TYPE" | grep -iq "zip archive"; then
        unzip -q "$IPA_FILE" -d "$TMP_DIR" || error_exit "Failed to unzip IPA"
    elif echo "$FILE_TYPE" | grep -iq "gzip compressed"; then
        tar -xzf "$IPA_FILE" -C "$TMP_DIR" || error_exit "Failed to extract gzip IPA"
    else
        error_exit "Unsupported IPA format: $FILE_TYPE"
    fi

    APP_DIR=$(find "$TMP_DIR/Payload" -type d -name "*.app" | head -n1)
    [[ -z "$APP_DIR" ]] && error_exit "No .app found in Payload"

    BINARY_NAME=$(/usr/libexec/PlistBuddy -c 'Print CFBundleExecutable' "$APP_DIR/Info.plist" 2>/dev/null || basename "$APP_DIR")
    BINARY_PATH="$APP_DIR/$BINARY_NAME"

    [[ ! -f "$BINARY_PATH" ]] && error_exit "Binary not found: $BINARY_PATH"

    OT_OUTPUT=$(otool -l "$BINARY_PATH" 2>/dev/null) || error_exit "otool failed on binary"

    CRYPTID=$(echo "$OT_OUTPUT" | awk '/LC_ENCRYPTION_INFO/,/cryptid/ { if ($1 == "cryptid") print $2; }')

    [[ -z "$CRYPTID" ]] && error_exit "Could not extract cryptid"

    case "$CRYPTID" in
        1) jq -n '{"encrypted": true, "cryptid": 1}' ;;
        0) jq -n '{"encrypted": false, "cryptid": 0}' ;;
        *) error_exit "Unknown cryptid value: $CRYPTID" ;;
    esac
}

check_required_tools
main "$@"
