#!/bin/bash

FLAGS_DIR="/var/lib/2fa_flags"
BYPASS_FILE="$FLAGS_DIR/$PAM_USER.bypass"

HOME_DIR=$(getent passwd "$PAM_USER" | cut -d: -f6)
REENROLL_FLAG="$HOME_DIR/.2fa_reenroll"

if [ ! -d "$FLAGS_DIR" ] || [ ! -r "$FLAGS_DIR" ] || [ ! -w "$FLAGS_DIR" ] || [ ! -d "$HOME_DIR" ] || [ ! -w "$HOME_DIR" ]; then
    exit 1  # Fail silently
fi

if [ -f "$BYPASS_FILE" ]; then
    rm "$BYPASS_FILE" || exit 1
    touch "$REENROLL_FLAG" || exit 1
    chown "$PAM_USER:$PAM_USER" "$REENROLL_FLAG" || exit 1 
    chmod 600 "$REENROLL_FLAG" || exit 1  
    exit 0  # Bypass successful, skip OTP
fi

exit 1  # No bypass, proceed to OTP requirement