#!/bin/bash

REENROLL_FLAG="$HOME/.2fa_reenroll"

enroll_otp() {
    echo "=== 2FA Enrolment Required ==="
    echo "Welcome! For security, you must set up 2FA now."
    echo "This will generate a QR code—scan it with Google Authenticator or Authy."
    echo "Save the emergency scratch codes shown— they're for recovery!"
    echo "Press Enter to start..."
    read -r
    google-authenticator
    if [ -f ~/.google_authenticator ]; then
        echo "Enrolment successful! Future logins require your OTP."
    else
        echo "Enrolment failed. Please try again."
        return 1  # Failure to loop
    fi
    return 0
}

# Trap Ctrl+C (SIGINT) to prevent interruption and retry
trap 'echo ""; echo "Interruption detected. You must complete 2FA enrolment to proceed. Retrying..."; return' INT

# Enforce first-time enrolment (mandatory loop with post-check)
if [ ! -f ~/.google_authenticator ]; then
    while true; do
        enroll_otp && break
        echo "You must complete enrolment to proceed. Retrying..."
    done

    # Post-loop enforcement: If still no file (e.g., advanced interruption), warn and exit shell
    if [ ! -f ~/.google_authenticator ]; then
        echo "ERROR: 2FA enrolment not completed. For security, logging you out."
        echo "Please try again or contact admin."
        exit 1  # Exit the shell, forcing logout
    fi
fi

# Reset trap after enrolment (allow normal Ctrl+C in shell)
trap - INT

# Check for re-enrolment - no enforcement here
if [ -f "$REENROLL_FLAG" ]; then
    echo "=== 2FA Recovery Mode ==="
    echo "Admin has enabled a one-time bypass (e.g., for lost phone)."
    echo "Your current OTP may not work."
    read -p "Generate a new OTP secret now? (y/n): " choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        enroll_otp
    else                                                                        
        echo "OK, skipping. Run 'google-authenticator' manually if needed."
    fi
    rm "$REENROLL_FLAG"  # Clean up the flag (user can do this)
fi