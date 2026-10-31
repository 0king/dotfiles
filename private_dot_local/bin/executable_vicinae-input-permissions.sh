#!/usr/bin/env bash
set -euo pipefail

################################################################################
# Script: vicinae-input-permissions.sh
# Location: ~/.local/bin/vicinae-input-permissions.sh
#
# ==============================================================================
# 1. WHY THIS SCRIPT EXISTS (THE PROBLEM & SECURITY THREAT MODEL)
# ==============================================================================
# Vicinae (https://vicinae.com) is an extensible launcher on Linux. Its snippet
# auto-expansion and key injection engine requires two low-level Linux kernel
# capabilities:
#
#   a) Monitoring physical keystrokes via evdev (/dev/input/event*) to detect
#      when you type your trigger keywords (e.g. ";;e2").
#   b) Simulating a virtual keyboard via /dev/uinput to delete the trigger
#      sequence with backspaces and inject clipboard paste (Ctrl+V).
#
# On modern Linux (Ubuntu/Debian/Fedora/Arch), /dev/input/event* and /dev/uinput
# are restricted to root and the 'input' group (permissions: crw-rw----).
#
# Typically, users and installers resort to one of two flawed workarounds:
#
#   FLAWED WORKAROUND A: "sudo setcap cap_dac_override+ep vicinae-input-server"
#     - Risk: cap_dac_override allows the binary to bypass ALL Linux file
#       permission checks across the entire filesystem (e.g. reading /etc/shadow
#       or user SSH private keys if the binary were ever compromised).
#
#   FLAWED WORKAROUND B: "sudo usermod -aG input $USER"
#     - Risk: Adding your normal user account to the 'input' group grants EVERY
#       program running under your user account (browsers, npm/pip packages,
#       Steam games, random terminal scripts) raw read access to all keyboards.
#       Any unprivileged user script can silently act as an ambient keylogger,
#       completely breaking Wayland's built-in input isolation.
#
# THE SOLUTION IMPLEMENTED BY THIS SCRIPT (THE GOLD STANDARD: LEAST PRIVILEGE):
#   - Keep your user account OUTSIDE the 'input' group (no ambient keylogger).
#   - Strip broad filesystem capabilities (setcap -r) from the binary.
#   - Configure the helper binary (vicinae-input-server) with SetGID 'input' (2755).
#     When executed, ONLY vicinae-input-server gains effective GID 'input'.
#     Your other user applications do NOT inherit this group.
#   - Deploy a scoped udev rule with POSIX ACLs for /dev/uinput so both 'input'
#     and existing tools (e.g., mouseless) can access virtual keyboard injection.
#
# ==============================================================================
# 2. WHAT THIS SCRIPT DOES (TECHNICAL DETAILS)
# ==============================================================================
# When running "apply":
#   1. Locates vicinae-input-server in /usr/local/libexec/vicinae or local build.
#   2. Removes your user ($TARGET_USER, default 'dj') from group 'input'.
#   3. Clears any filesystem capabilities (setcap -r) from vicinae-input-server.
#   4. Sets file ownership to root:input and permissions to 2755 (SetGID):
#        - 2: SetGID bit (runs with effective group ID 'input').
#        - 7: Owner (root) has rwx.
#        - 5: Group (input) has rx.
#        - 5: Others have rx.
#   5. Deploys /etc/udev/rules.d/99-vicinae-uinput.rules to grant group 'input'
#      read/write access to /dev/uinput using POSIX ACLs (setfacl), ensuring
#      no conflicts with other software managing uinput (like 'mouseless').
#   6. Loads kernel module 'uinput' and triggers udev to apply changes immediately.
#
# When running "revert":
#   1. Removes the custom udev rule /etc/udev/rules.d/99-vicinae-uinput.rules.
#   2. Restores default 0755 permissions and root:root ownership on the binary.
#   3. Cleans up capabilities and reloads udev rules to restore factory state.
#
# When running "status":
#   1. Inspects your user's group memberships (verifying absence of 'input').
#   2. Inspects vicinae-input-server binary path, permissions, and capabilities.
#   3. Inspects /dev/uinput ownership and POSIX ACL entries.
#
# ==============================================================================
# 3. HOW TO USE THIS SCRIPT
# ==============================================================================
# Check current permission status (can be run without sudo):
#   ~/.local/bin/vicinae-input-permissions.sh status
#
# Apply the secure configuration (requires sudo):
#   sudo ~/.local/bin/vicinae-input-permissions.sh apply
#
# Revert back to system default (requires sudo):
#   sudo ~/.local/bin/vicinae-input-permissions.sh revert
#
# After applying, restart Vicinae to use the new permissions:
#   killall vicinae-server vicinae-input-server 2>/dev/null || true
#   vicinae
################################################################################

UDEV_RULE_FILE="/etc/udev/rules.d/99-vicinae-uinput.rules"
MODULES_LOAD_FILE="/etc/modules-load.d/uinput.conf"
DEFAULT_BINARY="/usr/local/libexec/vicinae/vicinae-input-server"
BUILD_BINARY="/media/d_drive/dev/local-builds/vicinae/build/bin/vicinae-input-server"
TARGET_USER="${SUDO_USER:-${USER:-dj}}"

# ------------------------------------------------------------------------------
# Helper: Verify root privileges
# ------------------------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Error: This action requires administrator privileges." >&2
        echo "Please re-run using sudo: sudo $0 ${1:-apply}" >&2
        exit 1
    fi
}

# ------------------------------------------------------------------------------
# Helper: Locate the vicinae-input-server binary
# ------------------------------------------------------------------------------
find_binary() {
    if [[ -f "$DEFAULT_BINARY" ]]; then
        echo "$DEFAULT_BINARY"
    elif [[ -f "$BUILD_BINARY" ]]; then
        echo "$BUILD_BINARY"
    else
        command -v vicinae-input-server || true
    fi
}

# ------------------------------------------------------------------------------
# Action: apply
# ------------------------------------------------------------------------------
do_apply() {
    check_root "apply"
    echo "=== Applying Secure Vicinae Input Permissions ==="

    local bin
    bin=$(find_binary)
    if [[ -z "$bin" ]]; then
        echo "Error: Could not locate vicinae-input-server binary." >&2
        echo "Checked locations:" >&2
        echo "  - $DEFAULT_BINARY" >&2
        echo "  - $BUILD_BINARY" >&2
        exit 1
    fi
    echo "[1/5] Target binary identified: $bin"

    # Step 1: Remove user from 'input' group to close the ambient keylogger hole
    if id -nG "$TARGET_USER" 2>/dev/null | grep -qw "input"; then
        echo "[2/5] Removing user '$TARGET_USER' from group 'input'..."
        gpasswd -d "$TARGET_USER" input || true
    else
        echo "[2/5] User '$TARGET_USER' is not in 'input' group. (OK)"
    fi

    # Step 2: Strip broad filesystem capabilities (cap_dac_override)
    echo "[3/5] Stripping broad filesystem capabilities from binary..."
    setcap -r "$bin" 2>/dev/null || true

    # Step 3: Grant SetGID 'input' (2755) to the binary
    # This allows only vicinae-input-server to inherit GID 'input' upon exec
    echo "[4/5] Setting ownership to root:input and mode 2755 (SetGID)..."
    chown root:input "$bin"
    chmod 2755 "$bin"

    # Step 4: Configure udev rule for /dev/uinput using POSIX ACLs
    # Using setfacl ensures existing groups (like 'mouseless') are preserved
    echo "[5/5] Deploying udev rule for /dev/uinput..."
    cat << 'EOF' > "$UDEV_RULE_FILE"
# Secure uinput access for Vicinae using POSIX ACLs
KERNEL=="uinput", SUBSYSTEM=="misc", GROUP="input", MODE="0660", OPTIONS+="static_node=uinput", RUN+="/usr/bin/setfacl -m g:input:rw /dev/uinput"
EOF

    echo "uinput" > "$MODULES_LOAD_FILE"
    modprobe uinput 2>/dev/null || true

    udevadm control --reload-rules
    udevadm trigger --name-match=uinput 2>/dev/null || udevadm trigger
    if [[ -e /dev/uinput ]] && command -v setfacl >/dev/null 2>&1; then
        setfacl -m g:input:rw /dev/uinput 2>/dev/null || true
    fi

    echo ""
    echo "✓ Successfully configured vicinae-input-server!"
    echo "  - Binary: $bin (Ownership: root:input, Mode: 2755 / SetGID)"
    echo "  - User: '$TARGET_USER' removed from group 'input'"
    echo "  - /dev/uinput: granted read/write permissions to 'input' group"
    echo ""
    echo "Important: Active login shells cache group memberships."
    echo "Your user '$TARGET_USER' will completely lose 'input' group access on your next desktop login."
}

# ------------------------------------------------------------------------------
# Action: revert
# ------------------------------------------------------------------------------
do_revert() {
    check_root "revert"
    echo "=== Reverting Vicinae Input Permissions ==="

    local bin
    bin=$(find_binary)

    # Step 1: Remove udev rules
    if [[ -f "$UDEV_RULE_FILE" ]]; then
        echo "[1/3] Removing custom udev rule $UDEV_RULE_FILE..."
        rm -f "$UDEV_RULE_FILE"
        udevadm control --reload-rules
        udevadm trigger
    fi

    # Step 2: Reset binary permissions to standard root:root 0755
    if [[ -n "$bin" && -f "$bin" ]]; then
        echo "[2/3] Resetting ownership and permissions on $bin..."
        chown root:root "$bin" 2>/dev/null || chown "$TARGET_USER:$TARGET_USER" "$bin"
        chmod 0755 "$bin"
        setcap -r "$bin" 2>/dev/null || true
    fi

    echo "[3/3] Done. Input permissions restored to system defaults."
}

# ------------------------------------------------------------------------------
# Action: status
# ------------------------------------------------------------------------------
do_status() {
    echo "=== Vicinae Input Permissions Status ==="
    echo "Target User:  $TARGET_USER"
    echo "User Groups:  $(id -nG "$TARGET_USER" 2>/dev/null || id -nG)"

    local bin
    bin=$(find_binary)
    if [[ -n "$bin" ]]; then
        echo "Binary Path:  $bin"
        echo "Permissions:  $(ls -l "$bin")"
        echo "Capabilities: $(getcap "$bin" 2>/dev/null || echo "none")"
    else
        echo "Binary Path:  NOT FOUND"
    fi

    echo "/dev/uinput:  $(ls -l /dev/uinput 2>/dev/null || echo "not found")"
    if [[ -e /dev/uinput ]] && command -v getfacl >/dev/null 2>&1; then
        echo "uinput ACL:   $(getfacl -c /dev/uinput 2>/dev/null | tr '\n' ' ')"
    fi
    echo "udev rule:    $(ls -l "$UDEV_RULE_FILE" 2>/dev/null || echo "not present")"
}

# ------------------------------------------------------------------------------
# CLI Router
# ------------------------------------------------------------------------------
case "${1:-status}" in
    apply|setup)
        do_apply
        ;;
    revert|restore|undo)
        do_revert
        ;;
    status|check)
        do_status
        ;;
    *)
        echo "Usage: $0 {apply|revert|status}"
        echo ""
        echo "Commands:"
        echo "  apply   - Configure SetGID 2755, remove user from input, deploy udev rules"
        echo "  revert  - Restore default permissions and remove custom udev rules"
        echo "  status  - Audit current permissions, groups, and device access"
        exit 1
        ;;
esac
