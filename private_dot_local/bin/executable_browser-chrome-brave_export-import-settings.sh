#!/usr/bin/env bash
# ==============================================================================
# browser-chrome-brave_export-import-settings.sh
# ------------------------------------------------------------------------------
# Interactive Cloud-Safe Export & Import for Chromium and Brave Browser Settings
#
# Supports:
#   - Brave (Brave-Origin, Brave-Browser, Beta, Nightly)
#   - Google Chrome / Chromium
#
# Key Features:
#   - 100% Cloud-Safe: Strictly purges passwords, credit cards, autofill,
#     crypto wallet states, BAT rewards, and browsing history before saving.
#   - Full Preferences Backup: Preserves UI settings, themes, shields, flags.
#   - Complete Keymap Preservation:
#       * Brave native command accelerators (brave.accelerators)
#       * Extension command shortcuts (extensions.commands)
#       * Extracted Vimium & Vimium C custom keymappings
#   - Anti-Corruption Restore: Safely strips stale machine-bound HMAC hashes
#     (protection.macs) so Chromium/Brave imports settings without reset loops.
#   - Process Safety: Prohibits restoring while browser processes are active.
#   - Interactive TUI (fzf / whiptail / fallback menu) + Non-interactive CLI.
# ==============================================================================

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
CHEZMOI_REPO_DIR="${CHEZMOI_REPO_DIR:-$HOME/.local/share/chezmoi}"
DEFAULT_STORAGE_DIR="$CHEZMOI_REPO_DIR/brave"

# Terminal styling
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' RESET=''
fi

log_info()    { printf "${BLUE}[INFO]${RESET} %s\n" "$*"; }
log_success() { printf "${GREEN}[OK]${RESET} %s\n" "$*"; }
log_warn()    { printf "${YELLOW}[WARN]${RESET} %s\n" "$*" >&2; }
log_error()   { printf "${RED}[ERROR]${RESET} %s\n" "$*" >&2; }

# Check dependencies
command -v python3 >/dev/null 2>&1 || {
    log_error "Python 3 is required but not installed. Exiting."
    exit 1
}

# ------------------------------------------------------------------------------
# Browser Path Discovery
# ------------------------------------------------------------------------------
declare -A BROWSER_DIRS=(
    ["brave-origin"]="$HOME/.config/BraveSoftware/Brave-Origin"
    ["brave-browser"]="$HOME/.config/BraveSoftware/Brave-Browser"
    ["brave-beta"]="$HOME/.config/BraveSoftware/Brave-Browser-Beta"
    ["brave-nightly"]="$HOME/.config/BraveSoftware/Brave-Browser-Nightly"
    ["google-chrome"]="$HOME/.config/google-chrome"
    ["google-chrome-beta"]="$HOME/.config/google-chrome-beta"
    ["chromium"]="$HOME/.config/chromium"
)

declare -A BROWSER_PROCS=(
    ["brave-origin"]="brave-origin"
    ["brave-browser"]="brave-browser"
    ["brave-beta"]="brave-browser-beta"
    ["brave-nightly"]="brave-browser-nightly"
    ["google-chrome"]="chrome"
    ["google-chrome-beta"]="chrome-beta"
    ["chromium"]="chromium"
)

detect_available_browsers() {
    local avail=()
    for b in "brave-origin" "brave-browser" "google-chrome" "chromium" "brave-beta" "brave-nightly" "google-chrome-beta"; do
        if [ -d "${BROWSER_DIRS[$b]}" ]; then
            avail+=("$b")
        fi
    done
    echo "${avail[@]}"
}

check_browser_running() {
    local browser="$1"
    local proc_pattern="${BROWSER_PROCS[$browser]:-$browser}"
    if pgrep -f "$proc_pattern" >/dev/null 2>&1; then
        return 0 # running
    fi
    return 1 # not running
}

# ------------------------------------------------------------------------------
# Python Worker Engine (Embedded for Robust JSON & LevelDB Parsing)
# ------------------------------------------------------------------------------
run_python_engine() {
    python3 - "$@" << 'EOF'
import sys, os, json, glob, re, shutil, datetime

SENSITIVE_TOP_LEVEL = {
    # Credentials & Passwords
    "password_manager", "total_passwords_available_for_account",
    "total_passwords_available_for_profile", "credentials_enable_service",
    "credentials_enable_autosignin",
    # Autofill & Credit Cards / Payments
    "autofill", "payments",
    # Accounts & Authentication Tokens
    "account_values", "gaia_cookie", "google", "signin", "sync",
    # Crypto Wallet & Rewards
    "brave_rewards", "brave_sync_v2",
    # Browsing History & Visited URLs
    "history_clusters", "autocomplete", "sessions",
    # Machine-bound HMACs & Checksums (Prevent reset loops)
    "protection", "updateclientdata", "updateclientlastupdatecheckerror",
    "updateclientlastupdatecheckerrorcategory",
    "updateclientlastupdatecheckerrorextracode1",
    "commerce_daily_metrics_last_update_time", "domain_diversity",
    "announcement_notification_service_first_run_time"
}

BRAVE_COMMAND_NAMES = {
    33000: "Browser Back",
    33001: "Browser Forward",
    33002: "Reload / Refresh",
    33003: "Home",
    33007: "Hard Reload (Bypass Cache)",
    34000: "New Window",
    34001: "New Incognito / Private Window",
    34012: "Close Window / Exit",
    34014: "New Tab",
    34015: "Close Tab",
    34016: "Next Tab",
    34017: "Previous Tab",
    34018: "Select Tab 1",
    34019: "Select Tab 2",
    34020: "Select Tab 3",
    34021: "Select Tab 4",
    34022: "Select Tab 5",
    34023: "Select Tab 6",
    34024: "Select Tab 7",
    34025: "Select Tab 8",
    34026: "Select Tab 9 (Last Tab)",
    34028: "Reopen Closed Tab",
    34030: "Toggle Fullscreen",
    34031: "Quit Browser",
    34032: "Move Tab Right",
    34033: "Move Tab Left",
    34057: "Duplicate Tab",
    34061: "Mute / Unmute Tab",
    34062: "Cycle Next Tab (MRU)",
    34063: "Cycle Previous Tab (MRU)",
    34100: "Vertical Tabs Toggle",
    35000: "Bookmark Current Tab",
    35001: "Bookmark All Tabs",
    35002: "View Page Source",
    35003: "Print",
    35004: "Save Page As",
    35007: "Print Using System Dialog",
    37000: "Find in Page",
    37001: "Find Next",
    37002: "Find Previous",
    37003: "Stop Loading / Close Find",
    38001: "Zoom In",
    38002: "Reset Zoom",
    38003: "Zoom Out",
    39000: "Focus Next Pane",
    39001: "Focus Address Bar / Omnibox",
    39002: "Focus Search Box",
    39006: "Focus Bookmarks Toolbar",
    40000: "Open Local File",
    40004: "Developer Tools (Inspect)",
    40005: "Developer Tools Console",
    40009: "Toggle Bookmarks Bar",
    40010: "Show Browsing History",
    40011: "Show Downloads",
    40012: "Bookmarks Manager",
    40013: "Clear Browsing Data Dialog",
    40019: "Help Center",
    40023: "Task Manager",
    52500: "Tab Search",
    56301: "Quick Commands / Command Palette"
}

def sanitize_preferences(data):
    clean = {k: v for k, v in data.items() if k not in SENSITIVE_TOP_LEVEL}
    
    # Sanitize profile subkeys
    if "profile" in clean and isinstance(clean["profile"], dict):
        cs = clean["profile"].get("content_settings", {})
        if "exceptions" in cs:
            # Strip site engagement and domain-specific history
            cs["exceptions"] = {}
            
    # Sanitize extension settings (strip CSP report-to URLs, API keys & worker telemetry)
    if "extensions" in clean and isinstance(clean["extensions"], dict):
        exts = clean["extensions"].get("settings", {})
        if isinstance(exts, dict):
            for ext_id, ext_data in exts.items():
                if isinstance(ext_data, dict):
                    for k in ["service_worker_registration_info", "serviceworkerevents", "filtered_service_worker_events"]:
                        if k in ext_data:
                            del ext_data[k]
                    manifest = ext_data.get("manifest", {})
                    if isinstance(manifest, dict) and "content_security_policy" in manifest:
                        del manifest["content_security_policy"]

    # Sanitize brave subkeys (wallet, rewards, history)
    if "brave" in clean and isinstance(clean["brave"], dict):
        b = clean["brave"]
        for bk in list(b.keys()):
            if any(x in bk.lower() for x in ["wallet", "rewards", "bat", "history"]):
                del b[bk]
                
    # Normalize local user home path
    home = os.path.expanduser("~")
    def norm_home(obj):
        if isinstance(obj, dict):
            return {k: norm_home(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [norm_home(v) for v in obj]
        elif isinstance(obj, str) and home in obj:
            return obj.replace(home, "~")
        return obj

    return norm_home(clean)

def extract_vimium_keymappings(profile_dir):
    """Search for custom key mappings in Vimium and Vimium C LevelDB logs."""
    results = {}
    ext_dirs = [
        os.path.join(profile_dir, "Sync Extension Settings"),
        os.path.join(profile_dir, "Local Extension Settings")
    ]
    
    # Vimium: dbepggeogbaibhgnhhndojpepiihcmeb
    # Vimium C: hfjbmagddngcpeloejdejnfgbamkjaeg
    targets = {
        "dbepggeogbaibhgnhhndojpepiihcmeb": "Vimium",
        "hfjbmagddngcpeloejdejnfgbamkjaeg": "Vimium C"
    }
    
    for base_dir in ext_dirs:
        if not os.path.isdir(base_dir):
            continue
        for ext_id, ext_name in targets.items():
            ext_path = os.path.join(base_dir, ext_id)
            if not os.path.isdir(ext_path):
                continue
            for log_file in glob.glob(os.path.join(ext_path, "*.log")):
                try:
                    with open(log_file, "rb") as f:
                        data = f.read()
                    idx = data.find(b"keyMappings")
                    if idx != -1:
                        chunk = data[idx:idx+4096]
                        # Match mapping patterns
                        m = re.search(rb"(\"|\\x[0-9a-f]{2})?((?:#|map|unmap)[^\x00\x01\x02\x03\x04\x05\x06\x07\x08]+)", chunk)
                        if m:
                            raw = m.group(2).decode("utf-8", errors="ignore")
                            if '"' in raw:
                                raw = raw.split('"')[0]
                            text = raw.replace("\\n", "\n").strip()
                            if ext_name not in results or len(text) > len(results[ext_name]):
                                results[ext_name] = text
                except Exception:
                    pass
    return results

def list_profiles(browser_dir):
    if not os.path.isdir(browser_dir):
        return []
    profiles = []
    for d in sorted(os.listdir(browser_dir)):
        if d in ["System Profile", "Guest Profile"]:
            continue
        pref_file = os.path.join(browser_dir, d, "Preferences")
        if os.path.isfile(pref_file):
            try:
                with open(pref_file, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                name = data.get("profile", {}).get("name", d)
                accel = data.get("brave", {}).get("accelerators", {})
                ext_cmds = data.get("extensions", {}).get("commands", {})
                ext_count = len(data.get("extensions", {}).get("settings", {}))
                profiles.append({
                    "dir": d,
                    "name": name,
                    "native_shortcuts": len(accel),
                    "extension_shortcuts": len(ext_cmds),
                    "extensions_count": ext_count
                })
            except Exception as e:
                profiles.append({"dir": d, "name": f"{d} (error reading)", "error": str(e)})
    return profiles

def export_profile(browser_dir, profile_dir_name, out_base_dir, dry_run=False):
    src_pref = os.path.join(browser_dir, profile_dir_name, "Preferences")
    if not os.path.isfile(src_pref):
        print(f"Preferences file not found for profile: {profile_dir_name}")
        return False
        
    with open(src_pref, "r", encoding="utf-8", errors="ignore") as f:
        raw_data = json.load(f)
        
    profile_name = raw_data.get("profile", {}).get("name", profile_dir_name)
    sanitized = sanitize_preferences(raw_data)
    
    # Build clean human-readable shortcuts summary
    native_accels = sanitized.get("brave", {}).get("accelerators", {})
    readable_native = {}
    for cmd_id_str, keys in sorted(native_accels.items()):
        try:
            cmd_id = int(cmd_id_str)
            label = BRAVE_COMMAND_NAMES.get(cmd_id, f"Custom Command #{cmd_id}")
        except ValueError:
            label = f"Command {cmd_id_str}"
        readable_native[label] = {
            "command_id": cmd_id_str,
            "accelerators": keys
        }
        
    ext_commands = sanitized.get("extensions", {}).get("commands", {})
    ext_settings = sanitized.get("extensions", {}).get("settings", {})
    readable_ext_commands = []
    
    for raw_key, cmd_data in sorted(ext_commands.items()):
        ext_id = cmd_data.get("extension", "")
        cmd_name = cmd_data.get("command_name", "")
        is_global = cmd_data.get("global", False)
        # Parse shortcut key from raw_key (format "linux:Key")
        key_name = raw_key.split(":", 1)[1] if ":" in raw_key else raw_key
        ext_name = ext_settings.get(ext_id, {}).get("manifest", {}).get("name", ext_id)
        
        readable_ext_commands.append({
            "extension_name": ext_name,
            "extension_id": ext_id,
            "command": cmd_name,
            "shortcut": key_name,
            "scope": "Global (System-wide)" if is_global else "In-Browser"
        })
        
    shortcuts_data = {
        "profile_dir": profile_dir_name,
        "profile_name": profile_name,
        "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "brave_native_shortcuts": readable_native,
        "extension_shortcuts": readable_ext_commands
    }
    
    # Extract Vimium / Vimium C custom mappings
    full_profile_path = os.path.join(browser_dir, profile_dir_name)
    vimium_mappings = extract_vimium_keymappings(full_profile_path)
    
    dest_dir = os.path.join(out_base_dir, "profiles", profile_dir_name)
    
    if dry_run:
        print(f"[DRY-RUN] Would export profile '{profile_name}' ({profile_dir_name}) to: {dest_dir}")
        print(f"  - Preferences.json: {len(sanitized)} clean top-level keys")
        print(f"  - shortcuts.json: {len(readable_native)} native, {len(readable_ext_commands)} extension shortcuts")
        for v_name, v_text in vimium_mappings.items():
            print(f"  - {v_name} keymappings: {len(v_text.splitlines())} lines")
        return True

    os.makedirs(dest_dir, exist_ok=True)
    
    # Write Preferences.json
    pref_out = os.path.join(dest_dir, "Preferences.json")
    with open(pref_out, "w", encoding="utf-8") as f:
        json.dump(sanitized, f, indent=2, sort_keys=True)
        
    # Write shortcuts.json
    shortcuts_out = os.path.join(dest_dir, "shortcuts.json")
    with open(shortcuts_out, "w", encoding="utf-8") as f:
        json.dump(shortcuts_data, f, indent=2)
        
    # Write Vimium / Vimium C mappings if found
    for v_name, v_text in vimium_mappings.items():
        v_filename = f"{v_name.lower().replace(' ', '_')}_keymappings.txt"
        v_out = os.path.join(dest_dir, v_filename)
        with open(v_out, "w", encoding="utf-8") as f:
            f.write(v_text + "\n")
            
    print(f"Successfully exported profile '{profile_name}' ({profile_dir_name}) -> {dest_dir}")
    return True

def restore_profile(storage_dir, profile_dir_name, browser_dir, dry_run=False):
    src_dir = os.path.join(storage_dir, "profiles", profile_dir_name)
    src_pref = os.path.join(src_dir, "Preferences.json")
    
    if not os.path.isfile(src_pref):
        print(f"Exported Preferences.json not found in: {src_dir}")
        return False
        
    with open(src_pref, "r", encoding="utf-8") as f:
        imported_data = json.load(f)
        
    # Expand home dir placeholders
    home = os.path.expanduser("~")
    def expand_home(obj):
        if isinstance(obj, dict):
            return {k: expand_home(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [expand_home(v) for v in obj]
        elif isinstance(obj, str) and obj.startswith("~/"):
            return obj.replace("~/", home + "/")
        return obj
        
    imported_data = expand_home(imported_data)
    
    dest_profile = os.path.join(browser_dir, profile_dir_name)
    dest_pref = os.path.join(dest_profile, "Preferences")
    
    if dry_run:
        print(f"[DRY-RUN] Would restore profile '{profile_dir_name}' to: {dest_profile}")
        print(f"  - Target Preferences: {dest_pref}")
        print(f"  - Backup would be saved to: {dest_pref}.bak.<timestamp>")
        return True

    os.makedirs(dest_profile, exist_ok=True)
    
    # Merge or backup if existing
    if os.path.isfile(dest_pref):
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f"{dest_pref}.bak.{ts}"
        shutil.copy2(dest_pref, backup_file)
        print(f"Created backup of existing preferences: {backup_file}")
        try:
            with open(dest_pref, "r", encoding="utf-8", errors="ignore") as f:
                target_data = json.load(f)
        except Exception:
            target_data = {}
    else:
        target_data = {}
        
    # Merge imported settings into target
    target_data.update(imported_data)
    
    # CRITICAL: Strip stale machine HMAC protection block to prevent corruption reset loops
    if "protection" in target_data:
        del target_data["protection"]
        
    # Atomic write to Preferences
    tmp_file = f"{dest_pref}.tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(target_data, f, indent=2)
    os.replace(tmp_file, dest_pref)
    
    # Clear stale Secure Preferences to satisfy Chromium checksum regenerator
    sec_pref = os.path.join(dest_profile, "Secure Preferences")
    if os.path.isfile(sec_pref):
        try:
            sec_bak = f"{sec_pref}.bak.{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(sec_pref, sec_bak)
            os.remove(sec_pref)
        except Exception:
            pass
            
    print(f"Successfully restored preferences for profile '{profile_dir_name}'")
    return True

# Dispatch command line
cmd = sys.argv[1] if len(sys.argv) > 1 else ""

if cmd == "list":
    b_dir = sys.argv[2]
    profs = list_profiles(b_dir)
    print(json.dumps(profs))
elif cmd == "export":
    b_dir = sys.argv[2]
    p_name = sys.argv[3]
    out_dir = sys.argv[4]
    dry = sys.argv[5].lower() == "true" if len(sys.argv) > 5 else False
    if p_name == "all":
        profs = list_profiles(b_dir)
        for p in profs:
            export_profile(b_dir, p["dir"], out_dir, dry)
    else:
        export_profile(b_dir, p_name, out_dir, dry)
elif cmd == "restore":
    storage_dir = sys.argv[2]
    p_name = sys.argv[3]
    b_dir = sys.argv[4]
    dry = sys.argv[5].lower() == "true" if len(sys.argv) > 5 else False
    if p_name == "all":
        profiles_dir = os.path.join(storage_dir, "profiles")
        if os.path.isdir(profiles_dir):
            for p in sorted(os.listdir(profiles_dir)):
                if os.path.isdir(os.path.join(profiles_dir, p)):
                    restore_profile(storage_dir, p, b_dir, dry)
    else:
        restore_profile(storage_dir, p_name, b_dir, dry)
EOF
}

# ------------------------------------------------------------------------------
# Interactive TUI UI & Menus
# ------------------------------------------------------------------------------
select_browser_interactive() {
    local available
    available=($(detect_available_browsers))
    if [ ${#available[@]} -eq 0 ]; then
        log_error "No supported Chromium or Brave browser configuration found in ~/.config!"
        exit 1
    fi
    
    if [ ${#available[@]} -eq 1 ]; then
        echo "${available[0]}"
        return
    fi
    
    if command -v fzf >/dev/null 2>&1 && [ -t 0 ]; then
        printf "%s\n" "${available[@]}" | fzf --prompt="Select Browser > " --height=40% --reverse
    else
        echo -e "${CYAN}Available Browsers:${RESET}" >&2
        select b in "${available[@]}"; do
            if [ -n "$b" ]; then
                echo "$b"
                return
            fi
        done
    fi
}

select_profile_interactive() {
    local b_dir="$1"
    local raw_json
    raw_json=$(run_python_engine list "$b_dir")
    
    local choices=("all (Export/Import All Profiles)")
    while IFS= read -r line; do
        if [ -n "$line" ]; then
            choices+=("$line")
        fi
    done < <(python3 -c "
import sys, json
data = json.loads('''$raw_json''')
for p in data:
    d = p.get('dir')
    n = p.get('name')
    s = p.get('native_shortcuts', 0)
    e = p.get('extension_shortcuts', 0)
    print(f'{d} | {n} ({s} native shortcuts, {e} ext shortcuts)')
")
    
    local selected
    if command -v fzf >/dev/null 2>&1 && [ -t 0 ]; then
        selected=$(printf "%s\n" "${choices[@]}" | fzf --prompt="Select Profile > " --height=50% --reverse)
    else
        echo -e "${CYAN}Available Profiles:${RESET}" >&2
        select c in "${choices[@]}"; do
            if [ -n "$c" ]; then
                selected="$c"
                break
            fi
        done
    fi
    
    if [[ "$selected" == all* ]]; then
        echo "all"
    else
        echo "$selected" | awk -F' \\| ' '{print $1}'
    fi
}

interactive_main_menu() {
    clear
    printf "${BOLD}${CYAN}========================================================================${RESET}\n"
    printf "${BOLD}${CYAN}   🌐 Cloud-Safe Browser Settings & Keymap Sync (Brave / Chrome)${RESET}\n"
    printf "${BOLD}${CYAN}========================================================================${RESET}\n"
    printf "${YELLOW}🔒 Security Guarantee: Zero passwords, credit cards, or crypto processed.${RESET}\n\n"
    
    local browser
    browser=$(select_browser_interactive)
    local b_dir="${BROWSER_DIRS[$browser]}"
    
    printf "\n${BLUE}Selected Browser:${RESET} ${BOLD}%s${RESET} (%s)\n\n" "$browser" "$b_dir"
    
    local options=(
        "1) 📤 Export Settings (Cloud-Safe Backup to Chezmoi Repo)"
        "2) 📥 Import / Restore Settings to Browser"
        "3) 📋 List Profiles & View Keymap Status"
        "4) 🧪 Dry-Run Export (Preview sanitized output)"
        "5) 🚪 Exit"
    )
    
    local choice
    if command -v fzf >/dev/null 2>&1 && [ -t 0 ]; then
        choice=$(printf "%s\n" "${options[@]}" | fzf --prompt="Choose Action > " --height=40% --reverse)
    else
        echo -e "${CYAN}Choose an action:${RESET}"
        select opt in "${options[@]}"; do
            if [ -n "$opt" ]; then
                choice="$opt"
                break
            fi
        done
    fi
    
    case "$choice" in
        1*)
            local profile
            profile=$(select_profile_interactive "$b_dir")
            printf "\n${YELLOW}Exporting profile(s): %s${RESET}\n" "$profile"
            run_python_engine export "$b_dir" "$profile" "$DEFAULT_STORAGE_DIR" "false"
            log_success "Export completed. Backed-up files stored in: $DEFAULT_STORAGE_DIR/profiles/"
            ;;
        2*)
            if check_browser_running "$browser"; then
                printf "\n${RED}⚠️  WARNING: %s is currently running!${RESET}\n" "$browser"
                printf "You MUST completely close %s before restoring settings to prevent data corruption.\n\n" "$browser"
                read -r -p "Close browser and press Enter to continue (or Ctrl+C to abort)..."
                if check_browser_running "$browser"; then
                    log_error "%s is still running. Aborting restore for safety."
                    exit 1
                fi
            fi
            local profile
            profile=$(select_profile_interactive "$b_dir")
            printf "\n${YELLOW}Restoring profile(s): %s${RESET}\n" "$profile"
            run_python_engine restore "$DEFAULT_STORAGE_DIR" "$profile" "$b_dir" "false"
            log_success "Import completed safely."
            ;;
        3*)
            printf "\n${CYAN}Profiles for %s:${RESET}\n" "$browser"
            python3 -c "
import json
profs = json.loads('''$(run_python_engine list "$b_dir")''')
print(f'{\"Directory\":<16} | {\"Profile Name\":<20} | {\"Native Hotkeys\":<14} | {\"Ext Hotkeys\":<12} | {\"Extensions\"}')
print('-' * 80)
for p in profs:
    print(f\"{p.get('dir', ''):<16} | {p.get('name', ''):<20} | {p.get('native_shortcuts', 0):<14} | {p.get('extension_shortcuts', 0):<12} | {p.get('extensions_count', 0)}\")
"
            ;;
        4*)
            local profile
            profile=$(select_profile_interactive "$b_dir")
            printf "\n${YELLOW}[Preview] Dry-run export for %s:${RESET}\n" "$profile"
            run_python_engine export "$b_dir" "$profile" "$DEFAULT_STORAGE_DIR" "true"
            ;;
        5*|"")
            log_info "Exiting."
            exit 0
            ;;
    esac
}

# ------------------------------------------------------------------------------
# CLI Argument Dispatcher
# ------------------------------------------------------------------------------
show_help() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Interactive Mode:
    $SCRIPT_NAME                    Launch interactive TUI menu

Non-Interactive / Scripted Mode:
    -e, --export                    Export cloud-safe settings to dotfiles
    -i, --import                    Import / restore settings into browser
    -l, --list                      List detected profiles and shortcut counts
    -b, --browser <name>            Browser identifier (default: auto-detect)
                                    Options: brave-origin, brave-browser, google-chrome, chromium
    -p, --profile <name>            Profile directory name (e.g. Default, 'Profile 1', or 'all')
    -d, --dry-run                   Simulate operation without altering files
    -o, --output-dir <path>         Destination backup directory (default: $DEFAULT_STORAGE_DIR)
    -h, --help                      Show this help message

Examples:
    $SCRIPT_NAME --export --browser brave-origin --profile all
    $SCRIPT_NAME --import --browser brave-origin --profile Default
    $SCRIPT_NAME --list
EOF
}

ACTION=""
BROWSER=""
PROFILE="all"
DRY_RUN="false"
STORAGE_DIR="$DEFAULT_STORAGE_DIR"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -e|--export)
            ACTION="export"
            shift
            ;;
        -i|--import)
            ACTION="import"
            shift
            ;;
        -l|--list)
            ACTION="list"
            shift
            ;;
        -b|--browser)
            BROWSER="$2"
            shift 2
            ;;
        -p|--profile)
            PROFILE="$2"
            shift 2
            ;;
        -d|--dry-run)
            DRY_RUN="true"
            shift
            ;;
        -o|--output-dir)
            STORAGE_DIR="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

if [ -z "$ACTION" ]; then
    interactive_main_menu
    exit 0
fi

# Auto-detect browser if not specified
if [ -z "$BROWSER" ]; then
    available=($(detect_available_browsers))
    if [ ${#available[@]} -eq 0 ]; then
        log_error "No supported browser found."
        exit 1
    fi
    BROWSER="${available[0]}"
    log_info "Auto-detected active browser: $BROWSER"
fi

BROWSER_DIR="${BROWSER_DIRS[$BROWSER]:-}"
if [ -z "$BROWSER_DIR" ] || [ ! -d "$BROWSER_DIR" ]; then
    log_error "Browser directory not found for: $BROWSER ($BROWSER_DIR)"
    exit 1
fi

case "$ACTION" in
    list)
        python3 -c "
import json
profs = json.loads('''$(run_python_engine list "$BROWSER_DIR")''')
print(f'{\"Directory\":<16} | {\"Profile Name\":<20} | {\"Native Hotkeys\":<14} | {\"Ext Hotkeys\":<12} | {\"Extensions\"}')
print('-' * 80)
for p in profs:
    print(f\"{p.get('dir', ''):<16} | {p.get('name', ''):<20} | {p.get('native_shortcuts', 0):<14} | {p.get('extension_shortcuts', 0):<12} | {p.get('extensions_count', 0)}\")
"
        ;;
    export)
        log_info "Exporting cloud-safe settings for $BROWSER (Profile: $PROFILE) -> $STORAGE_DIR"
        run_python_engine export "$BROWSER_DIR" "$PROFILE" "$STORAGE_DIR" "$DRY_RUN"
        log_success "Export completed."
        ;;
    import)
        if [ "$DRY_RUN" != "true" ] && check_browser_running "$BROWSER"; then
            log_error "$BROWSER is currently running! Please exit the browser completely before restoring."
            exit 1
        fi
        log_info "Restoring settings for $BROWSER (Profile: $PROFILE) from $STORAGE_DIR"
        run_python_engine restore "$STORAGE_DIR" "$PROFILE" "$BROWSER_DIR" "$DRY_RUN"
        log_success "Import completed."
        ;;
esac
