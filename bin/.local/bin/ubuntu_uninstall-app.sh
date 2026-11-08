#!/usr/bin/env bash
#
# ubuntu_uninstall-app.sh — Interactive application uninstaller for Ubuntu
# supporting APT, Snap, and Flatpak with strict system package exclusion,
# immediate orphan dependency/runtime purging, and safe residual data cleanup.
#
# Usage:
#   ubuntu_uninstall-app.sh [KEYWORD] [OPTIONS]
#
# Examples:
#   ubuntu_uninstall-app.sh vlc
#   ubuntu_uninstall-app.sh          # interactively browse all user apps
#   ubuntu_uninstall-app.sh --dry-run discord
#

set -euo pipefail

# ── ANSI Color Palette ────────────────────────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD=$'\033[1m'
  DIM=$'\033[2m'
  RESET=$'\033[0m'
  RED=$'\033[31m'
  GREEN=$'\033[32m'
  YELLOW=$'\033[33m'
  BLUE=$'\033[34m'
  MAGENTA=$'\033[35m'
  CYAN=$'\033[36m'
  WHITE=$'\033[37m'
else
  BOLD=""
  DIM=""
  RESET=""
  RED=""
  GREEN=""
  YELLOW=""
  BLUE=""
  MAGENTA=""
  CYAN=""
  WHITE=""
fi

# ── Logging Helpers ───────────────────────────────────────────────────────────
log_info()    { printf "%s[INFO]%s  %s\n" "$CYAN" "$RESET" "$*"; }
log_success() { printf "%s[OK]%s    %s\n" "$GREEN" "$RESET" "$*"; }
log_warn()    { printf "%s[WARN]%s  %s\n" "$YELLOW" "$RESET" "$*" >&2; }
log_error()   { printf "%s[ERROR]%s %s\n" "$RED" "$RESET" "$*" >&2; }
die()         { log_error "$*"; exit 1; }

# ── CLI Configuration & Options ───────────────────────────────────────────────
KEYWORD=""
DRY_RUN=0
NO_FZF=0
NO_CLEANUP=0

show_help() {
  cat <<EOF
${BOLD}Usage:${RESET} $(basename "$0") [KEYWORD] [OPTIONS]

Interactively search and uninstall applications across APT, Snap, and Flatpak.
Strictly excludes system packages and runtimes, automatically cleans orphaned
dependencies/runtimes, and prompts to safely delete residual data via gio trash.

${BOLD}Arguments:${RESET}
  KEYWORD                       App name or keyword to filter by (optional)

${BOLD}Options:${RESET}
  -d, --dry-run                 Simulate search and show what would be removed
  -n, --no-fzf                  Disable fzf and use numbered terminal menu
      --no-cleanup              Skip scanning/prompting for residual data files
  -h, --help                    Show this help message and exit

${BOLD}Examples:${RESET}
  $(basename "$0") vlc           # Search for VLC across apt, snap, flatpak
  $(basename "$0")               # Interactively browse all installed user apps
  $(basename "$0") --dry-run git # Preview uninstall actions for git
EOF
}

# Parse command line arguments
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)
      show_help
      exit 0
      ;;
    -d|--dry-run)
      DRY_RUN=1
      shift
      ;;
    -n|--no-fzf)
      NO_FZF=1
      shift
      ;;
    --no-cleanup)
      NO_CLEANUP=1
      shift
      ;;
    -*)
      die "Unknown option: $1 (use --help for usage)"
      ;;
    *)
      if [ -z "$KEYWORD" ]; then
        KEYWORD="$1"
      else
        KEYWORD="$KEYWORD $1"
      fi
      shift
      ;;
  esac
done

# ── System Package Exclusion & App Discovery ───────────────────────────────────

# Temporary files for package lists
TMP_DIR="$(mktemp -d -t app-uninstaller.XXXXXX)"
cleanup_tmp() {
  rm -rf "$TMP_DIR"
}
trap cleanup_tmp EXIT

SYS_EXCLUDE_FILE="$TMP_DIR/system_excludes.txt"
USER_APPS_FILE="$TMP_DIR/user_apps.tsv"
touch "$SYS_EXCLUDE_FILE" "$USER_APPS_FILE"

build_apt_system_exclusions() {
  # 1. Base / Essential / Required / Important packages
  dpkg-query -W -f='${Package}\t${Priority}\t${Essential}\t${Section}\n' 2>/dev/null | \
    awk '$2 == "required" || $2 == "important" || $3 == "yes" { print $1 }' >> "$SYS_EXCLUDE_FILE"

  # 2. Automatically installed dependency packages
  if command -v apt-mark >/dev/null 2>&1; then
    apt-mark showauto 2>/dev/null >> "$SYS_EXCLUDE_FILE" || true
  fi

  # 3. Known critical system components & base patterns
  # Filter via regex matching package patterns
  dpkg-query -W -f='${Package}\t${Section}\n' 2>/dev/null | \
    awk -F'\t' '
      $2 ~ /^libs/ || $2 ~ /^kernel/ { print $1; next }
      $1 ~ /^(linux-|grub-|shim-|systemd|udev|lib|gir1\.2-|base-|ubuntu-|ca-certificates|fontconfig|fonts-|tzdata|locales|x11-|xserver-|xorg|gdm|gnome-shell|mutter|polkit|pipewire|wireplumber|alsa-|dbus|wpasupplicant|avahi-|accountsservice|apparmor|apport|anacron|cron|at-spi2|language-pack-|language-selector|nvidia-|printer-driver-|firmware-|amd64-microcode|intel-microcode|software-properties|update-manager|update-notifier|im-config|efibootmgr|snapd|flatpak)/ { print $1; next }
      $1 ~ /-dev$/ { print $1; next }
    ' >> "$SYS_EXCLUDE_FILE"

  sort -u "$SYS_EXCLUDE_FILE" -o "$SYS_EXCLUDE_FILE"
}

collect_apt_apps() {
  command -v dpkg-query >/dev/null 2>&1 || return 0

  # Get list of manually installed packages and packages with desktop launchers
  local manual_pkgs_file="$TMP_DIR/apt_manual.txt"
  local desktop_pkgs_file="$TMP_DIR/apt_desktop.txt"
  touch "$manual_pkgs_file" "$desktop_pkgs_file"

  if command -v apt-mark >/dev/null 2>&1; then
    apt-mark showmanual 2>/dev/null > "$manual_pkgs_file" || true
  fi

  # Packages that provide user desktop launchers
  dpkg -S /usr/share/applications/*.desktop 2>/dev/null | awk -F':' '{print $1}' | sort -u > "$desktop_pkgs_file" || true

  # Merge manual and desktop-providing packages
  local valid_candidates_file="$TMP_DIR/apt_candidates.txt"
  sort -u "$manual_pkgs_file" "$desktop_pkgs_file" > "$valid_candidates_file"

  # Query package details
  dpkg-query -W -f='${Package}\t${Version}\t${binary:Summary}\t${Status}\n' 2>/dev/null | \
    awk -F'\t' -v excludes="$SYS_EXCLUDE_FILE" -v candidates="$valid_candidates_file" '
      BEGIN {
        while ((getline line < excludes) > 0) {
          if (line != "") sys[line] = 1;
        }
        close(excludes);
        while ((getline line < candidates) > 0) {
          if (line != "") cand[line] = 1;
        }
        close(candidates);
      }
      $4 == "install ok installed" {
        pkg = $1
        ver = $2
        desc = $3
        # Must not be an excluded system package
        if (pkg in sys) next;
        # Must be either manually installed or have a desktop launcher
        if (!(pkg in cand)) next;
        # Sanitize summary description
        gsub(/[\r\n\t]+/, " ", desc)
        if (desc == "") desc = "Debian package"
        printf "apt\t%s\t%s\t%s\t%s\n", pkg, pkg, ver, desc
      }
    ' >> "$USER_APPS_FILE"
}

collect_snap_apps() {
  command -v snap >/dev/null 2>&1 || return 0

  local snap_list=""
  snap_list=$(snap list 2>/dev/null || true)
  [ -n "$snap_list" ] || return 0

  echo "$snap_list" | tail -n +2 | while read -r name version rev tracking publisher notes; do
    [ -n "$name" ] || continue

    # Exclude base runtime snaps
    if [[ "${notes:-}" =~ base ]] || [[ "${notes:-}" =~ snapd ]]; then
      continue
    fi

    # Exclude shared runtime and framework snaps
    case "$name" in
      bare|core|core18|core20|core22|core24|core26|snapd)
        continue
        ;;
      gtk-common-themes|gnome-*-*|kf6-*|mesa-*|webkitgtk-*|ffmpeg-*|lxqt-support-*|content-snap-*)
        continue
        ;;
      snapd-desktop-integration|desktop-security-center|firmware-updater|prompting-client|snap-store)
        continue
        ;;
    esac

    printf "snap\t%s\t%s\t%s\tSnap application\n" "$name" "$name" "$version" >> "$USER_APPS_FILE"
  done
}

collect_flatpak_apps() {
  command -v flatpak >/dev/null 2>&1 || return 0

  # flatpak list --app strictly excludes Flatpak system runtimes
  flatpak list --app --columns=name,application,version,description 2>/dev/null | \
    awk -F'\t' '
      NF >= 2 {
        name = $1
        appid = $2
        ver = ($3 != "" ? $3 : "latest")
        desc = ($4 != "" ? $4 : "Flatpak application")
        gsub(/[\r\n\t]+/, " ", desc)
        printf "flatpak\t%s\t%s\t%s\t%s\n", appid, name, ver, desc
      }
    ' >> "$USER_APPS_FILE"
}

# ── Main Collection Flow ──────────────────────────────────────────────────────
log_info "Scanning for installed user applications (excluding system packages)..."
build_apt_system_exclusions
collect_apt_apps
collect_snap_apps
collect_flatpak_apps

# ── Keyword Filtering ─────────────────────────────────────────────────────────
MATCHED_FILE="$TMP_DIR/matched_apps.tsv"
touch "$MATCHED_FILE"

if [ -n "$KEYWORD" ]; then
  awk -F'\t' -v kw="$KEYWORD" '
    BEGIN {
      kw_lower = tolower(kw)
    }
    {
      id_lower = tolower($2)
      name_lower = tolower($3)
      desc_lower = tolower($5)
      if (index(id_lower, kw_lower) > 0 || index(name_lower, kw_lower) > 0 || index(desc_lower, kw_lower) > 0) {
        print $0
      }
    }
  ' "$USER_APPS_FILE" > "$MATCHED_FILE"
else
  cp "$USER_APPS_FILE" "$MATCHED_FILE"
fi

TOTAL_MATCHES=$(wc -l < "$MATCHED_FILE" | tr -d ' ')

if [ "$TOTAL_MATCHES" -eq 0 ]; then
  if [ -n "$KEYWORD" ]; then
    log_warn "No installed user applications found matching keyword: '${KEYWORD}'"
  else
    log_warn "No installed user applications found."
  fi
  exit 0
fi

# ── Interactive Selection ─────────────────────────────────────────────────────
SELECTED_LINE=""

use_fzf() {
  command -v fzf >/dev/null 2>&1 && [ "$NO_FZF" -eq 0 ] && [ -t 0 ] && [ -t 1 ]
}

if use_fzf; then
  # Format entries for fzf display
  # Columns: TYPE | NAME | VERSION | DESCRIPTION
  FZF_INPUT="$TMP_DIR/fzf_input.txt"
  awk -F'\t' '
    {
      badge = sprintf("[%s]", $1)
      printf "%-10s  %-35s  %-15s  %s\t%s\t%s\t%s\t%s\t%s\n", badge, $3, $4, $5, $1, $2, $3, $4, $5
    }
  ' "$MATCHED_FILE" > "$FZF_INPUT"

  SELECTED_RAW=$(fzf \
    --prompt="Select app to uninstall > " \
    --header="ENTER: Select | ESC: Cancel" \
    --height=45% \
    --reverse \
    --cycle \
    --with-nth=1 \
    --delimiter='\t' < "$FZF_INPUT" || true)

  if [ -z "$SELECTED_RAW" ]; then
    log_info "No application selected. Exiting."
    exit 0
  fi

  SELECTED_LINE=$(echo "$SELECTED_RAW" | awk -F'\t' '{printf "%s\t%s\t%s\t%s\t%s", $2, $3, $4, $5, $6}')
else
  # Numbered terminal fallback
  echo ""
  echo "${BOLD}Available Applications:${RESET}"
  echo "──────────────────────────────────────────────────────────────────────────────"
  local_idx=1
  declare -a line_array=()
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    line_array+=("$line")
    ptype=$(echo "$line" | cut -f1)
    pname=$(echo "$line" | cut -f3)
    pver=$(echo "$line" | cut -f4)
    pdesc=$(echo "$line" | cut -f5)
    printf "  %2d) %s[%-7s]%s %s%-30s%s %-12s %s\n" \
      "$local_idx" "$CYAN" "$ptype" "$RESET" "$BOLD" "$pname" "$RESET" "$pver" "$pdesc"
    local_idx=$((local_idx + 1))
  done < "$MATCHED_FILE"
  echo "──────────────────────────────────────────────────────────────────────────────"

  while true; do
    printf "%sSelect package number to uninstall [1-%d] (q to cancel): %s" "$BOLD" "$TOTAL_MATCHES" "$RESET"
    read -r choice
    case "$choice" in
      q|Q|exit|quit)
        log_info "Cancelled by user."
        exit 0
        ;;
      ''|*[!0-9]*)
        echo "Please enter a valid number between 1 and $TOTAL_MATCHES."
        ;;
      *)
        if [ "$choice" -ge 1 ] && [ "$choice" -le "$TOTAL_MATCHES" ]; then
          SELECTED_LINE="${line_array[$((choice - 1))]}"
          break
        else
          echo "Please enter a valid number between 1 and $TOTAL_MATCHES."
        fi
        ;;
    esac
  done
fi

# Extract selected application fields
APP_TYPE=$(echo "$SELECTED_LINE" | cut -f1)
APP_ID=$(echo "$SELECTED_LINE" | cut -f2)
APP_NAME=$(echo "$SELECTED_LINE" | cut -f3)
APP_VERSION=$(echo "$SELECTED_LINE" | cut -f4)
APP_DESC=$(echo "$SELECTED_LINE" | cut -f5)

# ── Confirmation Card ─────────────────────────────────────────────────────────
echo ""
echo "${BOLD}${MAGENTA}Selected Application Details:${RESET}"
printf "  ${BOLD}Type:${RESET}        %s[%s]%s\n" "$CYAN" "$APP_TYPE" "$RESET"
printf "  ${BOLD}Name:${RESET}        %s%s%s\n" "$BOLD" "$APP_NAME" "$RESET"
printf "  ${BOLD}Identifier:${RESET}  %s\n" "$APP_ID"
printf "  ${BOLD}Version:${RESET}     %s\n" "$APP_VERSION"
printf "  ${BOLD}Summary:${RESET}     %s\n" "$APP_DESC"
echo ""

if [ "$DRY_RUN" -eq 1 ]; then
  log_info "[DRY-RUN] Simulating uninstallation for $APP_NAME ($APP_TYPE)."
  log_info "[DRY-RUN] Would execute removal and immediate orphan/runtime cleanup:"
  case "$APP_TYPE" in
    apt)
      echo "  -> sudo apt-get purge -y $APP_ID"
      echo "  -> sudo apt-get autoremove --purge -y"
      ;;
    snap)
      echo "  -> sudo snap remove --purge $APP_ID"
      ;;
    flatpak)
      echo "  -> flatpak uninstall -y $APP_ID"
      echo "  -> flatpak uninstall --unused -y"
      ;;
  esac
else
  printf "%sAre you sure you want to uninstall %s%s (%s)? [y/N]: %s" "$BOLD$RED" "$APP_NAME" "$RESET$BOLD" "$APP_TYPE" "$RESET"
  read -r confirm_uninstall
  case "$confirm_uninstall" in
    y|Y|yes|YES)
      ;;
    *)
      log_info "Uninstallation cancelled."
      exit 0
      ;;
  esac
fi

# ── Step 1: Remove App & Orphaned Dependencies / Runtimes ─────────────────────
if [ "$DRY_RUN" -eq 0 ]; then
  log_info "Uninstalling application and purging orphaned dependencies/runtimes..."
  case "$APP_TYPE" in
    apt)
      log_info "Running: sudo apt-get purge -y $APP_ID"
      sudo apt-get purge -y "$APP_ID"
      log_info "Cleaning orphaned dependencies (sudo apt-get autoremove --purge -y)..."
      sudo apt-get autoremove --purge -y
      ;;
    snap)
      log_info "Running: sudo snap remove --purge $APP_ID"
      sudo snap remove --purge "$APP_ID"
      ;;
    flatpak)
      log_info "Running: flatpak uninstall -y $APP_ID"
      flatpak uninstall -y "$APP_ID"
      log_info "Cleaning unused Flatpak runtimes (flatpak uninstall --unused -y)..."
      flatpak uninstall --unused -y
      ;;
  esac
  log_success "Application and dependencies/runtimes removed successfully."
fi

# ── Step 2: Prompt for Residual Configuration & User Data ─────────────────────
if [ "$NO_CLEANUP" -eq 1 ]; then
  log_info "Skipping residual file cleanup (--no-cleanup flag set)."
  exit 0
fi

echo ""
printf "%sDo you want to scan for and delete remaining configuration files and user data? [y/N]: %s" "$BOLD" "$RESET"
if [ "$DRY_RUN" -eq 1 ]; then
  echo "y (simulated)"
  clean_residual_confirm="y"
else
  read -r clean_residual_confirm
fi

case "$clean_residual_confirm" in
  y|Y|yes|YES)
    ;;
  *)
    log_info "Skipping residual file cleanup. Uninstallation complete."
    exit 0
    ;;
esac

# ── Residual Path Detection ───────────────────────────────────────────────────
# Normalize names for search
APP_NAME_LOWER="$(echo "$APP_NAME" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')"
APP_ID_LOWER="$(echo "$APP_ID" | tr '[:upper:]' '[:lower:]')"

CANDIDATE_PATHS=()

# User paths
CANDIDATE_PATHS+=(
  "$HOME/.config/$APP_NAME"
  "$HOME/.config/$APP_NAME_LOWER"
  "$HOME/.config/$APP_ID"
  "$HOME/.config/$APP_ID_LOWER"
  "$HOME/.cache/$APP_NAME"
  "$HOME/.cache/$APP_NAME_LOWER"
  "$HOME/.cache/$APP_ID"
  "$HOME/.cache/$APP_ID_LOWER"
  "$HOME/.local/share/$APP_NAME"
  "$HOME/.local/share/$APP_NAME_LOWER"
  "$HOME/.local/share/$APP_ID"
  "$HOME/.local/share/$APP_ID_LOWER"
  "$HOME/.local/state/$APP_NAME"
  "$HOME/.local/state/$APP_NAME_LOWER"
  "$HOME/.$APP_NAME"
  "$HOME/.$APP_NAME_LOWER"
)

# Snap-specific paths
if [ "$APP_TYPE" = "snap" ]; then
  CANDIDATE_PATHS+=(
    "$HOME/snap/$APP_ID"
    "$HOME/snap/$APP_NAME_LOWER"
    "/var/snap/$APP_ID"
  )
fi

# Flatpak-specific paths
if [ "$APP_TYPE" = "flatpak" ]; then
  CANDIDATE_PATHS+=(
    "$HOME/.var/app/$APP_ID"
    "$HOME/.local/share/flatpak/app/$APP_ID"
  )
fi

# System paths (for APT)
if [ "$APP_TYPE" = "apt" ]; then
  CANDIDATE_PATHS+=(
    "/etc/$APP_ID"
    "/var/log/$APP_ID"
    "/var/lib/$APP_ID"
  )
fi

# Deduplicate and validate existing paths
FOUND_USER_PATHS=()
FOUND_SYSTEM_PATHS=()
declare -A SEEN_PATHS

for p in "${CANDIDATE_PATHS[@]}"; do
  # Avoid dangerous root or home directory matches
  [ -n "$p" ] || continue
  [ "$p" != "$HOME" ] || continue
  [ "$p" != "/" ] || continue
  [ "$p" != "/etc" ] || continue
  [ "$p" != "/var" ] || continue
  [ "$p" != "/usr" ] || continue

  if [ -e "$p" ] && [ -z "${SEEN_PATHS[$p]:-}" ]; then
    SEEN_PATHS["$p"]=1
    if [[ "$p" == "$HOME"* ]]; then
      FOUND_USER_PATHS+=("$p")
    else
      FOUND_SYSTEM_PATHS+=("$p")
    fi
  fi
done

TOTAL_FOUND=$(( ${#FOUND_USER_PATHS[@]} + ${#FOUND_SYSTEM_PATHS[@]} ))

if [ "$TOTAL_FOUND" -eq 0 ]; then
  log_info "No residual configuration files or user data found."
  log_success "Uninstallation complete."
  exit 0
fi

echo ""
echo "${BOLD}Found Residual Configuration / Data Files:${RESET}"
echo "──────────────────────────────────────────────────────────────────────────────"
for p in "${FOUND_USER_PATHS[@]}"; do
  sz=$(du -sh "$p" 2>/dev/null | awk '{print $1}' || echo "unknown")
  printf "  %s[USER - gio trash]%s %-10s %s\n" "$GREEN" "$RESET" "($sz)" "$p"
done
for p in "${FOUND_SYSTEM_PATHS[@]}"; do
  sz=$(du -sh "$p" 2>/dev/null | awk '{print $1}' || echo "unknown")
  printf "  %s[SYS - sudo rm]%s   %-10s %s\n" "$RED" "$RESET" "($sz)" "$p"
done
echo "──────────────────────────────────────────────────────────────────────────────"

if [ "$DRY_RUN" -eq 1 ]; then
  log_info "[DRY-RUN] Would remove the above $TOTAL_FOUND path(s)."
  log_success "[DRY-RUN] Finished simulation."
  exit 0
fi

printf "%sConfirm deletion of these residual data files? [y/N]: %s" "$BOLD$RED" "$RESET"
read -r confirm_delete

case "$confirm_delete" in
  y|Y|yes|YES)
    ;;
  *)
    log_info "Residual file cleanup cancelled. Application uninstallation is complete."
    exit 0
    ;;
esac

# Safe deletion of user paths via gio trash
if [ ${#FOUND_USER_PATHS[@]} -gt 0 ]; then
  if command -v gio >/dev/null 2>&1; then
    for p in "${FOUND_USER_PATHS[@]}"; do
      if gio trash "$p" 2>/dev/null; then
        log_success "Moved to system trash: $p"
      else
        log_warn "gio trash failed on '$p', skipping permanent deletion."
      fi
    done
  else
    log_warn "gio trash not found; moving files to trash is unavailable. Skipping user paths."
  fi
fi

# Deletion of system paths via sudo rm -rf
if [ ${#FOUND_SYSTEM_PATHS[@]} -gt 0 ]; then
  for p in "${FOUND_SYSTEM_PATHS[@]}"; do
    log_info "Removing system path: $p"
    sudo rm -rf "$p"
    log_success "Removed: $p"
  done
fi

log_success "All residual files cleaned. Uninstallation finished successfully."
