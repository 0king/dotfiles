#!/usr/bin/env bash
#
# vscode-projects.sh — List every VS Code / VS Code Insiders / VSCodium
# project (recent + full history) across all installs on this machine.
#
# The script now defaults to interactive mode. 
# Use --list or -l for the original non-interactive output.
#
# Background you should know before reading the output:
#   - VS Code "Profiles" (the Settings/Extensions profile switcher) do NOT
#     keep separate recent-project lists. That history lives at the
#     install level and is shared by every profile. This script lists
#     the profiles it finds for context, then prints the one shared
#     project list underneath.
#   - As of VS Code 1.118 (Apr 2026), the recent-items list moved out of
#     the per-install "globalStorage/state.vscdb" into a new shared file
#     outside the config dir (so it can be shared with other MS apps).
#     This script checks BOTH the new and the old location.
#   - It also scans "workspaceStorage", which holds an entry for every
#     project VS Code has ever opened (not just the capped recent list),
#     so deleted/older projects still show up here.
#
# Requires: jq, sqlite3 (both installable via: sudo apt install jq sqlite3)

set -uo pipefail

# ── ANSI palette ──────────────────────────────────────────────────────────
readonly RED=$'\033[31m'
readonly GREEN=$'\033[32m'
readonly CYAN=$'\033[36m'
readonly BOLD=$'\033[1m'
readonly DIM=$'\033[2m'
readonly RESET=$'\033[0m'

for c in jq sqlite3; do
  command -v "$c" >/dev/null 2>&1 || {
    echo "Missing '$c'. Install with: sudo apt install jq sqlite3" >&2
    exit 1
  }
done

# Decode a file:// URI into a plain path (pure bash, no python needed).
urldecode() {
  local s="${1//+/ }"
  printf '%b' "${s//%/\\x}"
}

to_path() {
  local uri="$1"
  case "$uri" in
    file://*) printf '%s\n' "$(urldecode "${uri#file://}")" ;;
    *)        printf '[remote] %s\n' "$uri" ;;
  esac
}

# Shorten $HOME-prefixed paths to ~ for readability.
shorten_path() {
  local p="$1"
  p="${p#"$HOME"}"
  if [ "${p:0:1}" = "/" ] || [ -z "$p" ]; then
    printf '~%s' "$p"
  else
    printf '%s' "$p"
  fi
}

# Pull the recent-items list out of a state.vscdb, old or new location.
recent_from_db() {
  local db="$1"
  [ -f "$db" ] || return 0
  sqlite3 -readonly "$db" \
    "SELECT value FROM ItemTable WHERE key='history.recentlyOpenedPathsList';" 2>/dev/null |
    jq -r '.entries[]? | (.folderUri // .workspace.configPath // empty)' 2>/dev/null
}

# Pull every project VS Code has ever created workspace state for.
workspaces_from_storage() {
  local wsdir="$1"
  [ -d "$wsdir" ] || return 0
  find "$wsdir" -maxdepth 2 -name workspace.json -print0 2>/dev/null |
    while IFS= read -r -d '' f; do
      jq -r '.folder // .configuration // .workspace // empty' "$f" 2>/dev/null
    done
}

# name | candidate config dirs (colon-separated) | shared-storage folder name
VARIANTS=(
  "VS Code|$HOME/.config/Code:$HOME/snap/code/current/.config/Code:$HOME/.var/app/com.visualstudio.code/config/Code|.vscode-shared"
  "VS Code Insiders|$HOME/.config/Code - Insiders:$HOME/snap/code-insiders/current/.config/Code - Insiders|.vscode-insiders-shared"
  "VSCodium|$HOME/.config/VSCodium:$HOME/.var/app/com.vscodium.codium/config/VSCodium|.vscode-oss-shared"
)

collect_projects() {
  for entry in "${VARIANTS[@]}"; do
    IFS='|' read -r name cfgdirs shareddir <<< "$entry"
    IFS=':' read -ra CFGDIRS <<< "$cfgdirs"

    found_cfg=""
    for d in "${CFGDIRS[@]}"; do
      [ -d "$d/User" ] && { found_cfg="$d"; break; }
    done
    [ -n "$found_cfg" ] || continue

    {
      recent_from_db "$HOME/$shareddir/sharedStorage/state.vscdb"
      recent_from_db "$found_cfg/User/globalStorage/state.vscdb"
      workspaces_from_storage "$found_cfg/User/workspaceStorage"
    } | while IFS= read -r uri; do
        [ -n "$uri" ] && to_path "$uri"
      done
  done | sort -u
}

print_detailed() {
  for entry in "${VARIANTS[@]}"; do
    IFS='|' read -r name cfgdirs shareddir <<< "$entry"
    IFS=':' read -ra CFGDIRS <<< "$cfgdirs"

    found_cfg=""
    for d in "${CFGDIRS[@]}"; do
      [ -d "$d/User" ] && { found_cfg="$d"; break; }
    done
    [ -n "$found_cfg" ] || continue

    printf "${BOLD}== ${name}  (${found_cfg}) ==${RESET}\n"

    storage_json="$found_cfg/User/globalStorage/storage.json"
    profiles=""
    [ -f "$storage_json" ] && profiles=$(jq -r '.userDataProfiles[]?.name' "$storage_json" 2>/dev/null)
    if [ -n "$profiles" ]; then
      echo -e "Profiles: Default, $(echo "$profiles" | paste -sd, -) \n"
    else
      echo "Profiles: Default"
    fi

    {
      recent_from_db "$HOME/$shareddir/sharedStorage/state.vscdb"
      recent_from_db "$found_cfg/User/globalStorage/state.vscdb"
      workspaces_from_storage "$found_cfg/User/workspaceStorage"
    } | while IFS= read -r uri; do
        [ -n "$uri" ] && to_path "$uri"
      done | sort -u | while IFS= read -r p; do
        proj=$(basename "${p%/}")
        if [[ "$p" == \[remote\]* ]]; then
          printf "  ${CYAN}≡ ${BOLD}%s${RESET}\n" "${p#[remote] }"
        elif [ -e "$p" ]; then
          printf "  ${GREEN}✓ ${BOLD}%s${RESET} ${DIM}(%s)${RESET}\n" "$proj" "$(shorten_path "$p")"
        else
          printf "  ${RED}✗ ${BOLD}%s${RESET} ${DIM}(%s) — missing${RESET}\n" "$proj" "$(shorten_path "$p")"
        fi
      done
    echo
  done
}

# Default to interactive mode; use --list or -l for non-interactive output
if [[ "${1:-}" == "--list" || "${1:-}" == "-l" ]]; then
  print_detailed
  exit 0
fi

mapfile -t all_projects < <(collect_projects)

if [ ${#all_projects[@]} -eq 0 ]; then
  echo "No projects found."
  exit 0
fi

echo "Select a project to open in VS Code:"
for i in "${!all_projects[@]}"; do
  p="${all_projects[i]}"
  proj=$(basename "${p%/}")
  if [[ "$p" == \[remote\]* ]]; then
    printf "  %2d) ${CYAN}≡ ${BOLD}%s${RESET}\n" $((i+1)) "${p#[remote] }"
  elif [ -e "$p" ]; then
    printf "  %2d) ${GREEN}✓ ${BOLD}%s${RESET} ${DIM}(%s)${RESET}\n" $((i+1)) "$proj" "$(shorten_path "$p")"
  else
    printf "  %2d) ${RED}✗ ${BOLD}%s${RESET} ${DIM}(%s) — missing${RESET}\n" $((i+1)) "$proj" "$(shorten_path "$p")"
  fi
done

printf "\nEnter number (1-%d) or 'q' to quit: " "${#all_projects[@]}"
read -r choice
if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#all_projects[@]} )); then
  selected="${all_projects[choice-1]}"
  if [[ "$selected" == \[remote\]* ]]; then
    echo "Remote URIs cannot be opened directly."
    exit 1
  fi
  code "$selected"
elif [[ "$choice" != "q" && "$choice" != "Q" ]]; then
  echo "Invalid selection."
  exit 1
fi
