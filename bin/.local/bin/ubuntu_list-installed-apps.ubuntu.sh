#!/usr/bin/env bash
#
# list-installed-apps.sh — View, sort, group, and filter all installed
# applications on Ubuntu 26.
#
# Usage:
# Output the standard sorted list to a file
# ./list-installed-apps.sh -o installed-apps.txt
# Group by type and write to a file
# ./list-installed-apps.sh -g -o installed-apps-grouped.txt
# Filter large apps (>= 50 MB) and output to a file
# ./list-installed-apps.sh -m 50 -o large-apps.txt
# Filter by type and export directly to CSV or JSON
# ./list-installed-apps.sh -t snap,flatpak,appimage --csv -o desktop-packages.csv
# ./list-installed-apps.sh -t elf --json -o standalone-binaries.json
#
# Supported Application Types:
#   - deb      : Debian packages installed via APT / DPKG
#   - snap     : Canonical Snap packages
#   - flatpak  : Flatpak applications (system and user)
#   - elf      : Standalone ELF binaries (/usr/local, ~/.local, /opt, cargo, bun)
#   - appimage : AppImage standalone bundles (~/AppImages, ~/Applications, etc.)
#
# Features:
#   - App Name, Size (formatted in KB, MB, GB), Type, and Install/Update Date
#   - Sort by size (default), date, or name (ascending or descending)
#   - Group by type with per-group counts and size totals
#   - Filter by minimum / maximum size in MB
#   - Filter by type (deb, snap, flatpak, elf, appimage)
#   - Filter by name keyword
#   - Output formats: Formatted table (with colors), CSV, TSV, JSON
#   - Optional --apps-only mode for deb packages (shows only packages providing
#     GUI launchers or binary executables)
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
  BG_GRAY=$'\033[48;5;236m'
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
  BG_GRAY=""
fi

# ── Default Configuration ─────────────────────────────────────────────────────
SORT_BY="size"        # size (default), date, name
SORT_ORDER="desc"     # desc (default for size/date), asc (default for name)
GROUP_BY_TYPE=0       # 0 = unified list, 1 = grouped by type
MIN_SIZE_MB=""        # Filter: min size in MB
MAX_SIZE_MB=""        # Filter: max size in MB
FILTER_TYPES=""       # Comma-separated list of types to include
NAME_FILTER=""        # Name substring / regex filter
APPS_ONLY=0           # 0 = all deb packages, 1 = only debs with binaries/desktop files
OUTPUT_FORMAT="table" # table, csv, tsv, json
OUTPUT_FILE=""        # Destination file path (empty = stdout)
FORCE_COLOR=0         # 1 = keep colors even when writing to file

# ── Help Message ──────────────────────────────────────────────────────────────
show_help() {
  cat <<EOF
${BOLD}Usage:${RESET} $(basename "$0") [OPTIONS]

View, sort, group, and filter all installed applications on Ubuntu 26 across
deb, snap, flatpak, standalone elf binaries, and appimages.

${BOLD}Output Columns:${RESET}
  App Name, Size (KB/MB/GB), Type (deb, snap, flatpak, elf, appimage), Install Date

${BOLD}Sorting Options:${RESET}
  -s, --sort <size|date|name>   Field to sort by (default: ${BOLD}size${RESET})
      --asc                     Sort in ascending order
      --desc                    Sort in descending order (default for size & date)

${BOLD}Grouping Options:${RESET}
  -g, --group                   Group output by application type with subtotals

${BOLD}Filtering Options:${RESET}
  -m, --min-size <MB>           Filter apps with size >= <MB> (e.g. -m 10, -m 0.5)
      --max-size <MB>           Filter apps with size <= <MB> (e.g. --max-size 100)
  -t, --type <types>            Filter by type: deb, snap, flatpak, elf, appimage
                                (comma-separated, e.g. -t snap,flatpak)
  -n, --name <pattern>          Filter apps by name (case-insensitive substring)
  -a, --apps-only               Filter deb packages to only those providing
                                runnable binaries or desktop launchers
      --all-debs                Include all installed deb packages (default)

${BOLD}Output Format:${RESET}
  -o, --output <file>           Write output to file instead of stdout
      --table                   Formatted terminal table with summary (default)
      --csv                     Comma-separated values (CSV)
      --tsv                     Tab-separated values (TSV)
      --json                    JSON array of objects
      --no-color, --plain       Disable ANSI colored output

${BOLD}Information:${RESET}
  -h, --help                    Show this help message and exit

${BOLD}Examples:${RESET}
  $(basename "$0")                           # All apps sorted by size (largest first)
  $(basename "$0") -o installed-apps.txt     # Output to text file
  $(basename "$0") -g -o apps-grouped.txt    # Grouped by type, saved to file
  $(basename "$0") -s date                   # All apps sorted by installation date
  $(basename "$0") -g                        # Grouped by type (deb, snap, etc.)
  $(basename "$0") -m 50                     # Apps 50 MB or larger
  $(basename "$0") -g -m 100                 # Grouped by type, >= 100 MB
  $(basename "$0") -t snap,flatpak           # Only Snap and Flatpak applications
  $(basename "$0") -t appimage,elf           # Only AppImages and standalone ELF binaries
  $(basename "$0") --apps-only -m 20         # Large apps only (excluding deb libraries)
  $(basename "$0") --csv -o apps.csv         # Export to CSV file
  $(basename "$0") --json -o apps.json       # Export to JSON file

EOF
}

# ── Argument Parsing ──────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
  -h | --help)
    show_help
    exit 0
    ;;
  -s | --sort)
    [ -n "${2:-}" ] || {
      echo "Error: --sort requires an argument (size, date, name)" >&2
      exit 1
    }
    case "$2" in
    size | date | name) SORT_BY="$2" ;;
    *)
      echo "Error: Invalid sort field '$2'. Must be size, date, or name." >&2
      exit 1
      ;;
    esac
    shift 2
    ;;
  --asc)
    SORT_ORDER="asc"
    shift
    ;;
  --desc)
    SORT_ORDER="desc"
    shift
    ;;
  -g | --group)
    GROUP_BY_TYPE=1
    shift
    ;;
  -m | --min-size)
    [ -n "${2:-}" ] || {
      echo "Error: --min-size requires size in MB" >&2
      exit 1
    }
    MIN_SIZE_MB="$2"
    shift 2
    ;;
  --max-size)
    [ -n "${2:-}" ] || {
      echo "Error: --max-size requires size in MB" >&2
      exit 1
    }
    MAX_SIZE_MB="$2"
    shift 2
    ;;
  -t | --type)
    [ -n "${2:-}" ] || {
      echo "Error: --type requires comma-separated types" >&2
      exit 1
    }
    FILTER_TYPES="$2"
    shift 2
    ;;
  -n | --name)
    [ -n "${2:-}" ] || {
      echo "Error: --name requires search string" >&2
      exit 1
    }
    NAME_FILTER="$2"
    shift 2
    ;;
  -a | --apps-only)
    APPS_ONLY=1
    shift
    ;;
  --all-debs)
    APPS_ONLY=0
    shift
    ;;
  -o | --output)
    [ -n "${2:-}" ] || {
      echo "Error: --output requires a file path" >&2
      exit 1
    }
    OUTPUT_FILE="$2"
    shift 2
    ;;
  --table)
    OUTPUT_FORMAT="table"
    shift
    ;;
  --csv)
    OUTPUT_FORMAT="csv"
    shift
    ;;
  --tsv)
    OUTPUT_FORMAT="tsv"
    shift
    ;;
  --json)
    OUTPUT_FORMAT="json"
    shift
    ;;
  --color)
    FORCE_COLOR=1
    shift
    ;;
  --no-color | --plain)
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
    BG_GRAY=""
    shift
    ;;
  *)
    echo "Error: Unknown option '$1'. Use --help for usage." >&2
    exit 1
    ;;
  esac
done

# Adjust default sort order if sorting by name and user did not specify --desc
if [ "$SORT_BY" = "name" ] && [ "$SORT_ORDER" = "desc" ]; then
  SORT_ORDER="asc"
fi

# Convert MB filter to bytes
MIN_SIZE_BYTES=0
MAX_SIZE_BYTES=0
if [ -n "$MIN_SIZE_MB" ]; then
  MIN_SIZE_BYTES=$(awk -v mb="$MIN_SIZE_MB" 'BEGIN { printf "%.0f", mb * 1048576 }')
fi
if [ -n "$MAX_SIZE_MB" ]; then
  MAX_SIZE_BYTES=$(awk -v mb="$MAX_SIZE_MB" 'BEGIN { printf "%.0f", mb * 1048576 }')
fi

# Check type filter
type_allowed() {
  local check_type="$1"
  [ -z "$FILTER_TYPES" ] && return 0
  local IFS=','
  for t in $FILTER_TYPES; do
    t="$(echo "$t" | tr '[:upper:]' '[:lower:]' | xargs)"
    [ "$t" = "$check_type" ] && return 0
  done
  return 1
}

# ── Data Collectors ───────────────────────────────────────────────────────────

# 1. Collect DEB packages
collect_deb() {
  type_allowed "deb" || return 0
  command -v dpkg-query >/dev/null 2>&1 || return 0

  awk -v apps_only="$APPS_ONLY" -F'\t' '
  BEGIN {
    cmd = "find /var/lib/dpkg/info -name \"*.list\" -printf \"%f\\t%Ts\\t%TY-%Tm-%Td %TH:%TM\\n\" 2>/dev/null"
    while ((cmd | getline line) > 0) {
      split(line, a, "\t")
      sub(/\.list$/, "", a[1])
      ts[a[1]] = a[2]
      dt[a[1]] = a[3]
    }
    close(cmd)

    if (apps_only == 1) {
      bin_cmd = "grep -lE \"^/(usr/)?(s?bin|games)/|\\.desktop$\" /var/lib/dpkg/info/*.list 2>/dev/null"
      while ((bin_cmd | getline f) > 0) {
        sub(/^.*\/info\//, "", f)
        sub(/\.list$/, "", f)
        has_app[f] = 1
      }
      close(bin_cmd)
    }
  }
  $4 == "installed" {
    pkg = $1
    arch = $2
    sz_kb = $3 + 0
    sz_bytes = sz_kb * 1024

    if (apps_only == 1) {
      if (!(pkg in has_app) && !(pkg ":" arch in has_app)) {
        next
      }
    }

    t = (pkg in ts) ? ts[pkg] : ((pkg ":" arch in ts) ? ts[pkg ":" arch] : 0)
    d = (pkg in dt) ? dt[pkg] : ((pkg ":" arch in dt) ? dt[pkg ":" arch] : "Unknown")

    printf "%s\t%s\t%s\t%s\tdeb\n", pkg, sz_bytes, t, d
  }
  ' <(dpkg-query -W -f='${Package}\t${Architecture}\t${Installed-Size}\t${db:Status-Status}\n' 2>/dev/null)
}

# 2. Collect SNAP packages
collect_snap() {
  type_allowed "snap" || return 0

  local snap_out=""
  if command -v snap >/dev/null 2>&1; then
    snap_out=$(timeout 2 snap list 2>/dev/null || true)
  fi

  if [ -n "$snap_out" ]; then
    echo "$snap_out" | tail -n +2 | while read -r name version rev rest; do
      [ -n "$name" ] || continue
      local snap_file="/var/lib/snapd/snaps/${name}_${rev}.snap"
      local sz=0 ts=0 dt="Unknown"

      if [ -f "$snap_file" ]; then
        sz=$(stat -c %s "$snap_file" 2>/dev/null || echo 0)
        ts=$(stat -c %Y "$snap_file" 2>/dev/null || echo 0)
        dt=$(stat -c "%y" "$snap_file" 2>/dev/null | cut -c1-16 || echo "Unknown")
      elif [ -d "/snap/${name}/${rev}" ]; then
        sz=$(du -sb "/snap/${name}/${rev}" 2>/dev/null | cut -f1 || echo 0)
        ts=$(stat -c %Y "/snap/${name}/${rev}" 2>/dev/null || echo 0)
        dt=$(stat -c "%y" "/snap/${name}/${rev}" 2>/dev/null | cut -c1-16 || echo "Unknown")
      fi

      printf "%s\t%s\t%s\t%s\tsnap\n" "$name" "$sz" "$ts" "$dt"
    done
  else
    if [ -d "/var/lib/snapd/snaps" ]; then
      declare -A latest_rev_file
      for f in /var/lib/snapd/snaps/*.snap; do
        [ -f "$f" ] || continue
        base=$(basename "$f" .snap)
        pkg="${base%_*}"
        rev="${base##*_}"
        if [ -z "${latest_rev_file[$pkg]:-}" ]; then
          latest_rev_file["$pkg"]="$f"
        else
          old_ts=$(stat -c %Y "${latest_rev_file[$pkg]}" 2>/dev/null || echo 0)
          new_ts=$(stat -c %Y "$f" 2>/dev/null || echo 0)
          if [ "$new_ts" -gt "$old_ts" ]; then
            latest_rev_file["$pkg"]="$f"
          fi
        fi
      done

      for pkg in "${!latest_rev_file[@]}"; do
        f="${latest_rev_file[$pkg]}"
        sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
        ts=$(stat -c %Y "$f" 2>/dev/null || echo 0)
        dt=$(stat -c "%y" "$f" 2>/dev/null | cut -c1-16 || echo "Unknown")
        printf "%s\t%s\t%s\t%s\tsnap\n" "$pkg" "$sz" "$ts" "$dt"
      done
    fi
  fi
}

# 3. Collect FLATPAK packages
collect_flatpak() {
  type_allowed "flatpak" || return 0
  command -v flatpak >/dev/null 2>&1 || return 0

  flatpak list --app --columns=name:f,application:f,size:f 2>/dev/null | awk -F'\t' '
  function parse_size(str,    parts, val, unit, mult) {
    gsub(/[\xc2\xa0 ]+/, " ", str)
    split(str, parts, " ")
    val = parts[1] + 0
    unit = toupper(parts[2])
    if (unit ~ /^G/) mult = 1073741824
    else if (unit ~ /^M/) mult = 1048576
    else if (unit ~ /^K/) mult = 1024
    else mult = 1
    return int(val * mult)
  }
  {
    name = $1
    appid = $2
    sz_str = $3
    sz_bytes = parse_size(sz_str)

    deploy_sys = "/var/lib/flatpak/app/" appid "/current/active/deploy"
    deploy_usr = ENVIRON["HOME"] "/.local/share/flatpak/app/" appid "/current/active/deploy"

    cmd = "stat -c \"%Y %y\" \"" deploy_sys "\" 2>/dev/null || stat -c \"%Y %y\" \"" deploy_usr "\" 2>/dev/null"
    ts = 0; dt = "Unknown"
    if ((cmd | getline line) > 0) {
      split(line, a, " ")
      ts = a[1]
      dt = a[2] " " substr(a[3], 1, 5)
    }
    close(cmd)

    display_name = (name != "" ? name : appid)
    printf "%s\t%s\t%s\t%s\tflatpak\n", display_name, sz_bytes, ts, dt
  }
  '
}

# 4. Collect APPIMAGE packages
collect_appimage() {
  type_allowed "appimage" || return 0

  declare -A seen_appimages
  local search_dirs=(
    "$HOME/AppImages"
    "$HOME/Applications"
    "$HOME/.local/bin"
    "$HOME/bin"
    "$HOME/Downloads"
    "$HOME/Desktop"
    "$HOME/.local/share/appimages"
    "$HOME/.var/app/it.mijorus.gearlever/cache"
    "$HOME/.var/app/it.mijorus.gearlever/data"
    "/opt"
    "/usr/local/bin"
    "/Applications"
  )

  for d in "${search_dirs[@]}"; do
    [ -d "$d" ] || continue
    while IFS= read -r f; do
      [ -f "$f" ] && [ -x "$f" ] || continue
      local real
      real=$(realpath "$f" 2>/dev/null || readlink -f "$f" 2>/dev/null || echo "$f")
      [ -n "${seen_appimages[$real]:-}" ] && continue
      seen_appimages["$real"]=1

      local name
      name=$(basename "$real" | sed -E 's/\.[aA][pP][pP][iI][mM][aA][gG][eE]$//')
      local sz ts dt
      sz=$(stat -c %s "$real" 2>/dev/null || echo 0)
      ts=$(stat -c %Y "$real" 2>/dev/null || echo 0)
      dt=$(stat -c "%y" "$real" 2>/dev/null | cut -c1-16 || echo "Unknown")

      printf "%s\t%s\t%s\t%s\tappimage\n" "$name" "$sz" "$ts" "$dt"
    done < <(find "$d" -maxdepth 3 -iname "*.appimage" 2>/dev/null)
  done

  local desktop_dirs=("/usr/share/applications" "$HOME/.local/share/applications")
  for dd in "${desktop_dirs[@]}"; do
    [ -d "$dd" ] || continue
    while IFS= read -r line; do
      local exec_path
      exec_path=$(echo "$line" | sed -E 's/^Exec=([^ ]+).*/\1/' | tr -d '"' | tr -d "'")
      case "$exec_path" in
      *.appimage | *.AppImage)
        if [ -f "$exec_path" ] && [ -x "$exec_path" ]; then
          local real
          real=$(realpath "$exec_path" 2>/dev/null || readlink -f "$exec_path" 2>/dev/null || echo "$exec_path")
          [ -n "${seen_appimages[$real]:-}" ] && continue
          seen_appimages["$real"]=1

          local name
          name=$(basename "$real" | sed -E 's/\.[aA][pP][pP][iI][mM][aA][gG][eE]$//')
          local sz ts dt
          sz=$(stat -c %s "$real" 2>/dev/null || echo 0)
          ts=$(stat -c %Y "$real" 2>/dev/null || echo 0)
          dt=$(stat -c "%y" "$real" 2>/dev/null | cut -c1-16 || echo "Unknown")

          printf "%s\t%s\t%s\t%s\tappimage\n" "$name" "$sz" "$ts" "$dt"
        fi
        ;;
      esac
    done < <(grep -h '^Exec=.*[aA][pP][pP][iI][mM][aA][gG][eE]' "$dd"/*.desktop 2>/dev/null || true)
  done
}

# 5. Collect standalone ELF binaries
collect_elf() {
  type_allowed "elf" || return 0

  declare -A seen_elf

  # A. Check standalone application suites in /opt
  if [ -d /opt ]; then
    for d in /opt/*; do
      [ -d "$d" ] || continue
      if dpkg -S "$d" >/dev/null 2>&1; then
        continue
      fi

      local has_elf=0
      while IFS= read -r f; do
        if [ -f "$f" ] && [ -x "$f" ]; then
          local magic
          magic=$(od -An -N4 -tx1 "$f" 2>/dev/null | tr -d ' \n')
          if [ "$magic" = "7f454c46" ]; then
            has_elf=1
            break
          fi
        fi
      done < <(find "$d" -maxdepth 3 -type f 2>/dev/null)

      if [ "$has_elf" -eq 1 ]; then
        local name
        name=$(basename "$d")
        local sz ts dt
        sz=$(du -sb "$d" 2>/dev/null | cut -f1 || echo 0)
        ts=$(stat -c %Y "$d" 2>/dev/null || echo 0)
        dt=$(stat -c "%y" "$d" 2>/dev/null | cut -c1-16 || echo "Unknown")
        seen_elf["$d"]=1
        seen_elf["$name"]=1
        printf "%s\t%s\t%s\t%s\telf\n" "$name" "$sz" "$ts" "$dt"
      fi
    done
  fi

  # B. Check local and user binary directories
  local bin_dirs=(
    "/usr/local/bin"
    "/usr/local/sbin"
    "$HOME/.local/bin"
    "$HOME/bin"
    "$HOME/.cargo/bin"
    "$HOME/.bun/bin"
  )

  for bdir in "${bin_dirs[@]}"; do
    [ -d "$bdir" ] || continue
    for f in "$bdir"/*; do
      [ -f "$f" ] && [ -x "$f" ] || continue
      local real
      real=$(realpath "$f" 2>/dev/null || readlink -f "$f" 2>/dev/null || echo "$f")
      [ -n "${seen_elf[$real]:-}" ] && continue

      local magic
      magic=$(od -An -N4 -tx1 "$real" 2>/dev/null | tr -d ' \n')
      [ "$magic" = "7f454c46" ] || continue

      case "$real" in
      *.appimage | *.AppImage) continue ;;
      esac
      local ai_magic
      ai_magic=$(od -An -j8 -N3 -tx1 "$real" 2>/dev/null | tr -d ' \n')
      [ "$ai_magic" = "414902" ] && continue
      [ "$ai_magic" = "414901" ] && continue

      if [[ "$bdir" == /usr/* ]] && dpkg -S "$real" >/dev/null 2>&1; then
        continue
      fi

      seen_elf["$real"]=1
      local name
      name=$(basename "$f")
      local sz ts dt
      sz=$(stat -c %s "$real" 2>/dev/null || echo 0)
      ts=$(stat -c %Y "$real" 2>/dev/null || echo 0)
      dt=$(stat -c "%y" "$real" 2>/dev/null | cut -c1-16 || echo "Unknown")

      printf "%s\t%s\t%s\t%s\telf\n" "$name" "$sz" "$ts" "$dt"
    done
  done
}

# ── Gather All Records ────────────────────────────────────────────────────────
RAW_DATA=$(
  {
    collect_deb
    collect_snap
    collect_flatpak
    collect_appimage
    collect_elf
  }
)

if [ -z "$RAW_DATA" ]; then
  echo "No installed applications found matching your criteria."
  exit 0
fi

# ── Sorting Pipeline ──────────────────────────────────────────────────────────
# Fields: 1=Name, 2=SizeBytes, 3=Timestamp, 4=DateStr, 5=Type

SORT_ARGS=()
if [ "$GROUP_BY_TYPE" -eq 1 ]; then
  SORT_ARGS+=("-k5,5")
fi

case "$SORT_BY" in
size)
  if [ "$SORT_ORDER" = "desc" ]; then
    SORT_ARGS+=("-k2,2nr")
  else
    SORT_ARGS+=("-k2,2n")
  fi
  ;;
date)
  if [ "$SORT_ORDER" = "desc" ]; then
    SORT_ARGS+=("-k3,3nr")
  else
    SORT_ARGS+=("-k3,3n")
  fi
  ;;
name)
  if [ "$SORT_ORDER" = "desc" ]; then
    SORT_ARGS+=("-k1,1fr")
  else
    SORT_ARGS+=("-k1,1f")
  fi
  ;;
esac

SORTED_DATA=$(echo "$RAW_DATA" | sort -t$'\t' "${SORT_ARGS[@]}")

# ── Formatting and Rendering ──────────────────────────────────────────────────
if [ -n "$OUTPUT_FILE" ] && [ "$FORCE_COLOR" -eq 0 ]; then
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
  BG_GRAY=""
fi

export MIN_SIZE_BYTES
export MAX_SIZE_BYTES
export NAME_FILTER
export GROUP_BY_TYPE
export OUTPUT_FORMAT
export BOLD DIM RESET RED GREEN YELLOW BLUE MAGENTA CYAN WHITE BG_GRAY

render_output() {
  awk -F'\t' '
function fmt_size(b) {
  if (b >= 1073741824) {
    return sprintf("%.2f GB", b / 1073741824)
  } else if (b >= 1048576) {
    return sprintf("%.2f MB", b / 1048576)
  } else if (b >= 1024) {
    return sprintf("%.2f KB", b / 1024)
  } else {
    return sprintf("%.2f KB", b / 1024)
  }
}

function type_color(t) {
  if (t == "deb") return ENVIRON["BLUE"]
  if (t == "snap") return ENVIRON["GREEN"]
  if (t == "flatpak") return ENVIRON["CYAN"]
  if (t == "elf") return ENVIRON["MAGENTA"]
  if (t == "appimage") return ENVIRON["YELLOW"]
  return ENVIRON["WHITE"]
}

BEGIN {
  min_b = ENVIRON["MIN_SIZE_BYTES"] + 0
  max_b = ENVIRON["MAX_SIZE_BYTES"] + 0
  name_filter = ENVIRON["NAME_FILTER"]
  group_mode = ENVIRON["GROUP_BY_TYPE"] + 0
  fmt = ENVIRON["OUTPUT_FORMAT"]

  bold = ENVIRON["BOLD"]
  dim = ENVIRON["DIM"]
  reset = ENVIRON["RESET"]
  cyan = ENVIRON["CYAN"]

  total_count = 0
  total_bytes = 0

  if (fmt == "csv") {
    print "App Name,Size Bytes,Size Formatted,Type,Install Date"
  } else if (fmt == "tsv") {
    print "App Name\tSize Bytes\tSize Formatted\tType\tInstall Date"
  } else if (fmt == "json") {
    printf "[\n"
  } else if (fmt == "table" && group_mode == 0) {
    printf "\n%s%-40s  %-12s  %-10s  %-16s%s\n", bold, "APP NAME", "SIZE", "TYPE", "INSTALL DATE", reset
    printf "%s%s%s\n", dim, "───────────────────────────────────────────────────────────────────────────────────", reset
  }

  prev_type = ""
}

{
  name = $1
  sz_b = $2 + 0
  ts = $3 + 0
  dt = $4
  type = $5

  # Filters
  if (min_b > 0 && sz_b < min_b) next
  if (max_b > 0 && sz_b > max_b) next
  if (name_filter != "" && tolower(name) !~ tolower(name_filter)) next

  count_by_type[type]++
  size_by_type[type] += sz_b

  total_count++
  total_bytes += sz_b

  sz_fmt = fmt_size(sz_b)

  if (fmt == "csv") {
    gsub(/"/, "\"\"", name)
    printf "\"%s\",%d,\"%s\",\"%s\",\"%s\"\n", name, sz_b, sz_fmt, type, dt
  } else if (fmt == "tsv") {
    printf "%s\t%d\t%s\t%s\t%s\n", name, sz_b, sz_fmt, type, dt
  } else if (fmt == "json") {
    if (total_count > 1) printf ",\n"
    gsub(/\\/, "\\\\", name)
    gsub(/"/, "\\\"", name)
    printf "  {\n"
    printf "    \"name\": \"%s\",\n", name
    printf "    \"size_bytes\": %d,\n", sz_b
    printf "    \"size\": \"%s\",\n", sz_fmt
    printf "    \"type\": \"%s\",\n", type
    printf "    \"install_date\": \"%s\"\n", dt
    printf "  }"
  } else {
    if (group_mode == 1) {
      if (type != prev_type) {
        if (prev_type != "") {
          printf "\n"
        }
        type_upper = toupper(type)
        t_col = type_color(type)
        printf "%s%s── TYPE: %s %s────────────────────────────────────────────────────────────%s\n", bold, t_col, type_upper, dim, reset
        printf "%s%-40s  %-12s  %-10s  %-16s%s\n", bold, "APP NAME", "SIZE", "TYPE", "INSTALL DATE", reset
        printf "%s%s%s\n", dim, "───────────────────────────────────────────────────────────────────────────────────", reset
        prev_type = type
      }
    }

    t_col = type_color(type)
    disp_name = (length(name) > 40) ? substr(name, 1, 37) "..." : name

    printf "%-40s  %12s  %s%-10s%s  %s%s%s\n", disp_name, sz_fmt, t_col, type, reset, dim, dt, reset
  }
}

END {
  if (fmt == "json") {
    printf "\n]\n"
  } else if (fmt == "table") {
    if (total_count == 0) {
      print "\nNo applications matched the specified filter criteria."
      exit 0
    }

    printf "%s%s%s\n", dim, "───────────────────────────────────────────────────────────────────────────────────", reset

    printf "\n%sSUMMARY BREAKDOWN BY TYPE%s\n", bold, reset
    printf "%s%-12s  %8s  %14s%s\n", dim, "TYPE", "COUNT", "TOTAL DISK", reset
    printf "%s%s%s\n", dim, "────────────────────────────────────────────", reset

    split("deb snap flatpak elf appimage", order, " ")
    for (i = 1; i <= 5; i++) {
      t = order[i]
      if (count_by_type[t] > 0) {
        t_col = type_color(t)
        printf "%s%-12s%s  %8d  %14s\n", t_col, t, reset, count_by_type[t], fmt_size(size_by_type[t])
      }
    }
    printf "%s%s%s\n", dim, "────────────────────────────────────────────", reset
    printf "%s%-12s  %8d  %14s%s\n\n", bold, "TOTAL", total_count, fmt_size(total_bytes), reset
  }
}
'
}

if [ -n "$OUTPUT_FILE" ]; then
  mkdir -p "$(dirname "$OUTPUT_FILE")" 2>/dev/null || true
  echo "$SORTED_DATA" | render_output >"$OUTPUT_FILE"
  echo "Report successfully written to: $OUTPUT_FILE" >&2
else
  echo "$SORTED_DATA" | render_output
fi
