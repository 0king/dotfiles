#!/usr/bin/env bash
#
# new-script.sh — Scaffolder and boilerplate generator for modern, robust Bash scripts.
#
# Usage:
#   ./new-script.sh <script-name> [OPTIONS]
#   ./new-script.sh --interactive
#
# Examples:
#   ./new-script.sh backup-db.sh -d "Daily database backup utility"
#   ./new-script.sh deploy.sh -t subcommand -d "Multi-environment deployment CLI"
#   ./new-script.sh quick-task -t minimal
#   ./new-script.sh my-tool.sh -e # creates and opens in $EDITOR / code
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

# ── Defaults & Configuration ──────────────────────────────────────────────────
SCRIPT_NAME_INPUT=""
TEMPLATE="standard"
DESCRIPTION=""
AUTHOR=""
FORCE=0
OPEN_EDITOR=0
APPEND_EXT=1

# Auto-detect author from git config or environment
GIT_NAME="$(git config user.name 2>/dev/null || true)"
GIT_EMAIL="$(git config user.email 2>/dev/null || true)"
if [ -n "$GIT_NAME" ] && [ -n "$GIT_EMAIL" ]; then
  DEFAULT_AUTHOR="${GIT_NAME} <${GIT_EMAIL}>"
elif [ -n "$GIT_NAME" ]; then
  DEFAULT_AUTHOR="${GIT_NAME}"
else
  DEFAULT_AUTHOR="${USER:-$(whoami 2>/dev/null || echo 'User')}"
fi

# ── Help / Usage ──────────────────────────────────────────────────────────────
show_help() {
  cat <<EOF
${BOLD}Usage:${RESET} $(basename "$0") [SCRIPT_NAME] [OPTIONS]

Generate new, robust Bash scripts pre-populated with production-grade boilerplate.

${BOLD}Arguments:${RESET}
  SCRIPT_NAME                   Name or relative/absolute path of the script to create

${BOLD}Options:${RESET}
  -t, --template <name>         Boilerplate template: standard, minimal, subcommand
                                (default: ${BOLD}standard${RESET})
  -d, --description <text>      Brief summary / purpose of the script
  -a, --author <name>           Author information (default: ${BOLD}${DEFAULT_AUTHOR}${RESET})
  -f, --force                   Overwrite existing file without prompting
  -e, --edit                    Open the generated script in editor (\$VISUAL / \$EDITOR / code)
      --no-ext                  Do not automatically append .sh extension
  -i, --interactive             Run in interactive setup mode
  -l, --list-templates          List available templates and descriptions
  -h, --help                    Show this help message and exit

${BOLD}Available Templates:${RESET}
  ${CYAN}standard${RESET}    Comprehensive production script with strict mode, color logs,
              argument parsing, help text, and an automated cleanup trap.
  ${CYAN}minimal${RESET}     Lightweight strict script with directory resolution, usage function,
              and basic structure.
  ${CYAN}subcommand${RESET}  Modular CLI framework with subcommands (e.g. 'tool start', 'tool stop'),
              per-command handlers, and global option parsing.

${BOLD}Examples:${RESET}
  $(basename "$0") backup-db.sh
  $(basename "$0") sync-files.sh -d "Sync local assets to remote S3 bucket"
  $(basename "$0") deploy-tool -t subcommand -d "Cloud deploy runner"
  $(basename "$0") quick-check.sh -t minimal
  $(basename "$0") process-data.sh --edit
  $(basename "$0") -i
EOF
}

list_templates() {
  cat <<EOF
${BOLD}Available Templates:${RESET}

1. ${BOLD}${CYAN}standard${RESET} (Default)
   - Unofficial Bash Strict Mode (set -euo pipefail)
   - Dynamic SCRIPT_DIR and SCRIPT_NAME resolution
   - ANSI color palette with NO_COLOR & TTY detection
   - Logging helpers (log_info, log_success, log_warn, log_error, die)
   - Exit & signal cleanup trap with optional temporary directory
   - Command line flag and option parsing (-h, -v, -d, etc.)
   - Professional show_help() output
   - Clean main() entry point

2. ${BOLD}${CYAN}minimal${RESET}
   - Strict mode (set -euo pipefail)
   - SCRIPT_DIR resolution
   - Compact usage function
   - Streamlined argument loop and main()

3. ${BOLD}${CYAN}subcommand${RESET}
   - Multi-command CLI architecture (like git, docker, kubectl)
   - Subcommand routing (e.g., status, run, config)
   - Per-command help & argument handling
   - Logging and cleanup traps
EOF
}

# ── Boilerplate Generators ────────────────────────────────────────────────────

generate_standard_template() {
  local target_basename="$1"
  local desc="${2:-Script description and purpose.}"
  local author="$3"
  local created_date="$4"

  cat <<'EOF' | sed \
    -e "s|{{SCRIPT_NAME}}|${target_basename}|g" \
    -e "s|{{DESCRIPTION}}|${desc}|g" \
    -e "s|{{AUTHOR}}|${author}|g" \
    -e "s|{{DATE}}|${created_date}|g"
#!/usr/bin/env bash
#
# {{SCRIPT_NAME}} — {{DESCRIPTION}}
#
# Author:  {{AUTHOR}}
# Date:    {{DATE}}
#
# Usage:
#   ./{{SCRIPT_NAME}} [OPTIONS] [ARGUMENTS]
#

set -euo pipefail

# ── Script Environment ────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"

# ── ANSI Color Palette ────────────────────────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD=$'\033[1m'
  DIM=$'\033[2m'
  RESET=$'\033[0m'
  RED=$'\033[31m'
  GREEN=$'\033[32m'
  YELLOW=$'\033[33m'
  BLUE=$'\033[34m'
  CYAN=$'\033[36m'
else
  BOLD=""
  DIM=""
  RESET=""
  RED=""
  GREEN=""
  YELLOW=""
  BLUE=""
  CYAN=""
fi

# ── Logging Functions ─────────────────────────────────────────────────────────
log_info()    { printf "%s[INFO]%s  %s\n" "$CYAN" "$RESET" "$*"; }
log_success() { printf "%s[OK]%s    %s\n" "$GREEN" "$RESET" "$*"; }
log_warn()    { printf "%s[WARN]%s  %s\n" "$YELLOW" "$RESET" "$*" >&2; }
log_error()   { printf "%s[ERROR]%s %s\n" "$RED" "$RESET" "$*" >&2; }
die()         { log_error "$*"; exit 1; }

# ── Cleanup Handler ───────────────────────────────────────────────────────────
TMP_DIR=""
cleanup() {
  local exit_code=$?
  if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

# ── Default Configuration ─────────────────────────────────────────────────────
VERBOSE=0
DRY_RUN=0

# ── Help / Usage ──────────────────────────────────────────────────────────────
show_help() {
  cat <<HELP
${BOLD}Usage:${RESET} ${SCRIPT_NAME} [OPTIONS]

${BOLD}Description:${RESET}
  {{DESCRIPTION}}

${BOLD}Options:${RESET}
  -v, --verbose     Enable verbose output
  -n, --dry-run     Simulate actions without making permanent changes
  -h, --help        Show this help message and exit

${BOLD}Examples:${RESET}
  ./${SCRIPT_NAME} --verbose
  ./${SCRIPT_NAME} --dry-run
HELP
}

# ── Argument Parsing ──────────────────────────────────────────────────────────
parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help)
        show_help
        exit 0
        ;;
      -v|--verbose)
        VERBOSE=1
        shift
        ;;
      -n|--dry-run)
        DRY_RUN=1
        shift
        ;;
      --)
        shift
        break
        ;;
      -*)
        die "Unknown option: $1 (use --help for usage)"
        ;;
      *)
        # Positional arguments can be captured here
        shift
        ;;
    esac
  done
}

# ── Main Entry Point ──────────────────────────────────────────────────────────
main() {
  parse_args "$@"

  # Example: Create isolated temporary directory if needed
  # TMP_DIR="$(mktemp -d -t "${SCRIPT_NAME}.XXXXXX")"

  log_info "Starting ${SCRIPT_NAME}..."
  if [ "$DRY_RUN" -eq 1 ]; then
    log_warn "Running in dry-run mode. No changes will be made."
  fi

  # TODO: Add your script logic here
  log_success "Completed successfully."
}

main "$@"
EOF
}

generate_minimal_template() {
  local target_basename="$1"
  local desc="${2:-Script description and purpose.}"
  local author="$3"
  local created_date="$4"

  cat <<'EOF' | sed \
    -e "s|{{SCRIPT_NAME}}|${target_basename}|g" \
    -e "s|{{DESCRIPTION}}|${desc}|g" \
    -e "s|{{AUTHOR}}|${author}|g" \
    -e "s|{{DATE}}|${created_date}|g"
#!/usr/bin/env bash
#
# {{SCRIPT_NAME}} — {{DESCRIPTION}}
# Author: {{AUTHOR}}
# Date:   {{DATE}}
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"

usage() {
  cat <<USAGE
Usage: ${SCRIPT_NAME} [options]

{{DESCRIPTION}}

Options:
  -h, --help    Show this message and exit
USAGE
}

main() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "Unknown argument: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
  done

  echo "Running ${SCRIPT_NAME}..."
  # TODO: Implement script actions
}

main "$@"
EOF
}

generate_subcommand_template() {
  local target_basename="$1"
  local desc="${2:-Modular CLI tool with subcommands.}"
  local author="$3"
  local created_date="$4"

  cat <<'EOF' | sed \
    -e "s|{{SCRIPT_NAME}}|${target_basename}|g" \
    -e "s|{{DESCRIPTION}}|${desc}|g" \
    -e "s|{{AUTHOR}}|${author}|g" \
    -e "s|{{DATE}}|${created_date}|g"
#!/usr/bin/env bash
#
# {{SCRIPT_NAME}} — {{DESCRIPTION}}
#
# Author:  {{AUTHOR}}
# Date:    {{DATE}}
#
# Usage:
#   ./{{SCRIPT_NAME}} <command> [OPTIONS]
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"

# ── Colors ────────────────────────────────────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD=$'\033[1m'
  RESET=$'\033[0m'
  RED=$'\033[31m'
  GREEN=$'\033[32m'
  YELLOW=$'\033[33m'
  CYAN=$'\033[36m'
else
  BOLD="" RESET="" RED="" GREEN="" YELLOW="" CYAN=""
fi

log_info()    { printf "%s[INFO]%s  %s\n" "$CYAN" "$RESET" "$*"; }
log_success() { printf "%s[OK]%s    %s\n" "$GREEN" "$RESET" "$*"; }
log_warn()    { printf "%s[WARN]%s  %s\n" "$YELLOW" "$RESET" "$*" >&2; }
log_error()   { printf "%s[ERROR]%s %s\n" "$RED" "$RESET" "$*" >&2; }
die()         { log_error "$*"; exit 1; }

# ── Help / Usage ──────────────────────────────────────────────────────────────
show_help() {
  cat <<HELP
${BOLD}Usage:${RESET} ${SCRIPT_NAME} <command> [OPTIONS]

${BOLD}Description:${RESET}
  {{DESCRIPTION}}

${BOLD}Commands:${RESET}
  start         Start the service/task
  stop          Stop the service/task
  status        Check current status
  help          Show help for a command

${BOLD}Global Options:${RESET}
  -h, --help    Show this help message and exit
  -v, --version Show version

${BOLD}Examples:${RESET}
  ./${SCRIPT_NAME} status
  ./${SCRIPT_NAME} start --port 8080
HELP
}

# ── Subcommand Handlers ───────────────────────────────────────────────────────
cmd_start() {
  local port=8080
  while [ $# -gt 0 ]; do
    case "$1" in
      -p|--port)
        port="$2"
        shift 2
        ;;
      *)
        die "Unknown option for 'start': $1"
        ;;
    esac
  done
  log_info "Starting service on port ${port}..."
  # TODO: Start logic
  log_success "Service started."
}

cmd_stop() {
  log_info "Stopping service..."
  # TODO: Stop logic
  log_success "Service stopped."
}

cmd_status() {
  log_info "Checking status..."
  # TODO: Status logic
  printf "Status: %sReady%s\n" "$GREEN" "$RESET"
}

# ── Main Dispatcher ───────────────────────────────────────────────────────────
main() {
  if [ $# -eq 0 ]; then
    show_help
    exit 0
  fi

  local command="$1"
  shift

  case "$command" in
    -h|--help|help)
      show_help
      ;;
    -v|--version)
      echo "${SCRIPT_NAME} v0.1.0"
      ;;
    start)
      cmd_start "$@"
      ;;
    stop)
      cmd_stop "$@"
      ;;
    status)
      cmd_status "$@"
      ;;
    *)
      die "Unknown command: '${command}'. Run '${SCRIPT_NAME} --help' for available commands."
      ;;
  esac
}

main "$@"
EOF
}

# ── Interactive Mode ──────────────────────────────────────────────────────────
run_interactive() {
  printf "\n%s=== New Bash Script Setup Wizard ===%s\n\n" "$BOLD" "$RESET"

  # 1. Script Name
  while [ -z "$SCRIPT_NAME_INPUT" ]; do
    printf "%sEnter script name%s (e.g. backup-db.sh): " "$BOLD" "$RESET"
    read -r SCRIPT_NAME_INPUT
    SCRIPT_NAME_INPUT="$(echo "$SCRIPT_NAME_INPUT" | xargs)"
  done

  # 2. Template
  printf "\n%sSelect template:%s\n" "$BOLD" "$RESET"
  printf "  1) standard   (Strict mode, logging, flags parsing, cleanup trap) [Default]\n"
  printf "  2) minimal    (Lean & clean strict-mode structure)\n"
  printf "  3) subcommand (Modular multi-command CLI tool)\n"
  printf "Choice [1-3] (default: 1): "
  read -r t_choice
  case "${t_choice:-1}" in
    2|minimal)    TEMPLATE="minimal" ;;
    3|subcommand) TEMPLATE="subcommand" ;;
    *)            TEMPLATE="standard" ;;
  esac

  # 3. Description
  printf "\n%sEnter brief description%s (press Enter for default): " "$BOLD" "$RESET"
  read -r user_desc
  if [ -n "$user_desc" ]; then
    DESCRIPTION="$user_desc"
  fi

  # 4. Author
  printf "\n%sAuthor%s [%s]: " "$BOLD" "$RESET" "$DEFAULT_AUTHOR"
  read -r user_author
  if [ -n "$user_author" ]; then
    AUTHOR="$user_author"
  fi

  # 5. Open in editor
  printf "\n%sOpen in editor after creation?%s [y/N]: " "$BOLD" "$RESET"
  read -r edit_choice
  case "${edit_choice:-n}" in
    [yY]|[yY][eE][sS]) OPEN_EDITOR=1 ;;
    *)                 OPEN_EDITOR=0 ;;
  esac
  echo ""
}

# ── Argument Parsing ──────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)
      show_help
      exit 0
      ;;
    -l|--list-templates)
      list_templates
      exit 0
      ;;
    -t|--template)
      [ $# -ge 2 ] || die "Option $1 requires a template name"
      TEMPLATE="$2"
      shift 2
      ;;
    -d|--description)
      [ $# -ge 2 ] || die "Option $1 requires a description string"
      DESCRIPTION="$2"
      shift 2
      ;;
    -a|--author)
      [ $# -ge 2 ] || die "Option $1 requires an author string"
      AUTHOR="$2"
      shift 2
      ;;
    -f|--force)
      FORCE=1
      shift
      ;;
    -e|--edit)
      OPEN_EDITOR=1
      shift
      ;;
    --no-ext)
      APPEND_EXT=0
      shift
      ;;
    -i|--interactive)
      run_interactive
      break
      ;;
    -*)
      die "Unknown option: $1 (run with --help for usage)"
      ;;
    *)
      if [ -z "$SCRIPT_NAME_INPUT" ]; then
        SCRIPT_NAME_INPUT="$1"
      else
        die "Unexpected extra argument: $1"
      fi
      shift
      ;;
  esac
done

# If no script name was given, check if running interactively in terminal
if [ -z "$SCRIPT_NAME_INPUT" ]; then
  if [ -t 0 ]; then
    run_interactive
  else
    die "Script name is required. Run '$(basename "$0") --help' for usage."
  fi
fi

# ── Validate & Resolve File Path ──────────────────────────────────────────────
TARGET_FILE="$SCRIPT_NAME_INPUT"

# Append .sh extension if missing and not disabled
if [ "$APPEND_EXT" -eq 1 ] && [[ "$TARGET_FILE" != *.sh ]]; then
  TARGET_FILE="${TARGET_FILE}.sh"
fi

TARGET_DIR="$(dirname "$TARGET_FILE")"
TARGET_BASENAME="$(basename "$TARGET_FILE")"
AUTHOR="${AUTHOR:-$DEFAULT_AUTHOR}"
DESCRIPTION="${DESCRIPTION:-Utility script to ${TARGET_BASENAME%.sh}.}"
CREATED_DATE="$(date +'%Y-%m-%d')"

# Validate template
case "$TEMPLATE" in
  standard|minimal|subcommand) ;;
  *) die "Invalid template '$TEMPLATE'. Must be one of: standard, minimal, subcommand." ;;
esac

# Create directory path if needed
if [ ! -d "$TARGET_DIR" ]; then
  mkdir -p "$TARGET_DIR"
  log_info "Created directory: ${TARGET_DIR}"
fi

# Check for existing file
if [ -e "$TARGET_FILE" ] && [ "$FORCE" -eq 0 ]; then
  if [ -t 0 ]; then
    printf "%sFile '%s' already exists. Overwrite?%s [y/N]: " "$YELLOW" "$TARGET_FILE" "$RESET"
    read -r confirm
    case "${confirm:-n}" in
      [yY]|[yY][eE][sS]) ;;
      *) log_warn "Aborted without overwriting."; exit 0 ;;
    esac
  else
    die "File '$TARGET_FILE' already exists. Use -f/--force to overwrite."
  fi
fi

# ── Generate Template Content ─────────────────────────────────────────────────
case "$TEMPLATE" in
  standard)
    generate_standard_template "$TARGET_BASENAME" "$DESCRIPTION" "$AUTHOR" "$CREATED_DATE" > "$TARGET_FILE"
    ;;
  minimal)
    generate_minimal_template "$TARGET_BASENAME" "$DESCRIPTION" "$AUTHOR" "$CREATED_DATE" > "$TARGET_FILE"
    ;;
  subcommand)
    generate_subcommand_template "$TARGET_BASENAME" "$DESCRIPTION" "$AUTHOR" "$CREATED_DATE" > "$TARGET_FILE"
    ;;
esac

# ── Make Executable & Verify ──────────────────────────────────────────────────
chmod +x "$TARGET_FILE"

# Syntax check generated script
if ! bash -n "$TARGET_FILE" 2>/dev/null; then
  die "Generated script contains syntax errors! Please inspect: $TARGET_FILE"
fi

# ── Summary & Output ──────────────────────────────────────────────────────────
log_success "Created executable script: ${BOLD}${TARGET_FILE}${RESET}"
printf "  %s• Template:%s    %s\n" "$DIM" "$RESET" "$TEMPLATE"
printf "  %s• Author:%s      %s\n" "$DIM" "$RESET" "$AUTHOR"
printf "  %s• Description:%s %s\n" "$DIM" "$RESET" "$DESCRIPTION"
if [[ "$TARGET_FILE" = /* ]] || [[ "$TARGET_FILE" = ./* ]]; then
  RUN_HINT="$TARGET_FILE"
else
  RUN_HINT="./$TARGET_FILE"
fi
printf "\n%sRun it with:%s\n  %s --help\n\n" "$BOLD" "$RESET" "$RUN_HINT"

# ── Optional Editor Launch ────────────────────────────────────────────────────
if [ "$OPEN_EDITOR" -eq 1 ]; then
  EDITOR_CMD="${VISUAL:-${EDITOR:-}}"
  if [ -z "$EDITOR_CMD" ]; then
    if command -v code >/dev/null 2>&1; then
      EDITOR_CMD="code"
    elif command -v nano >/dev/null 2>&1; then
      EDITOR_CMD="nano"
    elif command -v vim >/dev/null 2>&1; then
      EDITOR_CMD="vim"
    fi
  fi

  if [ -n "$EDITOR_CMD" ]; then
    log_info "Opening in editor: ${EDITOR_CMD} ${TARGET_FILE}"
    exec $EDITOR_CMD "$TARGET_FILE"
  else
    log_warn "No editor found (\$VISUAL, \$EDITOR, code, nano, or vim). Skipped opening."
  fi
fi
