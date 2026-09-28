#!/usr/bin/env bash
#
# create-github-repo.sh — Interactive CLI tool to create a GitHub repository,
# configure it with SSH or HTTPS remotes, initialize Git (if needed), and optionally
# commit and push changes.
#
# Usage:
#   ./create-github-repo.sh [OPTIONS]
#
# Examples:
#   ./create-github-repo.sh
#   ./create-github-repo.sh -n "my-awesome-project" --private
#   ./create-github-repo.sh -n "org-tool" -o "my-org" -p
#   ./create-github-repo.sh --push -m "Initial release"
#
# Prerequisites:
#   - git (required)
#   - curl (required)
#   - ssh (optional, required only for SSH remotes)
#   - jq (optional, recommended; fallback parser included)
#   - GitHub SSH Key configured (if using SSH remotes)
#   - GitHub Personal Access Token (PAT) with 'repo' scope OR 'gh' CLI authenticated
#

set -euo pipefail

# ── Terminal & Color Support ──────────────────────────────────────────────────
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
log_step()    { printf "\n%s%s==> %s%s\n" "$BOLD" "$BLUE" "$*" "$RESET"; }
log_success() { printf "%s[OK]%s    %s\n" "$GREEN" "$RESET" "$*"; }
log_warn()    { printf "%s[WARN]%s  %s\n" "$YELLOW" "$RESET" "$*" >&2; }
log_error()   { printf "%s[ERROR]%s %s\n" "$RED" "$RESET" "$*" >&2; }
die()         { log_error "$*"; exit 1; }

# ── Cleanup Handler ───────────────────────────────────────────────────────────
cleanup() {
  # Restore terminal echo in case script aborted during hidden password prompt
  stty echo 2>/dev/null || true
  # Remove temp files if any were created
  if [ -n "${TEMP_DIR:-}" ] && [ -d "${TEMP_DIR:-}" ]; then
    rm -rf "$TEMP_DIR" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# Create temporary directory for API payloads / responses
TEMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'gh-repo-create.XXXXXX')"

# ── Default Configuration ─────────────────────────────────────────────────────
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/gh-repo-creator"
SAVED_TOKEN_FILE="$CONFIG_DIR/token"

REPO_NAME=""
REPO_DESC=""
IS_PRIVATE=true
ORG_NAME=""
DEFAULT_BRANCH="main"
BRANCH=""
REMOTE_NAME="origin"
COMMIT_MSG="Initial commit"
AUTO_PUSH=""
INTERACTIVE=true
TARGET_DIR="."
CLI_TOKEN=""

SSH_USER=""
SSH_AUTH_OK=false
AUTH_USER=""
USE_GH_CLI=false
USE_HTTPS=false
ACTIVE_TOKEN=""
OWNER=""
TARGET_BRANCH=""

# ── Help / Usage ──────────────────────────────────────────────────────────────
show_help() {
  cat <<EOF
${BOLD}Usage:${RESET} $(basename "$0") [OPTIONS]

Interactive wizard to create a GitHub repository, link it via SSH or HTTPS, initialize git,
and optionally push local commits.

${BOLD}Options:${RESET}
  -n, --name <name>         Repository name (defaults to sanitized directory name)
  -d, --desc <description>  Repository description
  -p, --public              Make repository public (default: private)
      --private             Make repository private (default)
  -o, --org <org>           Create repository under an Organization
  -b, --branch <branch>     Branch name to use (default: current or 'main')
  -r, --remote <name>       Git remote name (default: origin)
      --ssh                 Use SSH for git remote URL (default)
      --https               Use HTTPS for git remote URL
  -m, --message <msg>       Commit message if committing files (default: "Initial commit")
      --push                Automatically push to GitHub without prompting
      --no-push             Do not push to GitHub
      --dir <path>          Target directory to initialize (default: current directory)
      --token <token>       GitHub Personal Access Token (can also use \$GITHUB_TOKEN)
  -y, --yes                 Non-interactive mode (use defaults where possible)
  -h, --help                Show this help message and exit

${BOLD}Authentication:${RESET}
  The script can authenticate using either:
    1. GitHub CLI (\`gh\`) if installed and logged in (\`gh auth login\`)
    2. GitHub Personal Access Token (PAT) with 'repo' scope
       Create one at: https://github.com/settings/tokens
       Can be passed via --token, \$GITHUB_TOKEN, or saved locally in:
       $SAVED_TOKEN_FILE

${BOLD}Examples:${RESET}
  # Interactive wizard (recommended):
  $(basename "$0")

  # Create a private repo with custom description:
  $(basename "$0") -n "my-app" -d "NextGen Web Application"

  # Create a public repo in an organization and push immediately:
  $(basename "$0") -n "shared-utils" -o "acme-corp" --public --push

EOF
}

# ── Argument Parsing ──────────────────────────────────────────────────────────
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -n|--name)
        [[ $# -lt 2 ]] && die "Option $1 requires an argument."
        REPO_NAME="$2"; shift 2 ;;
      -d|--desc|--description)
        [[ $# -lt 2 ]] && die "Option $1 requires an argument."
        REPO_DESC="$2"; shift 2 ;;
      -p|--public)
        IS_PRIVATE=false; shift ;;
      --private)
        IS_PRIVATE=true; shift ;;
      -o|--org|--organization)
        [[ $# -lt 2 ]] && die "Option $1 requires an argument."
        ORG_NAME="$2"; shift 2 ;;
      -b|--branch)
        [[ $# -lt 2 ]] && die "Option $1 requires an argument."
        BRANCH="$2"; shift 2 ;;
      -r|--remote)
        [[ $# -lt 2 ]] && die "Option $1 requires an argument."
        REMOTE_NAME="$2"; shift 2 ;;
      --ssh)
        USE_HTTPS=false; shift ;;
      --https)
        USE_HTTPS=true; shift ;;
      -m|--message)
        [[ $# -lt 2 ]] && die "Option $1 requires an argument."
        COMMIT_MSG="$2"; shift 2 ;;
      --push)
        AUTO_PUSH=true; shift ;;
      --no-push)
        AUTO_PUSH=false; shift ;;
      --dir)
        [[ $# -lt 2 ]] && die "Option $1 requires an argument."
        TARGET_DIR="$2"; shift 2 ;;
      --token)
        [[ $# -lt 2 ]] && die "Option $1 requires an argument."
        CLI_TOKEN="$2"; shift 2 ;;
      -y|--yes)
        INTERACTIVE=false; shift ;;
      -h|--help)
        show_help; exit 0 ;;
      *)
        die "Unknown option: $1 (run with --help for usage)" ;;
    esac
  done
}

# ── Prompting Helpers ─────────────────────────────────────────────────────────
# Read input from /dev/tty if available so prompts work even if redirected
read_tty() {
  if [ -c /dev/tty ]; then
    read -r "$@" </dev/tty || true
  else
    read -r "$@" || true
  fi
}

# Read secret (silent echo) from /dev/tty
read_secret_tty() {
  if [ -c /dev/tty ]; then
    read -rs "$@" </dev/tty || true
  else
    stty -echo 2>/dev/null || true
    read -r "$@" || true
    stty echo 2>/dev/null || true
  fi
  printf "\n"
}

prompt_input() {
  local prompt_text="$1"
  local default_val="${2:-}"
  local var_name="$3"
  local user_input=""

  if [ "$INTERACTIVE" = false ] && [ -n "$default_val" ]; then
    printf -v "$var_name" '%s' "$default_val"
    return 0
  fi

  if [ -n "$default_val" ]; then
    printf "%s%s [%s%s%s]: %s" "$BOLD" "$prompt_text" "$CYAN" "$default_val" "$BOLD" "$RESET"
  else
    printf "%s%s: %s" "$BOLD" "$prompt_text" "$RESET"
  fi

  read_tty user_input
  if [ -z "$user_input" ]; then
    printf -v "$var_name" '%s' "$default_val"
  else
    printf -v "$var_name" '%s' "$user_input"
  fi
}

prompt_confirm() {
  local prompt_text="$1"
  local default_choice="${2:-Y}" # Y or N
  local choice=""

  if [ "$INTERACTIVE" = false ]; then
    [[ "$default_choice" =~ ^[Yy]$ ]] && return 0 || return 1
  fi

  local options_hint="[Y/n]"
  [[ "$default_choice" =~ ^[Nn]$ ]] && options_hint="[y/N]"

  while true; do
    printf "%s%s %s: %s" "$BOLD" "$prompt_text" "$options_hint" "$RESET"
    read_tty choice
    choice="${choice:-$default_choice}"
    case "$choice" in
      [Yy]|[Yy][Ee][Ss]) return 0 ;;
      [Nn]|[Nn][Oo])   return 1 ;;
      *) printf "Please enter 'y' or 'n'.\n" ;;
    esac
  done
}

# Sets variable $1 to the 0-based selected index
prompt_choice() {
  local var_name="$1"
  local prompt_text="$2"
  local default_idx="$3"
  shift 3
  local options=("$@")
  local choice=""

  printf "%s%s%s\n" "$BOLD" "$prompt_text" "$RESET"
  for i in "${!options[@]}"; do
    local idx=$((i + 1))
    if [ "$idx" -eq "$default_idx" ]; then
      printf "  %s[%d]%s %s %s(default)%s\n" "$CYAN" "$idx" "$RESET" "${options[$i]}" "$DIM" "$RESET"
    else
      printf "  [%d] %s\n" "$idx" "${options[$i]}"
    fi
  done

  if [ "$INTERACTIVE" = false ]; then
    printf -v "$var_name" '%d' "$((default_idx - 1))"
    return 0
  fi

  while true; do
    printf "%sEnter selection [1-%d, default: %d]: %s" "$BOLD" "${#options[@]}" "$default_idx" "$RESET"
    read_tty choice
    choice="${choice:-$default_idx}"
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#options[@]}" ]; then
      printf -v "$var_name" '%d' "$((choice - 1))"
      return 0
    fi
    printf "Invalid selection. Please choose a number between 1 and %d.\n" "${#options[@]}"
  done
}

# ── Dependency Checks ─────────────────────────────────────────────────────────
check_dependencies() {
  log_info "Checking essential dependencies..."
  local missing=()
  for cmd in git curl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done
  if [ "$USE_HTTPS" = false ] && ! command -v ssh >/dev/null 2>&1; then
    missing+=("ssh")
  fi

  if [ ${#missing[@]} -gt 0 ]; then
    die "Missing required command(s): ${missing[*]}. Please install them before proceeding."
  fi

  if ! command -v jq >/dev/null 2>&1; then
    log_warn "'jq' is not installed. JSON responses will be parsed using native shell fallback."
  fi
}

# ── SSH Authentication Check ──────────────────────────────────────────────────
check_ssh_auth() {
  if [ "$USE_HTTPS" = true ]; then
    log_info "Using HTTPS for remote operations (SSH check skipped)."
    return 0
  fi

  log_step "Step 1: Checking SSH Connection to GitHub"
  log_info "Testing SSH authentication with git@github.com..."

  local ssh_out=""
  # GitHub returns exit code 1 with "Hi <user>! You've successfully authenticated"
  ssh_out="$(ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -T git@github.com 2>&1 || true)"

  if printf "%s" "$ssh_out" | grep -qi "successfully authenticated"; then
    SSH_AUTH_OK=true
    SSH_USER="$(printf "%s" "$ssh_out" | sed -E -n 's/.*Hi ([^!]+)!.*/\1/p' | tr -d ' ')"
    log_success "GitHub SSH authentication verified! Logged in as: ${BOLD}@${SSH_USER}${RESET}"
  else
    SSH_AUTH_OK=false
    log_warn "Could not authenticate to GitHub over SSH."
    printf "\n%sDiagnostic output from SSH:%s\n" "$DIM" "$RESET"
    printf "%s%s%s\n\n" "$DIM" "$ssh_out" "$RESET"

    printf "%sSSH Setup Tips:%s\n" "$YELLOW" "$RESET"
    printf "  1. Verify an SSH key exists: %s\n" "ls -la ~/.ssh/id_ed25519.pub ~/.ssh/id_rsa.pub 2>/dev/null"
    printf "  2. If missing, generate one: %s\n" "ssh-keygen -t ed25519 -C \"your_email@example.com\""
    printf "  3. Add your public key to GitHub: %s\n" "https://github.com/settings/keys"
    printf "  4. Ensure your key is loaded in agent: %s\n\n" "eval \$(ssh-agent -s) && ssh-add ~/.ssh/id_ed25519"

    if [ "$INTERACTIVE" = true ]; then
      local auth_fail_choices=(
        "Switch remote protocol to HTTPS (Recommended)"
        "Continue with SSH anyway (SSH push may fail if keys are not ready)"
        "Abort to configure SSH keys"
      )
      local fail_choice=0
      prompt_choice fail_choice "How would you like to handle Git remote connection?" 1 "${auth_fail_choices[@]}"
      case "$fail_choice" in
        0)
          USE_HTTPS=true
          log_info "Remote protocol set to HTTPS."
          ;;
        1)
          USE_HTTPS=false
          log_warn "Continuing with SSH remote."
          ;;
        2)
          die "Aborted by user to configure SSH."
          ;;
      esac
    fi
  fi
}

# ── GitHub Token & Authentication ─────────────────────────────────────────────
clean_token() {
  local tok="$1"
  tok="${tok#Bearer }"
  tok="${tok#bearer }"
  tok="${tok#BEARER }"
  tok="${tok#token }"
  tok="${tok#TOKEN }"
  tok="$(printf '%s' "$tok" | tr -d "[:space:]\"'")"
  printf '%s' "$tok"
}

# Simple JSON string extractor fallback when jq is absent
extract_json_field() {
  local json="$1"
  local key="$2"
  if command -v jq >/dev/null 2>&1; then
    printf "%s" "$json" | jq -r --arg k "$key" '.[$k] // empty' 2>/dev/null || true
  else
    printf "%s" "$json" | grep -o "\"$key\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -n1 | sed -E "s/\"$key\"[[:space:]]*:[[:space:]]*\"([^\"]*)\"/\1/"
  fi
}

verify_github_token() {
  local token="$1"
  token="$(clean_token "$token")"
  [ -z "$token" ] && return 1

  local res_file="$TEMP_DIR/user.json"
  local curl_err="$TEMP_DIR/curl_user.log"
  local http_code=""

  http_code=$(curl -sS -w "%{http_code}" -o "$res_file" \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer $token" \
    -H "User-Agent: gh-repo-creator" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/user" 2>"$curl_err" || true)

  http_code="${http_code: -3}"

  if [ "$http_code" = "200" ]; then
    AUTH_USER=$(extract_json_field "$(cat "$res_file" 2>/dev/null || true)" "login")
    return 0
  else
    if [ "$http_code" = "000" ] || [ -z "$http_code" ]; then
      log_warn "Network connection failed while verifying token."
      [ -s "$curl_err" ] && cat "$curl_err" >&2
    elif [ "$http_code" = "401" ]; then
      log_warn "GitHub token rejected (HTTP 401 Unauthorized): Invalid or expired token."
    elif [ "$http_code" = "403" ]; then
      log_warn "GitHub token lacks permissions or exceeded rate limit (HTTP 403 Forbidden)."
    else
      log_warn "GitHub API returned HTTP $http_code while verifying token."
    fi
    return 1
  fi
}

resolve_authentication() {
  log_step "Step 2: GitHub API Authentication"

  # Check if GitHub CLI (gh) is available and authenticated
  if command -v gh >/dev/null 2>&1; then
    if gh auth status >/dev/null 2>&1; then
      local gh_user=""
      gh_user="$(gh api user -q .login 2>/dev/null || true)"
      if [ -n "$gh_user" ]; then
        log_info "Found authenticated GitHub CLI (gh) account: ${BOLD}@${gh_user}${RESET}"
        if [ "$INTERACTIVE" = true ]; then
          if prompt_confirm "Use GitHub CLI (gh) for repository creation?" "Y"; then
            USE_GH_CLI=true
            AUTH_USER="$gh_user"
            return 0
          fi
        else
          USE_GH_CLI=true
          AUTH_USER="$gh_user"
          return 0
        fi
      fi
    fi
  fi

  # Check CLI argument or environment token
  local token="${CLI_TOKEN:-${GITHUB_TOKEN:-}}"
  token="$(clean_token "$token")"

  # Check saved token file
  if [ -z "$token" ] && [ -f "$SAVED_TOKEN_FILE" ]; then
    token="$(head -n 1 "$SAVED_TOKEN_FILE" | tr -d '[:space:]')"
    token="$(clean_token "$token")"
    if [ -n "$token" ]; then
      log_info "Found saved GitHub token in ${SAVED_TOKEN_FILE}"
    fi
  fi

  # Validate existing token if found
  if [ -n "$token" ]; then
    log_info "Validating GitHub token..."
    if verify_github_token "$token"; then
      log_success "Authenticated as GitHub user: ${BOLD}@${AUTH_USER}${RESET}"
      ACTIVE_TOKEN="$token"
      return 0
    else
      log_warn "Provided GitHub token is invalid, expired, or cannot connect to GitHub."
      token=""
    fi
  fi

  # Interactive prompt for token if not authenticated
  if [ -z "$token" ]; then
    if [ "$INTERACTIVE" = false ]; then
      die "No valid GitHub token or GitHub CLI authentication found. Pass --token or set \$GITHUB_TOKEN."
    fi

    printf "\n%sGitHub Personal Access Token (PAT) Required%s\n" "$BOLD" "$RESET"
    printf "To create repositories, a Classic token with %s'repo'%s scope is recommended.\n" "$CYAN" "$RESET"
    printf "Create one here: %shttps://github.com/settings/tokens/new?scopes=repo&description=create-github-repo-cli%s\n" "$CYAN" "$RESET"
    printf "%sNote:%s If using a Fine-Grained PAT, ensure it has 'Administration: Read and write' and access to All Repositories.\n\n" "$YELLOW" "$RESET"

    while true; do
      printf "%sEnter your GitHub Personal Access Token:%s " "$BOLD" "$RESET"
      read_secret_tty token
      token="$(clean_token "$token")"

      if [ -z "$token" ]; then
        log_warn "Token cannot be empty."
        continue
      fi

      log_info "Verifying token with GitHub API..."
      if verify_github_token "$token"; then
        log_success "Authentication successful! Logged in as: ${BOLD}@${AUTH_USER}${RESET}"
        ACTIVE_TOKEN="$token"
        break
      else
        log_error "Token validation failed. Please check token permissions and try again."
        if ! prompt_confirm "Retry entering token?" "Y"; then
          die "Authentication aborted by user."
        fi
      fi
    done

    # Offer to save token securely
    if prompt_confirm "Save this token in $SAVED_TOKEN_FILE (permissions 0600) for future use?" "Y"; then
      mkdir -p "$CONFIG_DIR"
      chmod 700 "$CONFIG_DIR" 2>/dev/null || true
      printf "%s\n" "$ACTIVE_TOKEN" > "$SAVED_TOKEN_FILE"
      chmod 600 "$SAVED_TOKEN_FILE" 2>/dev/null || true
      log_success "Token saved securely."
    fi
  fi
}

# ── Local Git Inspection & Initialization ─────────────────────────────────────
sanitize_repo_name() {
  local name="$1"
  name="${name#@}"
  # Replace spaces and punctuation with hyphens, lowercase, remove invalid chars
  name="$(printf "%s" "$name" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd '[:alnum:]-_.')"
  name="$(printf "%s" "$name" | sed -E 's/^-+//; s/-+$//')"
  printf "%s" "$name"
}

setup_local_git() {
  log_step "Step 3: Local Git Repository Setup"

  # Move into target directory if specified
  if [ "$TARGET_DIR" != "." ]; then
    if [ ! -d "$TARGET_DIR" ]; then
      log_info "Target directory '$TARGET_DIR' does not exist. Creating it..."
      mkdir -p "$TARGET_DIR"
    fi
    cd "$TARGET_DIR"
  fi

  local current_dir_name
  current_dir_name="$(basename "$PWD")"
  local default_repo_name
  default_repo_name="$(sanitize_repo_name "$current_dir_name")"
  [ -z "$default_repo_name" ] && default_repo_name="my-project"

  # Detect if inside a git repository
  local is_git_repo=false
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    is_git_repo=true
    log_info "Current directory is already a Git repository."
  else
    log_warn "Current directory is not a Git repository."
    if [ "$INTERACTIVE" = true ]; then
      if prompt_confirm "Initialize a new Git repository here ($PWD)?" "Y"; then
        git init -b "$DEFAULT_BRANCH" 2>/dev/null || {
          git init
          git checkout -B "$DEFAULT_BRANCH" 2>/dev/null || true
        }
        is_git_repo=true
        log_success "Initialized empty Git repository."
      else
        die "Cannot proceed without a Git repository."
      fi
    else
      git init -b "$DEFAULT_BRANCH" 2>/dev/null || {
        git init
        git checkout -B "$DEFAULT_BRANCH" 2>/dev/null || true
      }
      is_git_repo=true
      log_success "Initialized empty Git repository."
    fi
  fi

  # Suggest starter .gitignore if none exists
  if [ ! -f .gitignore ]; then
    local create_gi=false
    if [ "$INTERACTIVE" = true ]; then
      if prompt_confirm "No .gitignore found. Create a standard starter .gitignore?" "Y"; then
        create_gi=true
      fi
    fi
    if [ "$create_gi" = true ]; then
      cat << 'GITIGNORE' > .gitignore
# Operating System
.DS_Store
Thumbs.db

# Environment & secrets
.env
.env*.local
*.pem
*.key

# Logs & temp
*.log
*.tmp
*.bak

# Dependencies & Build artifacts
node_modules/
dist/
build/
bin/
__pycache__/
*.py[cod]
.venv/
env/
GITIGNORE
      log_success "Created starter .gitignore"
    fi
  fi

  # Check & determine branch
  local detected_branch=""
  detected_branch="$(git branch --show-current 2>/dev/null || git symbolic-ref --short HEAD 2>/dev/null || echo "")"
  if [ -z "$detected_branch" ]; then
    detected_branch="$DEFAULT_BRANCH"
  fi

  if [ -n "$BRANCH" ]; then
    TARGET_BRANCH="$BRANCH"
    if [ "$TARGET_BRANCH" != "$detected_branch" ]; then
      git checkout -B "$TARGET_BRANCH" 2>/dev/null || true
    fi
  else
    TARGET_BRANCH="$detected_branch"
  fi
  log_info "Active Git branch: ${BOLD}${TARGET_BRANCH}${RESET}"

  # Default repo name resolution
  if [ -z "$REPO_NAME" ]; then
    if [ "$INTERACTIVE" = true ]; then
      prompt_input "GitHub repository name" "$default_repo_name" REPO_NAME
    else
      REPO_NAME="$default_repo_name"
    fi
  fi

  REPO_NAME="$(sanitize_repo_name "$REPO_NAME")"
  if [ -z "$REPO_NAME" ]; then
    die "Repository name cannot be empty."
  fi
}

# ── Repository Configuration Prompts ──────────────────────────────────────────
configure_repo_metadata() {
  log_step "Step 4: Repository Details"

  # Determine default personal owner
  local default_personal="${AUTH_USER:-${SSH_USER:-}}"
  default_personal="${default_personal#@}"

  if [ -n "$ORG_NAME" ]; then
    # Passed via CLI argument
    ORG_NAME="${ORG_NAME#@}"
    if [ -n "$default_personal" ] && [ "$ORG_NAME" = "$default_personal" ]; then
      # User passed their personal username as --org
      ORG_NAME=""
      OWNER="$default_personal"
    else
      OWNER="$ORG_NAME"
    fi
  elif [ "$INTERACTIVE" = true ]; then
    local owner_choices=()
    if [ -n "$default_personal" ]; then
      owner_choices+=("Personal account (@$default_personal)" "An Organization")
    else
      owner_choices+=("Personal account" "An Organization")
    fi

    local owner_type=0
    prompt_choice owner_type "Where should the repository be created?" 1 "${owner_choices[@]}"

    if [ "$owner_type" -eq 1 ]; then
      # Organization
      local org_input=""
      while true; do
        prompt_input "Enter Organization name" "" org_input
        org_input="${org_input#@}"
        org_input="$(printf '%s' "$org_input" | tr -d '[:space:]')"
        if [ -n "$org_input" ]; then
          if [ -n "$default_personal" ] && [ "$org_input" = "$default_personal" ]; then
            log_warn "'@$org_input' is your personal account, not an organization. Creating as personal repository."
            ORG_NAME=""
            OWNER="$default_personal"
          else
            ORG_NAME="$org_input"
            OWNER="$ORG_NAME"
          fi
          break
        fi
        log_warn "Organization name cannot be empty."
      done
    else
      # Personal account
      ORG_NAME=""
      if [ -n "$default_personal" ]; then
        OWNER="$default_personal"
      else
        local user_input=""
        while true; do
          prompt_input "Enter your GitHub username" "" user_input
          user_input="${user_input#@}"
          user_input="$(printf '%s' "$user_input" | tr -d '[:space:]')"
          if [ -n "$user_input" ]; then
            OWNER="$user_input"
            AUTH_USER="$user_input"
            break
          fi
          log_warn "Username cannot be empty."
        done
      fi
    fi
  else
    # Non-interactive without --org
    ORG_NAME=""
    OWNER="${default_personal:-}"
    if [ -z "$OWNER" ]; then
      die "Cannot determine repository owner in non-interactive mode. Pass -o/--org or authenticate with GitHub."
    fi
  fi

  # Description
  if [ -z "$REPO_DESC" ] && [ "$INTERACTIVE" = true ]; then
    prompt_input "Repository description (optional)" "" REPO_DESC
  fi

  # Visibility
  if [ "$INTERACTIVE" = true ]; then
    local vis_options=("Private (restricted access)" "Public (visible to everyone)")
    local default_vis_idx=1
    [ "$IS_PRIVATE" = false ] && default_vis_idx=2
    local vis_choice=0
    prompt_choice vis_choice "Select repository visibility:" "$default_vis_idx" "${vis_options[@]}"
    if [ "$vis_choice" -eq 1 ]; then
      IS_PRIVATE=false
    else
      IS_PRIVATE=true
    fi
  fi

  local target_url=""
  if [ "$USE_HTTPS" = true ]; then
    target_url="https://github.com/${OWNER}/${REPO_NAME}.git"
  else
    target_url="git@github.com:${OWNER}/${REPO_NAME}.git"
  fi

  printf "\n%sSummary of repository to create:%s\n" "$BOLD" "$RESET"
  printf "  • Name:        %s%s%s\n" "$BOLD" "$REPO_NAME" "$RESET"
  printf "  • Owner:       %s%s%s%s\n" "$CYAN" "$OWNER" "$([ -n "$ORG_NAME" ] && echo " (Organization)" || echo " (Personal)")" "$RESET"
  printf "  • Visibility:  %s%s%s\n" "$YELLOW" "$([ "$IS_PRIVATE" = true ] && echo "Private" || echo "Public")" "$RESET"
  [ -n "$REPO_DESC" ] && printf "  • Description: %s\n" "$REPO_DESC"
  printf "  • Remote URL:  %s%s%s\n\n" "$CYAN" "$target_url" "$RESET"

  if [ "$INTERACTIVE" = true ]; then
    if ! prompt_confirm "Create this repository on GitHub now?" "Y"; then
      die "Aborted by user."
    fi
  fi
}

# ── Create Repository on GitHub ───────────────────────────────────────────────
create_remote_repo() {
  log_step "Step 5: Creating GitHub Repository"

  local visibility_flag="private"
  [ "$IS_PRIVATE" = false ] && visibility_flag="public"

  # Path A: Using GitHub CLI if selected
  if [ "$USE_GH_CLI" = true ]; then
    log_info "Creating repository via GitHub CLI (gh)..."
    local gh_args=("$OWNER/$REPO_NAME" "--$visibility_flag")
    [ -n "$REPO_DESC" ] && gh_args+=("--description" "$REPO_DESC")
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      gh_args+=("--source=." "--remote=$REMOTE_NAME")
    fi

    if gh repo create "${gh_args[@]}"; then
      log_success "GitHub repository created successfully via gh CLI!"
      return 0
    else
      die "Failed to create repository with gh CLI."
    fi
  fi

  # Path B: Using GitHub REST API via curl
  local api_url="https://api.github.com/user/repos"
  if [ -n "$ORG_NAME" ]; then
    api_url="https://api.github.com/orgs/$ORG_NAME/repos"
  fi

  local payload=""
  if command -v jq >/dev/null 2>&1; then
    payload=$(jq -n \
      --arg name "$REPO_NAME" \
      --arg desc "$REPO_DESC" \
      --argjson priv "$IS_PRIVATE" \
      '{name: $name, description: $desc, private: $priv, auto_init: false}')
  else
    local escaped_desc
    escaped_desc=$(printf '%s' "$REPO_DESC" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\n' ' ')
    payload="{\"name\":\"$REPO_NAME\",\"description\":\"$escaped_desc\",\"private\":$IS_PRIVATE,\"auto_init\":false}"
  fi

  log_info "Sending creation request to GitHub API ($api_url)..."
  local res_file="$TEMP_DIR/create_res.json"
  local curl_err="$TEMP_DIR/curl_create.log"
  local http_code=""

  http_code=$(curl -sS -w "%{http_code}" -o "$res_file" -X POST \
    -H "Accept: application/vnd.github+json" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ACTIVE_TOKEN" \
    -H "User-Agent: gh-repo-creator" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -d "$payload" \
    "$api_url" 2>"$curl_err" || true)

  http_code="${http_code: -3}"

  if [ "$http_code" = "201" ]; then
    log_success "GitHub repository created successfully: ${BOLD}https://github.com/$OWNER/$REPO_NAME${RESET}"
  elif [ "$http_code" = "422" ]; then
    local err_msg=""
    if command -v jq >/dev/null 2>&1; then
      err_msg=$(jq -r '(.errors[].message // .message) // empty' "$res_file" 2>/dev/null | head -n1 || true)
    fi
    [ -z "$err_msg" ] && err_msg=$(extract_json_field "$(cat "$res_file" 2>/dev/null || true)" "message")
    [ -z "$err_msg" ] && err_msg="Unprocessable entity"

    log_warn "GitHub responded with 422: ${err_msg}"
    printf "%sThe repository '%s/%s' might already exist or the name is invalid.%s\n" "$YELLOW" "$OWNER" "$REPO_NAME" "$RESET"

    if [ "$INTERACTIVE" = true ]; then
      if prompt_confirm "Do you want to link the existing repository '$OWNER/$REPO_NAME' anyway?" "Y"; then
        log_info "Proceeding with existing repository..."
      else
        die "Aborted. Please choose a different repository name."
      fi
    else
      log_info "Non-interactive mode: proceeding with existing repository link..."
    fi
  elif [ "$http_code" = "000" ] || [ -z "$http_code" ]; then
    log_error "Network connection failed. Could not reach GitHub API."
    if [ -f "$curl_err" ] && [ -s "$curl_err" ]; then
      cat "$curl_err" >&2
    fi
    die "Please verify your internet connection or proxy settings."
  elif [ "$http_code" = "401" ]; then
    log_error "Authentication failed (HTTP 401 Unauthorized)."
    log_error "Your GitHub token is invalid, expired, or revoked."
    die "Please update your token via --token or in $SAVED_TOKEN_FILE."
  elif [ "$http_code" = "403" ]; then
    local error_body
    error_body=$(cat "$res_file" 2>/dev/null || cat "$curl_err" 2>/dev/null || echo "Forbidden")
    log_error "Permission denied (HTTP 403 Forbidden):"
    printf "%s\n" "$error_body" >&2
    log_warn "Troubleshooting tips:"
    log_warn "  1. If using a Classic PAT, ensure it has the 'repo' scope."
    log_warn "  2. If using a Fine-Grained PAT, ensure it has 'Administration: Read and write' permissions and access to All Repositories."
    log_warn "  3. If creating under an organization, ensure your account has permission to create repositories in @$OWNER."
    die "Failed to create GitHub repository due to permissions."
  elif [ "$http_code" = "404" ]; then
    local error_body
    error_body=$(cat "$res_file" 2>/dev/null || cat "$curl_err" 2>/dev/null || echo "Not Found")
    log_error "Endpoint not found (HTTP 404):"
    printf "%s\n" "$error_body" >&2
    if [ -n "$ORG_NAME" ]; then
      log_warn "GitHub Organization '@$ORG_NAME' was not found or your token does not have access to it."
    fi
    die "Failed to create GitHub repository."
  else
    local error_body
    error_body=$(cat "$res_file" 2>/dev/null || cat "$curl_err" 2>/dev/null || echo "Unknown error")
    log_error "GitHub API error (HTTP $http_code):"
    printf "%s\n" "$error_body" >&2
    die "Failed to create GitHub repository."
  fi
}

# ── Configure Remote URL (SSH / HTTPS) ────────────────────────────────────────
setup_git_remote() {
  log_step "Step 6: Configuring Git Remote"

  local target_url=""
  if [ "$USE_HTTPS" = true ]; then
    target_url="https://github.com/${OWNER}/${REPO_NAME}.git"
  else
    target_url="git@github.com:${OWNER}/${REPO_NAME}.git"
  fi

  log_info "Target Remote URL: ${BOLD}${target_url}${RESET}"

  local existing_url=""
  existing_url="$(git remote get-url "$REMOTE_NAME" 2>/dev/null || true)"

  if [ -n "$existing_url" ]; then
    if [ "$existing_url" = "$target_url" ]; then
      log_success "Remote '$REMOTE_NAME' is already configured correctly: $target_url"
    else
      log_warn "Remote '$REMOTE_NAME' already exists and points to: $existing_url"
      if [ "$INTERACTIVE" = true ]; then
        local choices=(
          "Update remote '$REMOTE_NAME' to: $target_url"
          "Keep existing remote and add a new remote (e.g. 'github')"
          "Cancel remote configuration"
        )
        local rem_choice=0
        prompt_choice rem_choice "How would you like to handle the existing remote?" 1 "${choices[@]}"
        case "$rem_choice" in
          0)
            git remote set-url "$REMOTE_NAME" "$target_url"
            log_success "Updated remote '$REMOTE_NAME' to $target_url"
            ;;
          1)
            prompt_input "Enter new remote name" "github" REMOTE_NAME
            git remote add "$REMOTE_NAME" "$target_url"
            log_success "Added remote '$REMOTE_NAME' with $target_url"
            ;;
          2)
            log_warn "Skipped remote configuration."
            ;;
        esac
      else
        git remote set-url "$REMOTE_NAME" "$target_url"
        log_success "Updated remote '$REMOTE_NAME' to $target_url"
      fi
    fi
  else
    git remote add "$REMOTE_NAME" "$target_url"
    log_success "Added remote '$REMOTE_NAME' -> $target_url"
  fi
}

# ── Commit and Push Changes ───────────────────────────────────────────────────
handle_commit_and_push() {
  log_step "Step 7: Commit & Push Changes (Optional)"

  # Ensure user.name and user.email are set in git config
  local git_user git_email
  git_user="$(git config user.name 2>/dev/null || true)"
  git_email="$(git config user.email 2>/dev/null || true)"
  if [ -z "$git_user" ] || [ -z "$git_email" ]; then
    log_warn "Git user name/email not configured."
    if [ "$INTERACTIVE" = true ]; then
      prompt_input "Git commit user.name" "${AUTH_USER:-User}" git_user
      prompt_input "Git commit user.email" "${AUTH_USER:-user}@users.noreply.github.com" git_email
      git config user.name "$git_user"
      git config user.email "$git_email"
      log_success "Configured local git identity."
    fi
  fi

  # Check if directory has commits
  local has_commits=false
  if git rev-parse --verify HEAD >/dev/null 2>&1; then
    has_commits=true
  fi

  local git_status
  git_status="$(git status --porcelain 2>/dev/null || true)"

  # If repo is empty with no files and no commits, offer to create README.md
  local file_count
  file_count="$(find . -maxdepth 1 -not -name '.git' -not -name '.' | wc -l)"
  if [ "$file_count" -eq 0 ] && [ "$has_commits" = false ]; then
    log_info "The directory is empty (no files found)."
    local create_readme=false
    if [ "$INTERACTIVE" = true ]; then
      if prompt_confirm "Create an initial README.md?" "Y"; then
        create_readme=true
      fi
    else
      create_readme=true
    fi
    if [ "$create_readme" = true ]; then
      printf "# %s\n\n%s\n" "$REPO_NAME" "${REPO_DESC:-A new repository created with create-github-repo.sh}" > README.md
      log_success "Created README.md"
      git_status="$(git status --porcelain 2>/dev/null || true)"
    fi
  fi

  # Stage and commit uncommitted changes if present
  if [ -n "$git_status" ]; then
    printf "\n%sUncommitted changes detected in working tree:%s\n" "$BOLD" "$RESET"
    git status --short
    printf "\n"

    local do_commit=false
    if [ "$INTERACTIVE" = true ]; then
      if prompt_confirm "Stage all files and commit now?" "Y"; then
        do_commit=true
        prompt_input "Commit message" "$COMMIT_MSG" COMMIT_MSG
      fi
    else
      do_commit=true
    fi

    if [ "$do_commit" = true ]; then
      log_info "Staging files..."
      git add -A
      git commit -m "$COMMIT_MSG"
      log_success "Committed changes: '${COMMIT_MSG}'"
      has_commits=true
    fi
  elif [ "$has_commits" = true ]; then
    log_info "Working tree clean. Existing commits ready on branch '${TARGET_BRANCH}'."
  else
    log_info "No files or commits to stage."
  fi

  # Push to GitHub
  local do_push=false
  if [ -n "$AUTO_PUSH" ]; then
    do_push="$AUTO_PUSH"
  elif [ "$INTERACTIVE" = true ] && [ "$has_commits" = true ]; then
    local proto_label="SSH"
    [ "$USE_HTTPS" = true ] && proto_label="HTTPS"
    if prompt_confirm "Push branch '${TARGET_BRANCH}' to '${REMOTE_NAME}' via ${proto_label} now?" "Y"; then
      do_push=true
    fi
  fi

  if [ "$do_push" = true ]; then
    if [ "$has_commits" = false ]; then
      log_warn "Nothing to push (no commits exist yet). Create a file and commit first."
    else
      local remote_url_disp
      remote_url_disp="$(git remote get-url "$REMOTE_NAME" 2>/dev/null || echo "remote")"
      log_info "Pushing ${TARGET_BRANCH} to ${REMOTE_NAME} (${remote_url_disp})..."
      if git push -u "$REMOTE_NAME" "$TARGET_BRANCH"; then
        log_success "Pushed successfully to GitHub!"
      else
        log_error "Push failed. Check remote URL, credentials/keys, permissions, or network connectivity."
        printf "You can retry pushing anytime with: %s\n" "${BOLD}git push -u $REMOTE_NAME $TARGET_BRANCH${RESET}"
      fi
    fi
  else
    printf "\n%sPush skipped.%s When ready, push changes using:\n" "$DIM" "$RESET"
    printf "  %s%sgit push -u %s %s%s\n\n" "$BOLD" "$CYAN" "$REMOTE_NAME" "$TARGET_BRANCH" "$RESET"
  fi
}

# ── Summary Display ───────────────────────────────────────────────────────────
display_summary() {
  local remote_url_disp
  remote_url_disp="$(git remote get-url "$REMOTE_NAME" 2>/dev/null || echo "git@github.com:${OWNER}/${REPO_NAME}.git")"

  printf "\n"
  printf "%s╔══════════════════════════════════════════════════════════════════════════════╗%s\n" "$GREEN" "$RESET"
  printf "%s║                    GitHub Repository Setup Complete!                         ║%s\n" "$GREEN" "$RESET"
  printf "%s╚══════════════════════════════════════════════════════════════════════════════╝%s\n" "$GREEN" "$RESET"
  printf "  %s• Repository:%s    %s/%s\n" "$BOLD" "$RESET" "$OWNER" "$REPO_NAME"
  printf "  %s• Web URL:%s       https://github.com/%s/%s\n" "$BOLD" "$RESET" "$OWNER" "$REPO_NAME"
  printf "  %s• Remote URL:%s    %s\n" "$BOLD" "$RESET" "$remote_url_disp"
  printf "  %s• Branch:%s        %s\n" "$BOLD" "$RESET" "$TARGET_BRANCH"
  printf "  %s• Visibility:%s    %s\n" "$BOLD" "$RESET" "$([ "$IS_PRIVATE" = true ] && echo "Private" || echo "Public")"
  printf "\n"
}

# ── Main Entrypoint ───────────────────────────────────────────────────────────
main() {
  parse_args "$@"

  printf "\n%s%s╭──────────────────────────────────────────────────────────╮%s\n" "$BOLD" "$CYAN" "$RESET"
  printf "%s%s│          GitHub Repository Creator & Setup               │%s\n" "$BOLD" "$CYAN" "$RESET"
  printf "%s%s╰──────────────────────────────────────────────────────────╯%s\n\n" "$BOLD" "$CYAN" "$RESET"

  check_dependencies
  check_ssh_auth
  resolve_authentication
  setup_local_git
  configure_repo_metadata
  create_remote_repo
  setup_git_remote
  handle_commit_and_push
  display_summary
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
