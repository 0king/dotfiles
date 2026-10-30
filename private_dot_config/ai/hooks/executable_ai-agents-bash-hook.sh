#!/usr/bin/env bash
# ==============================================================================
# ai-agents-bash-hook.sh
# Universal non-interactive Bash execution interceptor for AI coding agents:
# Kilo, Cline, Copilot, Antigravity, OpenCode, Aider, Pi, Dsh.
#
# Intercepts: commands invoked via `bash -c "<cmd>"`
# Ignores: normal interactive user terminals (0ms overhead)
# ==============================================================================

# 1. Guard against recursive hook execution
if [ -n "${_AI_HOOK_ACTIVE:-}" ]; then
  return 0 2>/dev/null || exit 0
fi

# 2. Only intercept non-interactive command string invocations
if [ -z "${BASH_EXECUTION_STRING:-}" ]; then
  return 0 2>/dev/null || exit 0
fi

# 3. Detect if parent process ancestry contains an AI agent
_ai_p=$PPID
_ai_agent=""

for _ in {1..8}; do
  [ -z "$_ai_p" ] || [ "$_ai_p" -le 1 ] && break
  comm=$(cat "/proc/$_ai_p/comm" 2>/dev/null || true)
  cmd=$(tr '\0' ' ' < "/proc/$_ai_p/cmdline" 2>/dev/null || true)

  case "$comm" in
    antigravity) _ai_agent="antigravity"; break ;;
    opencode) _ai_agent="opencode"; break ;;
    kilo) _ai_agent="kilo"; break ;;
    cline) _ai_agent="cline"; break ;;
    aider) _ai_agent="aider"; break ;;
    copilot) _ai_agent="copilot"; break ;;
    pi) _ai_agent="pi"; break ;;
    dsh) _ai_agent="dsh"; break ;;
  esac

  case "$cmd" in
    *antigravity*|*language_server*override_ide_name*antigravity*) _ai_agent="antigravity"; break ;;
    *opencode*) _ai_agent="opencode"; break ;;
    *kilo*) _ai_agent="kilo"; break ;;
    *roo-cline*|*cline*) _ai_agent="cline"; break ;;
    *github-copilot*|*copilot*) _ai_agent="copilot"; break ;;
    *aider*) _ai_agent="aider"; break ;;
    *" bin/pi "*|*" /pi "*|*" pi.js"*) _ai_agent="pi"; break ;;
    *" bin/dsh "*|*" /dsh "*) _ai_agent="dsh"; break ;;
  esac

  _ai_p=$(awk '{print $4}' "/proc/$_ai_p/stat" 2>/dev/null || true)
done

# If no AI agent is in the process tree, exit immediately
if [ -z "$_ai_agent" ]; then
  return 0 2>/dev/null || exit 0
fi

# Mark active to avoid recursion
export _AI_HOOK_ACTIVE=1
_ai_cmd="$BASH_EXECUTION_STRING"
_ai_cwd="$PWD"
_ai_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
_ai_out_file="/tmp/.ai_agent_out_${$}_${RANDOM}.tmp"

# Intercept stdout and stderr while passing them to original descriptors
exec 3>&1 4>&2
exec > >(tee "$_ai_out_file" >&3) 2> >(tee -a "$_ai_out_file" >&4)

_ai_on_exit() {
  local rc=$?
  # Restore original file descriptors
  exec 1>&3 2>&4 3>&- 4>&- 2>/dev/null || true

  # Record entry asynchronously in background
  (
    # Allow tee pipe buffer to flush
    sleep 0.05 2>/dev/null || true
    local out=""
    if [ -f "$_ai_out_file" ]; then
      out=$(head -c 65536 "$_ai_out_file" 2>/dev/null || true)
      rm -f "$_ai_out_file" 2>/dev/null || true
    fi

    if command -v ai_create-ai-agents-history-hook >/dev/null 2>&1; then
      ai_create-ai-agents-history-hook --record \
        --agent "$_ai_agent" \
        --cwd "$_ai_cwd" \
        --command "$_ai_cmd" \
        --exit-code "$rc" \
        --output "$out" \
        --timestamp "$_ai_ts" \
        --source "hook" >/dev/null 2>&1
    elif [ -x "$HOME/.local/bin/ai_create-ai-agents-history-hook" ]; then
      "$HOME/.local/bin/ai_create-ai-agents-history-hook" --record \
        --agent "$_ai_agent" \
        --cwd "$_ai_cwd" \
        --command "$_ai_cmd" \
        --exit-code "$rc" \
        --output "$out" \
        --timestamp "$_ai_ts" \
        --source "hook" >/dev/null 2>&1
    fi
  ) >/dev/null 2>&1 &
}

trap _ai_on_exit EXIT
