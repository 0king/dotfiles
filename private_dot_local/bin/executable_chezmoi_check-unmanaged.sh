#!/usr/bin/env bash
# ==============================================================================
# chezmoi_check-unmanaged.sh: Detect & Prompt for Untracked Files in Managed Dirs
#
# Scans directories that already contain files managed by chezmoi (e.g. ~/.local/bin,
# ~/.config/nvim, ~/.config/zsh, etc., excluding $HOME root files).
# Detects unmanaged files and interactively prompts whether to:
#   [y] Add to chezmoi
#   [n] Skip (leave unmanaged)
#   [i] Ignore (append to .chezmoiignore)
#   [a] Add all remaining
#   [q] Quit prompt
# ==============================================================================

set -euo pipefail

# Terminal color helpers
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
    RED=$(tput setaf 1 2>/dev/null || true)
    GREEN=$(tput setaf 2 2>/dev/null || true)
    YELLOW=$(tput setaf 3 2>/dev/null || true)
    BLUE=$(tput setaf 4 2>/dev/null || true)
    CYAN=$(tput setaf 6 2>/dev/null || true)
    BOLD=$(tput bold 2>/dev/null || true)
    DIM=$(tput dim 2>/dev/null || true)
    RESET=$(tput sgr0 2>/dev/null || true)
else
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    CYAN=""
    BOLD=""
    DIM=""
    RESET=""
fi

show_help() {
    cat <<EOF
${BOLD}Usage:${RESET} chezmoi_check-unmanaged.sh [OPTIONS] [PATHS...]

${BOLD}Description:${RESET}
  Detects unmanaged/new files located in directories that are already managed
  by chezmoi (such as ~/.local/bin, ~/.config/nvim, etc.).
  When run interactively, prompts whether each file should be tracked in chezmoi,
  ignored in .chezmoiignore, or skipped.

${BOLD}Options:${RESET}
  -c, --check-only    List unmanaged files without interactive prompting
  -s, --status        Run 'chezmoi status' before checking for unmanaged files
  -h, --help          Show this help message

${BOLD}Interactive Actions:${RESET}
  [y]es    Add target file to chezmoi tracking (chezmoi add)
  [n]o     Skip target file for now (leave unmanaged) [default]
  [i]gnore Append target file to .chezmoiignore
  [a]ll    Add this file and all subsequent untracked files
  [q]uit   Exit prompt immediately
  [?]help  Show prompt options

EOF
}

# Collect root-most managed directories containing files (excluding $HOME root loose files)
get_managed_dirs() {
    local home="$HOME"
    local -a files
    mapfile -t files < <(command chezmoi managed --include=files 2>/dev/null || true)

    local -A dir_map
    for f in "${files[@]}"; do
        local d
        d="$(dirname "$f")"
        if [[ "$d" != "." && -d "$home/$d" ]]; then
            dir_map["$d"]=1
        fi
    done

    # Sort by path length ascending so parent directories come before child directories
    local -a sorted_dirs
    mapfile -t sorted_dirs < <(for d in "${!dir_map[@]}"; do echo "$d"; done | awk '{ print length, $0 }' | sort -n | cut -d" " -f2-)

    local -a pruned_dirs=()
    for d in "${sorted_dirs[@]}"; do
        local is_child=0
        for p in "${pruned_dirs[@]}"; do
            if [[ "$d" == "$p" || "$d" == "$p"/* ]]; then
                is_child=1
                break
            fi
        done
        if (( ! is_child )); then
            pruned_dirs+=("$d")
        fi
    done

    for d in "${pruned_dirs[@]}"; do
        echo "$home/$d"
    done
}

add_to_ignore() {
    local target_rel="$1"
    local source_dir
    source_dir="$(command chezmoi source-path 2>/dev/null || echo "$HOME/.local/share/chezmoi")"
    local ignore_file="$source_dir/.chezmoiignore"

    if [ ! -f "$ignore_file" ]; then
        touch "$ignore_file"
    fi

    if ! grep -Fxq "$target_rel" "$ignore_file"; then
        # Ensure trailing newline if file does not end in one
        if [ -s "$ignore_file" ] && [ -n "$(tail -c 1 "$ignore_file")" ]; then
            echo "" >> "$ignore_file"
        fi
        echo "$target_rel" >> "$ignore_file"
        if [ -d "$source_dir/.git" ]; then
            git -C "$source_dir" add "$ignore_file" 2>/dev/null || true
        fi
    fi
}

main() {
    local CHECK_ONLY=0
    local RUN_STATUS=0
    local -a TARGET_PATHS=()

    for arg in "$@"; do
        case "$arg" in
            -h|--help)
                show_help
                exit 0
                ;;
            -c|--check-only)
                CHECK_ONLY=1
                ;;
            -s|--status)
                RUN_STATUS=1
                ;;
            -*)
                # Ignore unrecognized flags (e.g. passed from chezmoi status -v)
                ;;
            *)
                local resolved_path="$arg"
                if [[ "$resolved_path" == "~"* ]]; then
                    resolved_path="${resolved_path/#\~/$HOME}"
                elif [[ "$resolved_path" != /* ]]; then
                    resolved_path="$PWD/$resolved_path"
                fi
                if [ -e "$resolved_path" ]; then
                    TARGET_PATHS+=("$resolved_path")
                else
                    echo "⚠️  Path not found: $arg" >&2
                fi
                ;;
        esac
    done

    if (( RUN_STATUS )); then
        command chezmoi status
    fi

    local -a SCAN_DIRS=()
    if (( ${#TARGET_PATHS[@]} > 0 )); then
        SCAN_DIRS=("${TARGET_PATHS[@]}")
    else
        mapfile -t SCAN_DIRS < <(get_managed_dirs)
    fi

    if (( ${#SCAN_DIRS[@]} == 0 )); then
        exit 0
    fi

    local -a raw_unmanaged=()
    mapfile -t raw_unmanaged < <(command chezmoi unmanaged --include=files,symlinks "${SCAN_DIRS[@]}" 2>/dev/null || true)

    local -a unmanaged_files=()
    for item in "${raw_unmanaged[@]}"; do
        [ -z "$item" ] && continue
        unmanaged_files+=("$item")
    done

    local count="${#unmanaged_files[@]}"
    if (( count == 0 )); then
        exit 0
    fi

    echo ""
    echo -e "${YELLOW}${BOLD}❓ Untracked file(s) in managed directories (${count}):${RESET}"
    for f in "${unmanaged_files[@]}"; do
        echo -e "   ${CYAN}?${RESET}  ~/${f}"
    done
    echo ""

    # If non-interactive or check-only, stop here
    if (( CHECK_ONLY )) || [[ ! -t 0 ]] || [[ ! -t 1 ]]; then
        exit 0
    fi

    echo -e "${DIM}Options: [y]es, [n]o (skip), [i]gnore, [a]ll, [q]uit, [?]help${RESET}"
    echo ""

    local i=0
    local add_all=0

    while (( i < count )); do
        local file="${unmanaged_files[i]}"

        if (( add_all )); then
            command chezmoi add "$HOME/$file"
            echo -e "   ${GREEN}✅ Added ~/$file to chezmoi${RESET}"
            (( i++ ))
            continue
        fi

        printf "%s" "${BOLD}Add ~/$file to chezmoi?${RESET} [y/N/i/a/q/?] "
        local reply=""
        if [ -t 0 ]; then
            read -r reply || break
        elif [ -e /dev/tty ] && [ -r /dev/tty ]; then
            read -r reply < /dev/tty || break
        else
            break
        fi

        # Trim leading and trailing whitespace
        reply="${reply#"${reply%%[![:space:]]*}"}"
        reply="${reply%"${reply##*[![:space:]]}"}"

        case "$reply" in
            y|Y|yes|YES)
                command chezmoi add "$HOME/$file"
                echo -e "   ${GREEN}✅ Added ~/$file to chezmoi${RESET}"
                (( i++ ))
                ;;
            n|N|no|NO|"")
                echo -e "   ${DIM}⏩ Skipped ~/$file${RESET}"
                (( i++ ))
                ;;
            i|I|ignore|IGNORE)
                add_to_ignore "$file"
                echo -e "   ${BLUE}🙈 Ignored $file (added to .chezmoiignore)${RESET}"
                (( i++ ))
                ;;
            a|A|all|ALL)
                add_all=1
                command chezmoi add "$HOME/$file"
                echo -e "   ${GREEN}✅ Added ~/$file to chezmoi${RESET}"
                (( i++ ))
                ;;
            q|Q|quit|QUIT)
                echo -e "   ${YELLOW}👋 Stopped.${RESET}"
                break
                ;;
            \?|h|H|help|HELP)
                echo ""
                echo -e "${BOLD}Options:${RESET}"
                echo -e "  ${GREEN}y${RESET} - yes, add this file to chezmoi tracking"
                echo -e "  ${YELLOW}n${RESET} - no, skip this file (leave unmanaged for now) [default]"
                echo -e "  ${BLUE}i${RESET} - ignore, append to .chezmoiignore so it is no longer reported"
                echo -e "  ${CYAN}a${RESET} - all, add this file and all remaining untracked files"
                echo -e "  ${RED}q${RESET} - quit, stop prompting"
                echo -e "  ${BOLD}?${RESET} - show this help"
                echo ""
                ;;
            *)
                echo -e "   ${RED}Invalid option: '$reply'. Enter y, n, i, a, q, or ?${RESET}"
                ;;
        esac
    done
}

main "$@"
