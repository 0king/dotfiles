# yazi
function y() {
    local tmp="$(mktemp -t "yazi-cwd.XXXXXX")" cwd
    command yazi "$@" --cwd-file="$tmp"
    IFS= read -r -d '' cwd < "$tmp"
    [ "$cwd" != "$PWD" ] && [ -d "$cwd" ] && builtin cd -- "$cwd"
    command rm -f -- "$tmp"
}

# navigate and print dir contents
# chpwd is a zsh hook
function chpwd() {
    eza -ah --group-directories-first --icons
}

# git add & commit
# usage: gac 'my commit message'
gac() {
  if [ -z "$1" ]; then
    echo "Error: Commit message required."
    return 1
  fi
  
  git add -A
  git commit -m "$*"
}

# git add, commit & push
# usage: gacp 'my commit message'
gacp() {
  if [ -z "$1" ]; then
    echo "Error: Commit message required."
    return 1
  fi
  
  git add -A && git commit -m "$*" && git push
}

# run c files
run() {
    if [ -z "$1" ]; then
        echo "Usage: run <filename.ext> [args...]"
        return 1
    fi

    local src_file="$1"
    # Shift removes the first argument ($1) so "$@" contains only the trailing arguments
    shift 

    if [ ! -f "$src_file" ]; then
        echo "Error: File '$src_file' not found."
        return 1
    fi

    local filename=$(basename -- "$src_file")
    local ext="${filename##*.}"
    local base="${filename%.*}"
    local build_dir="build"

    case "$ext" in
        c)
            mkdir -p "$build_dir"
            if gcc "$src_file" -o "$build_dir/$base"; then
                "./$build_dir/$base" "$@"
            fi
            ;;
        cpp|cc|cxx)
            mkdir -p "$build_dir"
            if g++ "$src_file" -o "$build_dir/$base"; then
                "./$build_dir/$base" "$@"
            fi
            ;;
        java)
            mkdir -p "$build_dir"
            if javac -d "$build_dir" "$src_file"; then
                java -cp "$build_dir" "$base" "$@"
            fi
            ;;
        py)
            # You can swap 'python3' for 'uv run python' here if you want it tied to your uv environments
            python3 "$src_file" "$@"
            ;;
        js)
            node "$src_file" "$@"
            ;;
        ts)
            # Uses tsx (or swap with ts-node or bun) to execute TypeScript on the fly
            npx tsx "$src_file" "$@"
            ;;
        *)
            echo "Error: Unsupported file extension (.$ext)"
            return 1
            ;;
    esac
}

# chezmoi safe wrapper: preview affected files and ask confirmation before apply or re-add
chezmoi() {
    if [[ "$1" == "apply" ]]; then
        local skip_prompt=0
        for arg in "${@:2}"; do
            if [[ "$arg" == "-n" || "$arg" == "--dry-run" || "$arg" == "-f" || "$arg" == "--force" || "$arg" == "-h" || "$arg" == "--help" ]]; then
                skip_prompt=1
                break
            fi
        done
        if (( ! skip_prompt )) && ! command chezmoi verify "${@:2}" >/dev/null 2>&1; then
            echo "⚠️ The following files are going to be modified in your home directory:"
            command chezmoi status "${@:2}"
            echo ""
            while true; do
                if ! read -r "REPLY?Apply changes? [y,n,d,q,?] "; then
                    echo ""
                    echo "Apply cancelled."
                    return 1
                fi
                local input="${REPLY#"${REPLY%%[![:space:]]*}"}"
                input="${input%"${input##*[![:space:]]}"}"

                case "$input" in
                    d|D|1)
                        echo ""
                        command chezmoi diff "${@:2}"
                        echo ""
                        continue
                        ;;
                    \?)
                        echo ""
                        echo "  y - yes, apply changes"
                        echo "  n - no, do not apply changes"
                        echo "  d - diff, view pending differences"
                        echo "  q - quit, cancel apply"
                        echo "  ? - show this help"
                        echo ""
                        continue
                        ;;
                    y|Y|yes|YES)
                        break
                        ;;
                    *)
                        echo "Apply cancelled."
                        return 1
                        ;;
                esac
            done
        fi
        command chezmoi apply "${@:2}"
    elif [[ "$1" == "re-add" ]]; then
        local skip_prompt=0
        for arg in "${@:2}"; do
            if [[ "$arg" == "-n" || "$arg" == "--dry-run" || "$arg" == "-f" || "$arg" == "--force" || "$arg" == "-h" || "$arg" == "--help" ]]; then
                skip_prompt=1
                break
            fi
        done
        if (( ! skip_prompt )) && ! command chezmoi verify "${@:2}" >/dev/null 2>&1; then
            echo "⚠️ The following files are going to be updated in your dotfiles repository (~/.local/share/chezmoi):"
            command chezmoi status "${@:2}"
            echo ""
            while true; do
                if ! read -r "REPLY?Re-add changes to repository? [y,n,d,q,?] "; then
                    echo ""
                    echo "Re-add cancelled."
                    return 1
                fi
                local input="${REPLY#"${REPLY%%[![:space:]]*}"}"
                input="${input%"${input##*[![:space:]]}"}"

                case "$input" in
                    d|D|1)
                        echo ""
                        command chezmoi diff --reverse "${@:2}"
                        echo ""
                        continue
                        ;;
                    \?)
                        echo ""
                        echo "  y - yes, re-add changes to repository"
                        echo "  n - no, do not re-add changes"
                        echo "  d - diff, view reverse differences (destination -> repository)"
                        echo "  q - quit, cancel re-add"
                        echo "  ? - show this help"
                        echo ""
                        continue
                        ;;
                    y|Y|yes|YES)
                        break
                        ;;
                    *)
                        echo "Re-add cancelled."
                        return 1
                        ;;
                esac
            done
        fi
        command chezmoi re-add "${@:2}"
    else
        command chezmoi "$@"
    fi
}


