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

# chezmoi safe wrapper: preview diff and ask confirmation before apply
chezmoi() {
    if [[ "$1" == "apply" ]]; then
        if ! command chezmoi verify >/dev/null 2>&1; then
            echo "==> Pending differences between destination and target state:"
            command chezmoi diff
            echo ""
            read -q "REPLY?Do you want to proceed with applying these changes? (y/N): "
            echo ""
            if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
                echo "Apply cancelled."
                return 1
            fi
        fi
        command chezmoi apply "${@:2}"
    else
        command chezmoi "$@"
    fi
}

