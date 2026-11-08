#!/usr/bin/env bash
# ==============================================================================
# setup.sh: Cross-Platform Dotfiles Bootstrap & Package Linker (GNU Stow)
# Supports: Ubuntu/Debian, Fedora, Arch Linux, macOS
# ==============================================================================

set -euo pipefail

DOTFILES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/dotfiles/backups/$(date +%Y%m%d_%H%M%S)"

RESTOW_ONLY=0
DRY_RUN=0

for arg in "$@"; do
    case "$arg" in
        --restow|-r) RESTOW_ONLY=1 ;;
        --dry-run|-n) DRY_RUN=1 ;;
        --help|-h)
            echo "Usage: ./setup.sh [--restow|-r] [--dry-run|-n]"
            exit 0
            ;;
    esac
done

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# ------------------------------------------------------------------------------
# 1. OS & Distribution Detection
# ------------------------------------------------------------------------------
OS="unknown"
DISTRO="unknown"

case "$(uname -s)" in
    Darwin)
        OS="darwin"
        DISTRO="macos"
        ;;
    Linux)
        OS="linux"
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            DISTRO="${ID:-unknown}"
        fi
        ;;
esac

echo "=============================================================================="
echo "🚀 Dotfiles Setup (GNU Stow)"
echo "   OS: $OS | Distro: $DISTRO"
echo "   Dotfiles Directory: $DOTFILES_DIR"
echo "=============================================================================="

# ------------------------------------------------------------------------------
# 2. Dependency Installation (skipped if --restow)
# ------------------------------------------------------------------------------
if [ "$RESTOW_ONLY" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    echo "📦 Checking system dependencies..."

    if [ "$OS" = "darwin" ]; then
        if ! has_cmd brew; then
            echo "Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            eval "$(/opt/homebrew/bin/brew shellenv 2>/dev/null || /usr/local/bin/brew shellenv 2>/dev/null)"
        fi
        BREW_PACKAGES=(stow git zsh starship zoxide fzf ripgrep fd bat lazygit yazi neovim gitleaks jq font-fira-code-nerd-font)
        for pkg in "${BREW_PACKAGES[@]}"; do
            if ! brew list "$pkg" >/dev/null 2>&1; then
                brew install "$pkg" || echo "Warning: failed to install $pkg via brew"
            fi
        done
    elif [ "$OS" = "linux" ]; then
        case "$DISTRO" in
            ubuntu|debian)
                if sudo -n true 2>/dev/null; then
                    export DEBIAN_FRONTEND=noninteractive
                    sudo apt-get update -y
                    APT_PACKAGES=(stow git zsh fzf ripgrep fd-find bat lazygit neovim jq curl wget unzip build-essential wl-clipboard xclip)
                    MISSING_APT=()
                    for pkg in "${APT_PACKAGES[@]}"; do
                        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
                            MISSING_APT+=("$pkg")
                        fi
                    done
                    if [ ${#MISSING_APT[@]} -gt 0 ]; then
                        echo "Installing missing apt packages: ${MISSING_APT[*]}..."
                        sudo apt-get install -y "${MISSING_APT[@]}" || true
                    fi
                fi
                mkdir -p "$HOME/.local/bin"
                if has_cmd batcat && ! has_cmd bat; then
                    ln -sf "$(which batcat)" "$HOME/.local/bin/bat"
                fi
                if has_cmd fdfind && ! has_cmd fd; then
                    ln -sf "$(which fdfind)" "$HOME/.local/bin/fd"
                fi
                if ! has_cmd starship; then
                    curl -sS https://starship.rs/install.sh | sh -s -- -y
                fi
                if ! has_cmd zoxide; then
                    curl -sS https://raw.githubusercontent.com/ajeetdsouza/zoxide/main/install.sh | bash
                fi
                if ! has_cmd gitleaks; then
                    GITLEAKS_VERSION=$(curl -s "https://api.github.com/repos/gitleaks/gitleaks/releases/latest" 2>/dev/null | grep -Po '"tag_name": "v\K[^"]*' || echo "8.21.2")
                    curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar -xz -C "$HOME/.local/bin" gitleaks 2>/dev/null || true
                    chmod +x "$HOME/.local/bin/gitleaks" 2>/dev/null || true
                fi
                ;;
            fedora)
                if sudo -n true 2>/dev/null; then
                    DNF_PACKAGES=(stow git zsh starship zoxide fzf ripgrep fd-find bat lazygit neovim gitleaks jq curl wget unzip gcc make wl-clipboard xclip)
                    sudo dnf install -y "${DNF_PACKAGES[@]}" || true
                fi
                ;;
            arch)
                if sudo -n true 2>/dev/null; then
                    PAC_PACKAGES=(stow git zsh starship zoxide fzf ripgrep fd bat lazygit yazi neovim gitleaks jq curl wget unzip base-devel wl-clipboard xclip ttf-fira-code ttf-nerd-fonts-symbols)
                    sudo pacman -S --needed --noconfirm "${PAC_PACKAGES[@]}" || true
                fi
                ;;
        esac

        # FiraCode Nerd Font for Linux
        FONT_DIR="$HOME/.local/share/fonts"
        if [ ! -f "$FONT_DIR/FiraCodeNerdFont-Regular.ttf" ]; then
            echo "📦 Installing FiraCode Nerd Font..."
            mkdir -p "$FONT_DIR"
            curl -fLo "$FONT_DIR/FiraCode.zip" https://github.com/ryanoasis/nerd-fonts/releases/latest/download/FiraCode.zip 2>/dev/null || true
            if [ -f "$FONT_DIR/FiraCode.zip" ]; then
                unzip -qo "$FONT_DIR/FiraCode.zip" -d "$FONT_DIR" 2>/dev/null || true
                rm -f "$FONT_DIR/FiraCode.zip"
                if has_cmd fc-cache; then
                    fc-cache -f "$FONT_DIR" >/dev/null 2>&1 || true
                fi
                echo "✅ FiraCode Nerd Font installed."
            fi
        fi
    fi

    # Antidote plugin manager for Zsh
    ANTIDOTE_DIR="$HOME/.config/zsh/.antidote"
    if [ ! -d "$ANTIDOTE_DIR" ]; then
        echo "🔌 Cloning Antidote plugin manager..."
        git clone --depth=1 https://github.com/mattmc3/antidote.git "$ANTIDOTE_DIR" 2>/dev/null || true
    fi
fi

# ------------------------------------------------------------------------------
# 3. Local Git Configuration & Hooks
# ------------------------------------------------------------------------------
if [ -d "$DOTFILES_DIR/.git" ]; then
    echo "🔒 Configuring local Gitleaks pre-commit hook..."
    git -C "$DOTFILES_DIR" config core.hooksPath .githooks
fi

# Machine-local Git credentials pre-seeding
LOCAL_GIT_CONFIG="$HOME/.config/git/config.local"
if [ ! -f "$LOCAL_GIT_CONFIG" ]; then
    echo "👤 Pre-seeding machine-local Git credentials at $LOCAL_GIT_CONFIG..."
    mkdir -p "$(dirname "$LOCAL_GIT_CONFIG")"
    cat > "$LOCAL_GIT_CONFIG" << 'EOF'
[user]
	name = durjan
	email = 3360778+0king@users.noreply.github.com
EOF
    echo "✅ Local Git configuration created."
fi

# ------------------------------------------------------------------------------
# 4. Conflict Resolution & Backup Before Stowing
# ------------------------------------------------------------------------------
PACKAGES=(
    ai
    bin
    nvim
    desktop
    zsh
    alacritty
    ghostty
    kitty
    wezterm
    git
    kanata
    systemd
    vicinae
    yazi
    zed
    aider
)

backup_conflicts() {
    local pkg="$1"
    local pkg_dir="$DOTFILES_DIR/$pkg"
    [ -d "$pkg_dir" ] || return 0

    while IFS= read -r rel_file; do
        local target="$HOME/$rel_file"
        # If target exists and is a regular file/link NOT pointing to DOTFILES_DIR
        if [ -e "$target" ] || [ -L "$target" ]; then
            local current_link=""
            if [ -L "$target" ]; then
                current_link="$(readlink "$target" || true)"
            fi

            # If it already points to dotfiles, leave it
            case "$current_link" in
                *"$DOTFILES_DIR"*) continue ;;
            esac

            # Conflicting regular file or alien symlink: back it up
            local backup_target="$BACKUP_ROOT/$rel_file"
            echo "⚠️  Backing up conflicting target: $target -> $backup_target"
            mkdir -p "$(dirname "$backup_target")"
            mv "$target" "$backup_target"
        fi
    done < <(cd "$pkg_dir" && find . -mindepth 1 \( -type f -o -type l \) | sed 's|^\./||')
}

if [ "$DRY_RUN" -eq 0 ]; then
    echo "🛡️  Checking for conflicting regular files in \$HOME..."
    for pkg in "${PACKAGES[@]}"; do
        backup_conflicts "$pkg"
    done
fi

# ------------------------------------------------------------------------------
# 5. Stow Packages
# ------------------------------------------------------------------------------
echo "🔗 Stowing packages to \$HOME..."
STOW_FLAGS="-v -R -t $HOME -d $DOTFILES_DIR"
if [ "$DRY_RUN" -eq 1 ]; then
    STOW_FLAGS="-n $STOW_FLAGS"
fi

for pkg in "${PACKAGES[@]}"; do
    if [ -d "$DOTFILES_DIR/$pkg" ]; then
        echo "   -> Stowing package: $pkg"
        stow $STOW_FLAGS "$pkg"
    fi
done

# ------------------------------------------------------------------------------
# 6. Post-Stow: AI Tool Symlink Sync
# ------------------------------------------------------------------------------
SYNC_SCRIPT="$HOME/.local/bin/sync-ai-agents"
if [ "$DRY_RUN" -eq 0 ] && [ -x "$SYNC_SCRIPT" ]; then
    echo "🤖 Running sync-ai-agents to update all AI tool links..."
    "$SYNC_SCRIPT"
fi

echo "=============================================================================="
echo "✅ Dotfiles setup completed successfully!"
echo "=============================================================================="
