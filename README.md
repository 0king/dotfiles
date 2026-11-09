# 🚀 Dotfiles Managed with GNU Stow

Modern, modular, and cross-platform personal dotfiles managed with [GNU Stow](https://www.gnu.org/software/stow/).

- **Operating Systems**: Ubuntu / Debian, Fedora, Arch Linux, macOS (Apple Silicon & Intel)
- **Desktop Environments / Window Managers**: GNOME, KDE Plasma, Hyprland, PaperWM, Headless/Servers
- **Zero Secret Leaks**: Local-only Gitleaks pre-commit protection (`.githooks/pre-commit`) and Git `[include]` for machine-local credentials (`~/.config/git/config.local`)
- **Pure XDG Base Directory Compliance**: Modular packages adhere strictly to XDG standards (`~/.config/`, `~/.local/`)
- **100% Native Portability**: No template engines required. Platform variations resolve natively via dynamic Zsh detection, Git includes, and native Bash in `setup.sh`.

---

## 📂 Modular Directory Folding Architecture

All configuration directories fold directly into directory symlinks in `$HOME`, leaving zero loose internal symlinks:

- **15 Folded Directory Symlinks in `$HOME`**:
  - `~/.config/ai` -> `../dotfiles/ai/.config/ai`
  - `~/.config/alacritty` -> `../dotfiles/alacritty/.config/alacritty`
  - `~/.config/ghostty` -> `../dotfiles/ghostty/.config/ghostty`
  - `~/.config/git` -> `../dotfiles/git/.config/git`
  - `~/.config/kanata` -> `../dotfiles/kanata/.config/kanata`
  - `~/.config/kitty` -> `../dotfiles/kitty/.config/kitty`
  - `~/.config/nvim` -> `../dotfiles/nvim/.config/nvim`
  - `~/.config/systemd` -> `../dotfiles/systemd/.config/systemd`
  - `~/.config/vicinae` -> `../dotfiles/vicinae/.config/vicinae`
  - `~/.config/wezterm` -> `../dotfiles/wezterm/.config/wezterm`
  - `~/.config/yazi` -> `../dotfiles/yazi/.config/yazi`
  - `~/.config/zed` -> `../dotfiles/zed/.config/zed`
  - `~/.config/zsh` -> `../dotfiles/zsh/.config/zsh`
  - `~/.local/bin` -> `../dotfiles/bin/.local/bin`
  - `~/Desktop/mem` -> `../../dotfiles/desktop/Desktop/mem`
- **Only 3 Root Files in `$HOME`**:
  - `~/.zshenv` -> `dotfiles/zsh/.zshenv`
  - `~/.ai` -> `dotfiles/ai/.ai`
  - `~/.aider.conf.yml` -> `dotfiles/aider/.aider.conf.yml`

### Package-Local `.gitignore` Modularity
- **Root `.gitignore`**: Contains **universal rules only** (secrets, private keys, compiled binary formats `*.so`/`*.exe`, OS noise). Zero package-specific paths.
- **Package-Local `.gitignore` Files**: Each package encapsulates its own exclusions:
  - `systemd/.config/systemd/.gitignore`: OS target wants, snap units, and machine-generated `ai-memory.service`.
  - `git/.config/git/.gitignore`: Local machine credentials (`config.local`, `credentials*`).
  - `zsh/.config/zsh/.gitignore`: Runtime caches (`.antidote/`, `.zcompdump*`, `.zsh_plugins.zsh*`).
  - `bin/.local/bin/.gitignore`: Dynamic file-type classified ELF binaries and external symlinks.
  - `kanata/.config/kanata/.gitignore`: Editor artifacts (`.kilo/`, `*.old`).
  - `desktop/Desktop/mem/.gitignore`: Local chat histories (`.aider*`).
- **Dynamic ELF Binary Classifier (`scripts/classify-binaries.sh`)**:
  - Automatically identifies compiled ELF binaries (`\x7fELF`) and unmanaged external tool symlinks in `~/.local/bin`.
  - Dynamically maintains `bin/.local/bin/.gitignore` without wildcard rules, ensuring user scripts are auto-tracked by default.
  - Hooked directly into `dotfiles status`, `dotfiles apply`, `dotfiles push`, `.githooks/pre-commit`, and `setup.sh`.

---

## 📂 Modular Packages (16 Packages, 180 Managed Files)

```text
~/dotfiles/
├── ai/                      # Universal AI instructions & skills (symlinks ~/.config/ai and ~/.ai)
├── bin/                     # User scripts on PATH (~/.local/bin/*) + dotfiles CLI
├── nvim/                    # Modular LazyVim configuration (~/.config/nvim/)
├── desktop/                 # Desktop memos & keymaps (~/Desktop/mem/)
├── zsh/                     # Zsh configuration (~/.zshenv, ~/.config/zsh/*)
├── alacritty/               # Alacritty terminal config (~/.config/alacritty/)
├── ghostty/                 # Ghostty terminal config (~/.config/ghostty/)
├── kitty/                   # Kitty terminal config (~/.config/kitty/)
├── wezterm/                 # WezTerm terminal config (~/.config/wezterm/)
├── git/                     # Global Git configuration (~/.config/git/config & ignore)
├── kanata/                  # Keyboard remapping config & systemd service (~/.config/kanata/)
├── systemd/                 # User systemd timer & service units (~/.config/systemd/user/)
├── vicinae/                 # Launcher settings (~/.config/vicinae/)
├── yazi/                    # Yazi file manager config (~/.config/yazi/)
├── zed/                     # Zed editor settings (~/.config/zed/)
├── aider/                   # Aider AI assistant config (~/.aider.conf.yml)
│
├── brave/                   # Cloud-safe Brave/Chrome profile preferences & keymaps (repo asset)
├── docs/                    # Script & terminal documentation (repo asset)
├── archive/chezmoi/         # Historical Chezmoi templates and hooks
├── .githooks/               # Local pre-commit hook (gitleaks)
├── setup.sh                 # Cross-platform dependency installer & stow bootstrap
├── .stow-local-ignore       # Stow exclusion rules
├── usage.md                 # Complete GNU Stow usage guide & scenario handbook
└── README.md                # This documentation
```

---

## ⚡ Quick Start & Bootstrapping

### 1. Clone & Bootstrap

```bash
git clone git@github.com:0king/dotfiles.git ~/dotfiles
cd ~/dotfiles
./setup.sh
```

`setup.sh` automatically:
1. Detects your OS (Ubuntu/Debian, Fedora, Arch Linux, macOS)
2. Checks and installs required dependencies (`stow`, `git`, `zsh`, `ripgrep`, `fzf`, `neovim`, `starship`, fonts, etc.)
3. Pre-seeds machine-local Git credentials at `~/.config/git/config.local` if missing
4. Configures local-only Gitleaks pre-commit protection (`git config core.hooksPath .githooks`)
5. Backs up any conflicting regular files to `~/.cache/dotfiles/backups/<timestamp>`
6. Stows all 16 modular packages cleanly to `$HOME`
7. Runs `sync-ai-agents` to update symlinks for all AI tools (Cursor, Gemini, Claude, VS Code, etc.)

---

## 🛠️ Management CLI (`dotfiles` / `df*`)

A lightweight CLI tool is provided at `~/.local/bin/dotfiles`:

| Command | Alias | Description |
| :--- | :---: | :--- |
| `dotfiles status` | `dfs` | Show working tree status in `~/dotfiles` |
| `dotfiles diff` | `dfd` | Show unstaged/staged diffs in `~/dotfiles` |
| `dotfiles apply` | `dfa` | Re-stow all packages (`setup.sh --restow`) |
| `dotfiles audit` | — | Run Gitleaks scan on the repository |
| `dotfiles push` | `dfp` | Scan with Gitleaks and push to remote |
| `dotfiles pull` | — | Pull latest commits and re-stow |
| `dotfiles cd` | `dfcd` | Jump to `~/dotfiles` directory |

> 💡 **Need Stow Help?** See [`usage.md`](usage.md) for the exhaustive handbook covering all GNU Stow workflows, directory folding vs. unfolding, `--adopt` safety, unmanaged files, collisions, and edge case recovery.

---

## 🔒 Security & Local Gitleaks Protection

- **Local Hooks Only**: The pre-commit hook is enabled strictly for this repository via `core.hooksPath = .githooks` inside `~/dotfiles/.git/config`. Global Git configuration is never altered.
- **Git Native Includes**: Your user name and email are kept in `~/.config/git/config.local` (untracked by Git), which is included by `~/.config/git/config`:
  ```gitconfig
  [include]
      path = ~/.config/git/config.local
  ```

---

## ⌨️ Unified Terminal Keybindings (Kitty, Alacritty, WezTerm, Ghostty)

All terminal emulators share a consistent keybinding matrix:
- **Copy on Select**: Highlighting text automatically copies it to the system clipboard.
- **Select All (`Ctrl + Shift + A`)**: Captures and copies the entire buffer/scrollback history.
- **Vim Mode (`Ctrl + Shift + Space` or `Ctrl + Shift + X`)**: Activates modal keyboard navigation.
- **Line Scrolling**: `Ctrl + Shift + Up/Down` and `Ctrl + Shift + K/J`.
- **Page & Boundary Scrolling**: `Shift + PageUp/Down`, `Ctrl + Shift + PageUp/Down`, and `Shift/Ctrl + Shift + Home/End`.

👉 **Full Documentation**: See [`docs/terminal-keymap-README.md`](docs/terminal-keymap-README.md) and [`Desktop/mem/keymaps/terminal-keymap.md`](Desktop/mem/keymaps/terminal-keymap.md).
