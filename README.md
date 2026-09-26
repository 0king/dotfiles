# 🚀 Dotfiles Managed with Chezmoi

Modern, reproducible, and cross-platform personal dotfiles managed with [chezmoi](https://www.chezmoi.io/).

- **Operating Systems**: Ubuntu / Debian, Fedora, Arch Linux, macOS (Apple Silicon & Intel)
- **Desktop Environments / Window Managers**: GNOME, KDE Plasma, Hyprland, Headless/Servers
- **Zero Secret Leaks**: Author name & email are dynamically templated; local pre-commit hook runs `gitleaks`
- **Pure XDG Base Directory Compliance**: Git configuration lives cleanly in `~/.config/git/` rather than cluttering `$HOME`

---

## 📂 Architecture & Tracked Components

```text
~/.local/share/chezmoi/
├── .chezmoi.toml.tmpl                       # Machine initialization template (safety prompts, backup hook, author prompts)
├── .chezmoiignore                           # Universal ignore rules (blocks private keys, compiled binaries, caches)
├── .gitignore                               # Local gitignore for chezmoi repository
├── .githooks/
│   └── pre-commit                           # Local pre-commit hook scanning staged changes with gitleaks
├── dot_zshenv                               # Universal environment variables & XDG paths (runs first)
├── run_onchange_before_install-dependencies.sh.tmpl  # Automated pre-apply dependency installer hook
├── private_dot_config/
│   ├── git/
│   │   ├── config.tmpl                      # XDG Git configuration (templated name & email)
│   │   └── ignore                           # Global .gitignore (OS, editor, and build patterns)
│   ├── zsh/
│   │   ├── dot_zshrc.tmpl                   # Cross-platform Zsh setup (PATH, FZF, Starship, Antidote)
│   │   ├── aliases.zsh.tmpl                 # Aliases with cross-distro package management updates
│   │   ├── functions.zsh                    # Shell helper functions & safe chezmoi wrapper
│   │   ├── starship.toml                    # Starship prompt theme configuration
│   │   ├── dot_zsh_plugins.txt              # Antidote plugin bundle manifest
│   │   └── dot_gitignore                    # Local zsh ignore
│   ├── nvim/                                # LazyVim modular configuration (Lua, plugins, keymaps)
│   ├── wezterm/                             # Modular WezTerm Lua configuration
│   ├── alacritty/                           # Alacritty terminal configuration & themes
│   ├── kitty/                               # Kitty terminal configuration
│   ├── ghostty/                             # Ghostty terminal configuration
│   ├── kanata/                              # Keyboard remap configurations (unicfg.kbd)
│   ├── vicinae/                             # Launcher configuration (settings.json)
│   ├── yazi/                                # Yazi file manager configuration
│   └── zed/                                 # Zed editor configuration (private_settings.json)
├── private_dot_local/
│   └── bin/                                 # Custom user scripts (browser-picker, scripts collection)
│       └── scripts/                         # Automation & utilities (create-github-repo, bash-boilerplate, etc.)
└── README.md                                # This documentation
```

---

## ⚡ Bootstrapping a New Machine

Chezmoi enables complete system bootstrapping from scratch in a single command.

### 1. One-Liner Bootstrap

Once you push this repository to GitHub/GitLab, you can bootstrap any fresh machine by running:

```bash
sh -c "$(curl -fsLS get.chezmoi.io)" -- init --apply 0king
```

When run, Chezmoi will:
1. Clone your dotfiles into `~/.local/share/chezmoi`
2. Interactively prompt you for your name, email, and preferred desktop environment
3. Execute `run_onchange_before_install-dependencies.sh.tmpl` **before** placing files to install all required packages and fonts
4. Apply all configuration files and scripts into `$HOME`

---

### 2. Manual Bootstrap (Step-by-Step)

If you prefer to install prerequisites manually first:

#### Ubuntu / Debian
```bash
sudo apt-get update && sudo apt-get install -y git curl zsh
sh -c "$(curl -fsLS get.chezmoi.io)" -- init --apply <your-repo-url>
```

#### Fedora
```bash
sudo dnf install -y git curl zsh
sh -c "$(curl -fsLS get.chezmoi.io)" -- init --apply <your-repo-url>
```

#### Arch Linux
```bash
sudo pacman -S --needed git curl zsh chezmoi
chezmoi init --apply <your-repo-url>
```

#### macOS
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install git chezmoi
chezmoi init --apply <your-repo-url>
```

---

## 🔧 Automated Dependency Pre-Installer

The pre-apply script `run_onchange_before_install-dependencies.sh.tmpl` automatically provisions required tools before configuration files are linked:

- **CLI & TUI Utilities**: `git`, `zsh`, `starship`, `zoxide`, `fzf`, `ripgrep`, `fd`/`fdfind`, `bat`/`batcat`, `lazygit`, `yazi`, `neovim`, `gitleaks`, `jq`, `unzip`
- **Development Prerequisites**: `build-essential` / `gcc`, `make` (for Neovim Mason / Tree-sitter)
- **Clipboard Helpers**: `wl-clipboard` (Wayland), `xclip` (X11), `pbcopy` (macOS)
- **Typography**: Downloads and installs `FiraCode Nerd Font` to `~/.local/share/fonts`
- **Plugin Management**: Automatically clones `antidote` into `~/.config/zsh/.antidote`

---

## 🔒 Security & Secret Protection

### 1. Dynamic User Templating & Cloud Privacy
Author credentials and personal email addresses are never hardcoded into repository templates. When bootstrapping a machine (`chezmoi init`), `.chezmoi.toml.tmpl` interactively prompts for your author name and email without checking personal fallbacks into Git:
```gotemplate
{{- $name := promptStringOnce . "name" "Git author name" -}}
{{- $email := promptStringOnce . "email" "Git author email" -}}
```
The evaluated values are stored strictly locally in `~/.config/chezmoi/chezmoi.toml` (which is never tracked in Git). In `private_dot_config/git/config.tmpl`, Git configuration is rendered dynamically:
```ini
[user]
    name = {{ .name }}
    email = {{ .email }}
```
For cloud privacy, using GitHub's privacy-protected no-reply address (e.g. `3360778+0king@users.noreply.github.com`) ensures commit logs remain anonymous when pushed to public repositories.

### 2. Local-Only Gitleaks Hook
A pre-commit hook is installed at `.githooks/pre-commit` and activated via:
```bash
git config core.hooksPath .githooks
```
This hook automatically runs `gitleaks protect --staged` before every commit to your dotfiles repo. It prevents accidental commits of API tokens, SSH keys, or private data, while leaving your global Git hooks clean and unhindered.

### 3. Optional: Encrypted Secrets with `age`
If you wish to version-control sensitive files (e.g. private SSH configurations or API credentials), Chezmoi natively integrates with `age`:
```bash
# 1. Generate an age encryption key
chezmoi age-keygen -o ~/.config/chezmoi/key.txt

# 2. Add an encrypted secret file
chezmoi add --encrypt ~/.ssh/config
```

---

## 🛡️ Overwrite Prevention & Safety Safeguards

To prevent accidentally overwriting local machine files when running `chezmoi apply`, this repository comes with three layers of automated defense:

### 1. Interactive Overwrite Prompts (`lessInteractive = true`)
Configured in `.chezmoi.toml.tmpl` and active in `~/.config/chezmoi/chezmoi.toml`. Whenever `chezmoi apply` would modify or overwrite an existing file on disk, chezmoi pauses and prompts for explicit confirmation:
- `y` — **Yes**, overwrite this file
- `n` — **No**, skip this file
- `d` — **Diff**, view exact line changes for this file
- `q` — **Quit**, abort apply immediately

### 2. Automated Pre-Apply Backups (`[hooks.apply.pre]`)
A pre-apply hook runs automatically before changes are written to `$HOME`. It creates a snapshot of any existing files that are about to be updated:
```text
~/.cache/chezmoi/backups/<YYYYMMDD_HHMMSS>/
```
If you ever accidentally overwrite a file, you can immediately recover the previous version from this directory.

### 3. Shell Wrapper with Pre-Apply Diff
A safe `chezmoi` wrapper is defined in `functions.zsh`. When running `chezmoi apply` in Zsh:
1. It runs `chezmoi verify` to check if differences exist.
2. If differences are detected, it automatically displays the full `chezmoi diff`.
3. It asks for explicit confirmation (`Do you want to proceed with applying these changes? (y/N)`) before invoking `apply`.

### 4. Preserving Machine-Specific Modifications
- **Keep local edits in dotfiles repo**: Run `chezmoi add <path>` (or `chezmoi re-add` to update all modified managed files).
- **Interactive 3-way merge**: Run `chezmoi merge <path>` to resolve conflicting sections cleanly with your editor/merge tool.

---

## 🛠️ Daily Workflow Cheatsheet

| Command | Action |
| :--- | :--- |
| `chezmoi status` | Check which files differ between `$HOME` and the repository |
| `chezmoi diff` | Inspect the exact diff before applying changes |
| `chezmoi apply` | Deploy repository changes (with interactive prompts & backup) |
| `chezmoi apply <path>` | Safely deploy only a specific file or directory |
| `chezmoi re-add` | Update repository with any modified files from `$HOME` |
| `chezmoi merge <path>` | Open a 3-way merge tool to resolve conflicts interactively |
| `chezmoi edit <path>` | Edit a managed file directly in `$EDITOR` inside the repository |
| `chezmoi add <path>` | Start managing a new configuration file in Chezmoi |
| `chezmoi cd` | Open a shell directly inside `~/.local/share/chezmoi` |

---

## 🌐 Linking to a Remote Git Repository

When you are ready to push your dotfiles to GitHub, GitLab, or Codeberg:

```bash
# 1. Open the repository directory
chezmoi cd

# 2. Add your remote repository URL
git remote add origin git@github.com:0king/dotfiles.git

# 3. Verify author identity (ensuring no private info in commit logs)
git log -1 --format="Author: %an <%ae>"

# 4. Push your main branch
git branch -M main
git push -u origin main
```
