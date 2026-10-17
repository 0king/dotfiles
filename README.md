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
├── run_after_setup-ai-symlinks.sh.tmpl       # Automated post-apply AI tool symlink hook
├── private_dot_config/
│   ├── ai/                                  # Universal AI configuration (AGENTS.md, skills, rules, prompts)
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
│   ├── wezterm/                             # Modular WezTerm Lua configuration (unified keymaps)
│   ├── alacritty/                           # Alacritty terminal configuration & themes (unified keymaps)
│   ├── kitty/                               # Kitty terminal configuration (unified keymaps)
│   ├── ghostty/                             # Ghostty terminal configuration (unified keymaps)
│   ├── kanata/                              # Keyboard remap configurations (unicfg.kbd)
│   ├── vicinae/                             # Launcher configuration (settings.json)
│   ├── yazi/                                # Yazi file manager configuration
│   └── zed/                                 # Zed editor configuration (private_settings.json)
├── private_dot_local/
│   └── bin/                                 # Custom user scripts on PATH (git_*, ubuntu_*, vscode_*, etc.)
│       ├── executable_browser-chrome-brave_export-import-settings.sh # Cloud-safe browser preferences & keymap sync
│       ├── executable_sync-ai-agents        # Universal AI tool symlinker (Cursor, Gemini, Claude, etc.)
│       ├── code/                            # C/C++ source snippets (off PATH)
│       ├── docs/                            # Script manuals & guides (terminal-keymap.md, etc.)
│       └── out/                             # Script-generated data & snapshots (off PATH)
├── brave/                                   # Cloud-safe Brave/Chrome profile preferences & keymaps
├── docs/
│   ├── terminal-keymap-README.md            # Complete unified terminal keymap reference
│   └── brave-profile-and-keymap-README.md   # Complete Brave/Chrome profile settings & keymap reference
└── README.md                                # This documentation
```

---

## ⌨️ Unified Terminal Keybindings (Kitty, Alacritty, WezTerm, Ghostty)

All four terminal emulators share an identical mental model, keybinding matrix, and clipboard behaviors:
- **Copy on Select**: Highlighting text with the mouse automatically copies it to the system clipboard across all terminals.
- **Select All (`Ctrl + Shift + A`)**: Captures and copies the entire buffer/scrollback history directly to the clipboard.
- **Vim Mode (`Ctrl + Shift + Space` or `Ctrl + Shift + X`)**: Activates keyboard scrollback navigation—native modal Vi mode in Alacritty and WezTerm, and a Neovim pager overlay in Kitty and Ghostty.
- **Line Scrolling**: `Ctrl + Shift + Up/Down` and `Ctrl + Shift + K/J` (with WezTerm's default `ClearScrollback` safely overridden).
- **Page & Boundary Scrolling**: `Shift + PageUp/Down`, `Ctrl + Shift + PageUp/Down`, and `Shift/Ctrl + Shift + Home/End`.

👉 **Full Documentation**: See [`docs/terminal-keymap.md`](docs/terminal-keymap.md) for the detailed cheatsheet and architecture breakdown.

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

To prevent accidentally overwriting local machine files when running `chezmoi apply` or accidentally overwriting repository files when running `chezmoi re-add`, this repository comes with three layers of automated defense:

### 1. Interactive Overwrite Prompts (`lessInteractive = true`)
Configured in `.chezmoi.toml.tmpl` and active in `~/.config/chezmoi/chezmoi.toml`. Whenever `chezmoi apply` or `chezmoi re-add` would modify or overwrite an existing file on disk, chezmoi pauses and prompts for explicit confirmation:
- `y` — **Yes**, overwrite this file
- `n` — **No**, skip this file
- `d` — **Diff**, view exact line changes for this file
- `q` — **Quit**, abort operation immediately

### 2. Conflict Protection & Automated Pre-Execution Backups (`[hooks.apply.pre]` & `[hooks.re-add.pre]`)
Pre-execution hooks run automatically before changes are written to disk:
- **`[hooks.apply.pre]`**: 
  1. **Conflict Protection**: Intercepts changes to protected directories (e.g., `~/.config/zed`, `~/.config/vicinae`) where local changes must never be overwritten without explicit choice. Prompts interactively with:
     - `1) re-add` — Preserves local home changes and syncs them into the chezmoi source repo.
     - `2) apply (overwrite)` — Discards local home changes and overwrites from the repository.
     - `3) diff` — Views differences between the repository and local home file.
     - `4) cancel` — Immediately aborts `chezmoi apply` without modifying any file.
  2. **Automated Backup**: Creates timestamped snapshots in `$HOME` before `chezmoi apply` writes repository changes to your machine.
- **`[hooks.re-add.pre]`**: Backs up existing files in the source repository (`~/.local/share/chezmoi`) before `chezmoi re-add` syncs modified files from `$HOME`.

Backups are saved to:
```text
~/.cache/chezmoi/backups/<YYYYMMDD_HHMMSS>/
```
If you ever accidentally overwrite a file, you can immediately recover the previous version from this directory.

### 3. Shell Wrapper with Affected Files Preview & On-Demand Diff
A safe `chezmoi` wrapper is defined in `functions.zsh`. It intercepts both `apply` and `re-add`:

- **For `chezmoi apply`**:
  1. Checks if differences exist using `chezmoi verify`.
  2. Lists affected files that will be modified in `$HOME` (`chezmoi status`).
  3. Prompts: `Apply changes? [y,n,d,q,?]`.
  4. Entering `d` (or `1`) displays the pending diff, `y` applies changes, and `n`, `q`, or empty/space/Enter cancels.
  
- **For `chezmoi re-add`**:
  1. Checks if differences exist using `chezmoi verify`.
  2. Lists modified files that will be updated in the repository (`~/.local/share/chezmoi`).
  3. Prompts: `Re-add changes to repository? [y,n,d,q,?]`.
  4. Entering `d` (or `1`) displays the reverse diff (`chezmoi diff --reverse`), showing exactly what local edits will be brought into the repo, `y` confirms and re-adds, and `n`, `q`, or empty/space/Enter cancels.

*(Note: Passing `-n`, `--dry-run`, `-f`, `--force`, `-h`, or `--help` automatically bypasses the confirmation prompt.)*

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
| `chezmoi re-add` | Update repository with modified files from `$HOME` (with interactive prompts & backup) |
| `chezmoi merge <path>` | Open a 3-way merge tool to resolve conflicts interactively |
| `chezmoi edit <path>` | Edit a managed file directly in `$EDITOR` inside the repository |
| `chezmoi add <path>` | Start managing a new configuration file in Chezmoi |
| `chezmoi cd` | Open a shell directly inside `~/.local/share/chezmoi` |
| `gac '<msg>'` | Quick Git add & commit in any repo (`functions.zsh`) |
| `gacp '<msg>'` | Quick Git add, commit & push in any repo (`functions.zsh`) |

---

## 🌐 Linking to a Remote Git Repository & Automated Git Sync

When you are ready to push your dotfiles to GitHub, GitLab, or Codeberg:

```bash
# 1. Open the repository directory
chezmoi cd

# 2. Add your remote repository URL
git remote add origin git@github.com:0king/dotfiles.git

# 3. Verify author identity (ensuring no private info in commit logs)
git log -1 --format="Author: %an <%ae>"

# 4. Push your main branch and set upstream tracking
git branch -M main
git push -u origin main
```

### ⚡ Automated Git Commit & Push (`[git]` & Hooks)
Automated Git synchronization is configured in `.chezmoi.toml.tmpl` and `~/.config/chezmoi/chezmoi.toml`:
```toml
[git]
    autoAdd = true
    autoCommit = true
    autoPush = true
```

- **`autoAdd = true`**: Automatically runs `git add` whenever managing files with `chezmoi add`.
- **`autoCommit = true`**: Automatically stages and commits source modifications with an informative commit message when using `chezmoi add`, `chezmoi edit`, or `chezmoi forget`.
- **`autoPush = true`**: Automatically pushes all commits directly to your remote repository once upstream tracking is configured (`git push -u origin main`).
- **Post-Apply Hook (`[hooks.apply.post]`)**: Whenever `chezmoi apply` finishes successfully, an automated hook verifies if any changes remain uncommitted in `~/.local/share/chezmoi` (such as direct repository or template edits). If changes are found, they are automatically staged, committed, and pushed. Dry runs (`--dry-run` / `-n`) are safely detected and skipped.
- **Gitleaks Pre-Commit Protection**: Every automatic commit is scanned by `.githooks/pre-commit` before completion, guaranteeing secrets and API keys are never accidentally committed or pushed.
- **Zsh Helper (`gacp`)**: Defined in `functions.zsh` for quick direct repository edits: `gacp "commit message"` runs `git add -A && git commit -m "$*" && git push`.

---

## 🤖 Universal AI Agents & Skills Architecture (`~/.config/ai`)

A single source of truth for global agent guidelines (`AGENTS.md`), modular skills (`SKILL.md`), modular rules, and reusable prompts across all AI coding assistants on this computer:
- **Antigravity / Gemini CLI**
- **Cursor**
- **Claude Code**
- **VS Code & GitHub Copilot**
- **Aider**
- **Cline / Roo Code**
- **Kilo**
- **OpenCode**
- **Universal Fallbacks**: `~/.agents`, `~/.ai`, and `~/.config/agents` (automatically covers future tools)

### 📂 Directory Layout
```text
~/.config/ai/
├── AGENTS.md                  # Canonical global guidelines & rules for all AI agents
├── rules/                     # Modular rule files (.md / .mdc)
├── skills/                    # Modular agent skills (SKILL.md, scripts, references)
│   ├── audit-threat/
│   ├── audit-rust-threat/
│   └── audit-cpp-node-threat/
└── prompts/                   # Reusable prompt templates and system prompts
```

### 🔄 Day-to-Day Operations

#### 1. When a File is Modified in `$HOME` (or via any tool's symlink)
If an AI agent or editor updates `~/.config/ai/AGENTS.md`, a skill, or a rule (even through `~/.cursorrules` or `~/.gemini/config/AGENTS.md`):
```bash
# 1. Inspect what changed
chezmoi status
chezmoi diff

# 2. Sync back to Chezmoi repository
chezmoi re-add ~/.config/ai
# (or re-add a single file: chezmoi re-add ~/.config/ai/AGENTS.md)
```
*Chezmoi will stage, verify with `gitleaks`, commit, and push automatically.*

#### 2. When a File is Modified in the Chezmoi Repository
If you edit files in `~/.local/share/chezmoi/private_dot_config/ai/`:
```bash
chezmoi diff
chezmoi apply
```
*The automated post-apply hook `run_after_setup-ai-symlinks.sh.tmpl` automatically runs `sync-ai-agents` to ensure all agent symlinks are verified and refreshed.*

#### 3. When a New AI Agent is Installed
Run the sync script to automatically detect and create all necessary symlinks:
```bash
# Audit status (dry run)
sync-ai-agents --check

# Create / update symlinks
sync-ai-agents
```
To add support for a new tool that uses custom paths, edit `private_dot_local/bin/executable_sync-ai-agents`, add the target paths using `link_target`, and run `chezmoi apply`.

### 🧠 Instructions for AI Agents: Creating Skills & Rules

- **Adding a Skill**: Create a directory `~/.config/ai/skills/<skill-name>/` containing `SKILL.md` with YAML frontmatter (`name`, `description`), optional `scripts/` (executable helper tools), and `references/` (detailed documentation). Always write descriptions in third-person.
- **Adding Global Rules**: Edit `~/.config/ai/AGENTS.md` directly.
- **Adding Modular Rules**: Place `.md` files in `~/.config/ai/rules/<rule-name>.md`.
- **Adding Prompts**: Place templates in `~/.config/ai/prompts/<prompt-name>.md`.
- **Always Document Changes**: Summarize all modifications, files affected, and rationale per the global change documentation rule.

