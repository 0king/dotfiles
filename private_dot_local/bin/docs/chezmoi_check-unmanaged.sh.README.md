# chezmoi_check-unmanaged.sh

An interactive utility and `chezmoi status` companion that detects and alerts about unmanaged / new files in directories already tracked by chezmoi (e.g. `~/.local/bin`, `~/.config/nvim`, `~/.config/zsh`, etc.), prompting whether they should be tracked in chezmoi or ignored.

### Background & Problem

Standard `chezmoi status` only inspects files that are already part of chezmoi's source state. If a new script or configuration file is created inside an existing managed directory (such as `~/.local/bin/my-script` or `~/.config/nvim/lua/plugins/new-plugin.lua`), `chezmoi status` remains completely silent about it.

`chezmoi_check-unmanaged.sh` solves this by automatically identifying all managed directory roots (excluding loose `$HOME` files), checking for unmanaged entries via `chezmoi unmanaged`, and presenting an interactive prompt to manage them immediately.

### Key Features

1. **Automatic Managed Directory Discovery**:
   - Queries `chezmoi managed --include=files` to locate all directories holding tracked files.
   - Intelligently prunes child directories when their parent is already scanned (e.g. scanning `.local/bin` covers `.local/bin/code`, `.local/bin/docs`).
   - Excludes loose root files in `$HOME` (e.g. `.zshenv`) to avoid scanning unrelated directories across your home folder.

2. **Scoped Directory Support**:
   - Accepts specific path arguments (e.g. `~/.local/bin` or `.config/nvim`) to check only targeted locations.

3. **Seamless Chezmoi Status & Shell Integration**:
   - Integrated into the `chezmoi()` function in `~/.config/zsh/functions.zsh`.
   - Running `chezmoi status` or the alias `czs` in an interactive terminal automatically runs standard `chezmoi status` followed by the untracked file check.
   - Completely transparent in non-interactive environments, pipelines, scripts, and chezmoi hooks (skips prompting when not a TTY).

4. **Interactive Prompt Actions**:
   - **`[y]es`**: Runs `chezmoi add <file>` to track the file immediately.
   - **`[n]o`**: Skips the file for now (leaves unmanaged, default on Enter).
   - **`[i]gnore`**: Appends the target path to `.chezmoiignore` so you aren't alerted again.
   - **`[a]ll`**: Adds the current file and all remaining untracked files without further prompting.
   - **`[q]uit`**: Exits prompt immediately.
   - **`[?]help`**: Displays option reference.

---

### Usage

#### 1. Via `chezmoi status` or `czs` (Recommended)
Simply run your normal status command in `zsh`:
```bash
czs
# or
chezmoi status
```
If any unmanaged files exist in managed directories, they will be listed with an interactive prompt.

To bypass the unmanaged check when running status:
```bash
chezmoi status --no-unmanaged
```

#### 2. Standalone Script Usage
Run directly from terminal:
```bash
# Scan all managed directories and prompt interactively
chezmoi_check-unmanaged.sh

# Scan only ~/.local/bin
chezmoi_check-unmanaged.sh ~/.local/bin

# Preview unmanaged files without prompting (check-only mode)
chezmoi_check-unmanaged.sh --check-only

# Run 'chezmoi status' first, then prompt for unmanaged files
chezmoi_check-unmanaged.sh --status

# Display help
chezmoi_check-unmanaged.sh --help
```

### Options Overview

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-c, --check-only` | List unmanaged files without interactive prompt | `false` |
| `-s, --status` | Run standard `chezmoi status` first | `false` |
| `-h, --help` | Show usage instructions | — |
| `[PATHS...]` | One or more specific directories/files to scan | All managed directories |
