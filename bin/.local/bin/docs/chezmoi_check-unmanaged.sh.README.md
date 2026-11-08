# chezmoi_check-unmanaged.sh

An interactive utility and `chezmoi status` companion that detects and alerts about **newly added** unmanaged files and directories in locations already tracked by chezmoi (e.g. `~/.local/bin`, `~/.config/nvim`, `~/.config/ai/skills`, etc.), prompting whether they should be tracked in chezmoi or ignored.

### Background & Problem

Standard `chezmoi status` only inspects files that are already part of chezmoi's source state. If a new script or configuration file is created inside an existing managed directory (such as `~/.local/bin/my-script` or `~/.config/nvim/lua/plugins/new-plugin.lua`), `chezmoi status` remains completely silent about it.

At the same time, users often have existing tools and binaries in managed directories (e.g. `uv`, `mise`, `bat`, `fd`, etc.) that they intentionally do not manage via chezmoi. Nagging about these pre-existing files on every status run violates the status quo.

### Key Features

1. **Respects the Status Quo (Baseline Tracking)**:
   - Maintains a baseline snapshot of known unmanaged files in `~/.local/state/chezmoi/known_unmanaged.txt`.
   - On initial run, records existing unmanaged files into the baseline so you are never bothered with pre-existing items.
   - When you skip an unmanaged file (`[n]o` or <kbd>Enter</kbd>), it is remembered in the baseline and will not be prompted again.
   - Stale entries (files deleted or later added to chezmoi) are automatically cleaned up from the baseline.

2. **Alerts Only on New Stuff**:
   - Compares the current unmanaged state against the baseline.
   - Only genuinely **new** unmanaged files trigger a notification and interactive prompt.
   - If no new files exist, runs 100% silently with zero overhead.

3. **Automatic Managed Directory Discovery**:
   - Queries `chezmoi managed --include=files` to locate all directories holding tracked files.
   - Intelligently prunes child directories when their parent is already scanned (e.g. scanning `.local/bin` covers `.local/bin/code`, `.local/bin/docs`).
   - Excludes loose root files in `$HOME` (e.g. `.zshenv`) to avoid scanning unrelated directories across your home folder.

4. **Scoped Directory Support**:
   - Accepts specific path arguments (e.g. `~/.local/bin` or `.config/nvim`) to check only targeted locations.

5. **Seamless Chezmoi Status & Shell Integration**:
   - Integrated into the `chezmoi()` function in `~/.config/zsh/functions.zsh`.
   - Running `chezmoi status` or the alias `czs` in an interactive terminal automatically runs standard `chezmoi status` followed by the new file check.
   - Completely transparent in non-interactive environments, pipelines, scripts, and chezmoi hooks (skips prompting when not a TTY).

6. **Interactive Prompt Actions**:
   - **`[y]es`**: Runs `chezmoi add <file>` to track the file immediately.
   - **`[n]o`**: Skips the file and remembers it in the baseline so you aren't asked again (default on <kbd>Enter</kbd>).
   - **`[i]gnore`**: Appends the target path to `.chezmoiignore` and marks it known.
   - **`[a]ll`**: Adds the current file and all remaining new files to chezmoi.
   - **`[q]uit`**: Exits prompt immediately (unhandled files will prompt on next run).
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
If any new unmanaged files exist in managed directories, they will be listed with an interactive prompt. If none exist, output is clean and quiet.

To bypass the unmanaged check when running status:
```bash
chezmoi status --no-unmanaged
```

#### 2. Standalone Script Usage
Run directly from terminal:
```bash
# Scan for new unmanaged files and prompt interactively
chezmoi_check-unmanaged.sh

# Scan only ~/.local/bin for new files
chezmoi_check-unmanaged.sh ~/.local/bin

# Inspect ALL unmanaged files (ignoring the baseline)
chezmoi_check-unmanaged.sh --all

# Update/reset the baseline snapshot with all currently existing unmanaged files
chezmoi_check-unmanaged.sh --snapshot

# Preview new unmanaged files without prompting (check-only mode)
chezmoi_check-unmanaged.sh --check-only

# Run 'chezmoi status' first, then prompt for new unmanaged files
chezmoi_check-unmanaged.sh --status

# Display help
chezmoi_check-unmanaged.sh --help
```

### Options Overview

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-c, --check-only` | List new unmanaged files without interactive prompt | `false` |
| `-s, --status` | Run standard `chezmoi status` first | `false` |
| `-a, --all` | Check all unmanaged files, ignoring the baseline | `false` |
| `--snapshot` | Re-snapshot all current unmanaged files into baseline | `false` |
| `--reset-baseline` | Alias for `--snapshot` | `false` |
| `-h, --help` | Show usage instructions | — |
| `[PATHS...]` | One or more specific directories/files to scan | All managed directories |
