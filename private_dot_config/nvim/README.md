# 💤 LazyVim

A starter template for [LazyVim](https://github.com/LazyVim/LazyVim).
Refer to the [documentation](https://lazyvim.github.io/installation) to get started.

## Custom Clipboard & Editing Behavior

The configuration is customized to provide an intuitive **Copy**, **Cut**, and **Paste** workflow synced with the system clipboard, while preventing standard **Delete** operations from clobbering clipboard contents.

### Quick Reference

| Action | Keys | Description | System Clipboard (`+`) |
| :--- | :--- | :--- | :--- |
| **Copy** | `y`, `yy`, `y<motion>`, Visual `y` | Yank text | **Synced** (copies to system clipboard) |
| **Cut** | `c`, `cc`, `c<motion>`, `C`, Visual `c` | Cut text (remove & copy) | **Synced** (copies to system clipboard) |
| **Paste** | `p`, `P`, `gp`, `gP`, Visual `p` | Paste text | **Synced** (pastes from system clipboard) |
| **Delete** | `d`, `dd`, `d<motion>`, `x`, Visual `d` | Delete text | **Untouched** (stays in internal register) |

### Configuration Details

1. **Delete Isolation** — [`lua/config/options.lua`](lua/config/options.lua)
   - Sets `vim.opt.clipboard = ""` so standard deletions (`d`, `dd`, `dw`, `x`) do not overwrite the system clipboard or clobber text copied from outside applications.

2. **Copy Sync** — [`lua/config/autocmds.lua`](lua/config/autocmds.lua)
   - Employs a `TextYankPost` autocommand that automatically mirrors any yank (`operator == "y"`) into the system clipboard (`+` register).

3. **Paste & Cut Keymaps** — [`lua/config/keymaps.lua`](lua/config/keymaps.lua)
   - **Paste (`p`, `P`, `gp`, `gP`)**: Mapped in normal and visual modes to paste from the system clipboard (`"+p` / `"+P`) by default, while continuing to respect explicitly specified registers (such as `"ap`).
   - **Cut (`c`, `cc`, `C`)**: Mapped to true Cut (`"+d`, `"+dd`, `"+D`) in normal and visual modes to remove text from the buffer and copy it directly to the system clipboard, remaining in Normal mode.

---

## Command Palette (`legendary.nvim`)

The configuration integrates [legendary.nvim](https://github.com/mrjones2014/legendary.nvim) backed by `sqlite.lua` frecency sorting, providing a unified fuzzy-finder across Neovim keymaps, commands, functions, and autocmds.

### Shortcuts

| Shortcut | Mode | Action | Description |
| :--- | :--- | :--- | :--- |
| `<leader>p` | Normal (`n`) | `<cmd>CommandPalette<cr>` | Fuzzy-find all keymaps, commands & autocmds |
| `Alt + X` (`<A-x>`) | Normal (`n`), Visual (`x`), Insert (`i`) | `<cmd>CommandPalette<cr>` | Fast palette launcher (accessible directly in insert mode) |

### Design Notes & Terminal Compatibility
- **Why `Alt + X` instead of `Ctrl + Shift + P`**: Standard GUI command palette keybindings (`Ctrl + Shift + P`) conflict with terminal emulator defaults:
  - **Kitty**: Uses `kitty_mod + p` (`Ctrl + Shift + P`) as a multi-key chord prefix for hints kittens (`kitty_mod+p>...`).
  - **WezTerm**: Binds `Ctrl + Shift + P` to WezTerm's native command palette (`ActivateCommandPalette`).
  - **Ghostty & Windows Terminal**: Frequently bind `Ctrl + Shift + P` to terminal-level actions.
- Using **`Alt + X`** (the classic universal command launcher shortcut) and **`<leader>p`** ensures zero collisions with terminal emulator shortcuts or shell environments, preserves all default terminal behaviors, and provides instant access even while actively typing in Insert mode.

---

## Completion & Prose Editing (`lua/plugins/completion.lua`)

Automatic completion popups and inline hint text (ghost text) are disabled for plain text and markdown files (`.txt`, `.md`) to maintain a clean writing experience without distracting popups or accidental completions on Enter during prose editing.

### Behavior Summary

| Filetype | Extension | Auto Popup & Ghost/Hint Text | Enter (`<CR>`) Behavior | Manual Trigger (`<C-space>`) |
| :--- | :--- | :--- | :--- | :--- |
| `text`, `plaintext` | `.txt` | **Disabled** | Normal newline (no accept) | Available |
| `markdown` | `.md`, `.markdown` | **Disabled** | Normal newline (no accept) | Available |
| Code / Programming Languages | `.lua`, `.py`, `.rs`, `.ts`, etc. | **Enabled** | Accepts completion / newline | Available |

### Implementation Details
- Configures `saghen/blink.cmp` (`completion.menu.auto_show` and `completion.ghost_text.enabled`) to evaluate buffer filetype dynamically.
- Disables inline ghost text in prose files, ensuring Enter (`<CR>`) acts as a standard newline rather than accepting previewed completions.
- Includes a fallback configuration for `hrsh7th/nvim-cmp` (`autocomplete = false`) should the `nvim-cmp` extra ever be activated.
- Preserves manual trigger functionality (`<C-space>`) across all buffers.

---

## Statusline Line Count (`lua/plugins/lualine.lua`)

Replaces LazyVim's default clock/time chip in section `lualine_z` (bottom right) with the active buffer's total line count.

### Display Details

- **Icon**: `` (Nerd Font Powerline line number symbol `U+E0A1`).
- **Dynamic Calculation**: Retrieves the buffer line count dynamically via `vim.api.nvim_buf_line_count(0)`.
- **Alternative Format**: Can be customized to `#L` or other icons (e.g., ``) by updating the `icon` attribute in `lua/plugins/lualine.lua`.


