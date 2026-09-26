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
