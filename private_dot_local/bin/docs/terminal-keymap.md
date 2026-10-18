# ⌨️ Unified Terminal Keymap & Actions Reference

Standardized keybindings, clipboard behaviors, and Vim navigation across **Kitty**, **Alacritty**, **WezTerm**, and **Ghostty**.

---

## 📌 Quick Reference Cheat Sheet

| Action | Shortcut | Ghostty | Kitty | Alacritty | WezTerm |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Copy on Select** | *Mouse highlight* | `copy-on-select = clipboard` | `copy_on_select clipboard` | `save_to_clipboard = true` | `CompleteSelection(...)` |
| **Select All** | `Ctrl + Shift + A` | `select_all` | `launch --type=clipboard` | Vi Mode Macro | `select_all_and_copy` |
| **Vim Mode** | `Ctrl + Shift + Space`<br>`Ctrl + Shift + X` | Neovim scrollback | Neovim pager overlay | Native `ToggleViMode` | Native `ActivateCopyMode` |
| **Copy** | `Ctrl + Shift + C`<br>`Ctrl + Insert` | `copy_to_clipboard:mixed` | `copy_to_clipboard` | `Copy` | `CopyTo("Clipboard")` |
| **Paste** | `Ctrl + Shift + V` | `paste_from_clipboard` | `paste_from_clipboard` | `Paste` | `PasteFrom("Clipboard")` |
| **Paste Selection** | `Shift + Insert` | `paste_from_selection` | `paste_from_selection` | `PasteSelection` | `PasteFrom("PrimarySelection")` |
| **Line Scroll Up** | `Ctrl + Shift + Up`<br>`Ctrl + Shift + K` | `scroll_page_lines:-1` | `scroll_line_up` | `ScrollLineUp` | `ScrollByLine(-1)` *(Safe override)* |
| **Line Scroll Down** | `Ctrl + Shift + Down`<br>`Ctrl + Shift + J` | `scroll_page_lines:1` | `scroll_line_down` | `ScrollLineDown` | `ScrollByLine(1)` |
| **Page Scroll Up** | `Shift + PageUp`<br>`Ctrl + Shift + PageUp` | `scroll_page_up` | `scroll_page_up` | `ScrollPageUp` | `ScrollByPage(-1)` |
| **Page Scroll Down** | `Shift + PageDown`<br>`Ctrl + Shift + PageDown` | `scroll_page_down` | `scroll_page_down` | `ScrollPageDown` | `ScrollByPage(1)` |
| **Scroll to Top** | `Shift + Home`<br>`Ctrl + Shift + Home` | `scroll_to_top` | `scroll_home` | `ScrollToTop` | `ScrollToTop` |
| **Scroll to Bottom** | `Shift + End`<br>`Ctrl + Shift + End` | `scroll_to_bottom` | `scroll_end` | `ScrollToBottom` | `ScrollToBottom` |
| **Search Buffer** | `Ctrl + Shift + F` | `start_search` | `show_scrollback` | `SearchForward` | `Search(...)` |
| **New Window** | `Ctrl + Shift + N` | `new_window` | `new_os_window` | `CreateNewWindow` | `SpawnWindow` |

---

## 🔍 Core Features & Behaviors

### 1. Automatic Copy-on-Select
Highlighting any text with the left mouse button immediately copies it to your **System Clipboard** (pasted with `Ctrl+V` or `Ctrl+Shift+V`) and **Primary Selection** (pasted with mouse middle click or `Shift+Insert`). No manual copy shortcut is required.

### 2. Select All (`Ctrl + Shift + A`)
Instantly captures and copies the complete scrollback history into your system clipboard:
- **Ghostty**: Visually highlights all terminal cells and triggers the clipboard copy.
- **Kitty**: Uses `launch --type=clipboard --stdin-source=@screen_scrollback` to dump all buffer lines directly into the clipboard.
- **Alacritty**: Automates a Vi mode macro (`ToggleViMode` ➔ `ScrollToTop` ➔ `ToggleLineSelection` ➔ `ScrollToBottom` ➔ `Copy`).
- **WezTerm**: Executes a custom Lua callback extracting all scrollback rows and stripping trailing whitespace with toast notification feedback. Also supports visual selection in Copy Mode starting precisely from Row 1, Column 1 to the bottom line (`a` / `Ctrl+A` / `A` or via Command Palette).

### 3. Unified Vim Mode (`Ctrl + Shift + Space` / `Ctrl + Shift + X`)
Activates modal keyboard navigation across all four terminals using two complementary architectures:
- **Native In-Terminal Vi Mode (Alacritty & WezTerm)**:
  - Cursor switches to an interactive rectangular cell.
  - Move using `h`, `j`, `k`, `l`, `w`, `b`, `0`, `$`, `Ctrl+u` (half page up), `Ctrl+d` (half page down), `g` / `Home` / `Shift+Home` (jump directly to Row 1, Column 1), `G` / `End` / `Shift+End` (jump to bottom end of line).
  - Select text using `v` (character selection), `V` (line selection), `Ctrl+v` (block selection), or `a` / `Ctrl+A` (select all cells from Row 1, Column 1 to bottom end), or `A` (select all lines).
  - Press `y` to yank to clipboard and exit.
  - Search using `/` (forward) or `?` (backward), stepping with `n`/`N`.
  - Exit with `i`, `Escape`, or `q`.
- **Neovim Pager Integration (Kitty & Ghostty)**:
  - Terminal scrollback opens inside an overlay window running **real Neovim** (`nvim`).
  - Provides full syntax highlighting, Neovim plugins, text objects, and clipboard registers (`+`).
  - Press `:q` or `q` to dismiss the pager and immediately return to your terminal prompt.

### 4. Safe Scrolling & Override Protection
- Both standard Arrow keys (`Up`/`Down`) and Vim navigation keys (`K`/`J`) with `Ctrl + Shift` scroll line-by-line.
- **WezTerm Safety**: In WezTerm, `Ctrl + Shift + K` defaults to `ClearScrollback 'ScrollbackOnly'` (which deletes terminal history). This dotfiles configuration explicitly overrides this binding to `ScrollByLine(-1)`, protecting you from accidental history loss.

---

## 📁 Configuration File Locations

- **Ghostty**: `~/.config/ghostty/config.ghostty` (source: `private_dot_config/ghostty/config.ghostty`)
- **Kitty**: `~/.config/kitty/kitty.conf` (source: `private_dot_config/kitty/kitty.conf`)
- **Alacritty**: `~/.config/alacritty/alacritty.toml` (source: `private_dot_config/alacritty/alacritty.toml.tmpl`)
- **WezTerm**: `~/.config/wezterm/config/keys.lua` (source: `private_dot_config/wezterm/config/keys.lua`)
