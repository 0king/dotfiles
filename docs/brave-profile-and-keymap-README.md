# 🌐 Unified Brave & Chrome Profile Settings & Keymaps Reference

Documentation and disaster-recovery guide for managing, exporting, and restoring **Brave** (`brave-origin`, `brave-browser`) and **Google Chrome** profile preferences, native accelerators, extension shortcuts, and in-extension keybindings (**Vimium** & **Vimium C**) within `chezmoi`.

---

## 📌 Architecture: What Can & Cannot Be Synced

Chromium and Brave split profile data across three distinct tiers:

| Tier | Component | Cloud / Git Safe? | Storage & Mechanism |
| :--- | :--- | :--- | :--- |
| **Tier 1: Portable Plaintext / JSON** | • Brave Native Accelerators (`brave.accelerators`)<br>• Extension Shortcuts (`extensions.commands`)<br>• General UI Preferences (vertical tabs, sidebar, theme)<br>• Default search engines & shields settings | ✅ **100% Cloud-Safe** (Sanitized) | Stored in `Preferences.json` and `shortcuts.json`. Cleanly version-controlled in Git. |
| **Tier 2: In-Extension Custom Mappings** | • **Vimium** custom key mappings<br>• **Vimium C** custom key mappings | ✅ **100% Cloud-Safe** | Extracted into human-readable plaintext config files (`vimium_keymappings.txt`). |
| **Tier 3: Cryptographically OS/Machine-Bound** | • Passwords (`Login Data`)<br>• Session Cookies (`Cookies`)<br>• Payment cards (`Web Data`)<br>• Brave Rewards / BAT state<br>• Brave Crypto Wallet (`BraveWallet/`) | ❌ **Excluded (Never pushed to cloud)** | Encrypted with system `os_crypt` (GNOME Keyring / DPAPI). Stripped automatically by the sync tool. |

---

## 🚀 The CLI Utility: `browser-chrome-brave_export-import-settings.sh`

Located at: `~/.local/bin/browser-chrome-brave_export-import-settings.sh`  
Managed in Chezmoi at: `private_dot_local/bin/executable_browser-chrome-brave_export-import-settings.sh`

### 1. Interactive Mode (Default)
Simply run the script with no arguments to launch the interactive TUI menu (powered by `fzf` or clean interactive fallback):
```bash
browser-chrome-brave_export-import-settings.sh
```

Menu options include:
1. **Export Settings**: Cloud-safe extraction of sanitized preferences, shortcuts, and Vimium keymaps.
2. **Import / Restore Settings**: Restores preferences into the browser, automatically backing up target files and clearing stale machine-bound HMACs.
3. **List Profiles**: Displays all detected profiles with shortcut counts and friendly names.
4. **Dry-Run Export**: Previews changes without writing to disk.

### 2. Scripted / Headless Mode
```bash
# List profiles for active browser
browser-chrome-brave_export-import-settings.sh --list

# Export all profiles
browser-chrome-brave_export-import-settings.sh --export --profile all

# Export only the default profile
browser-chrome-brave_export-import-settings.sh --export --profile Default

# Restore settings into a specific profile
browser-chrome-brave_export-import-settings.sh --import --profile Default

# Dry-run restoration
browser-chrome-brave_export-import-settings.sh --import --profile Default --dry-run
```

---

## ⌨️ Shortcuts & Keymaps Quick Reference

### 1. Brave Native Accelerators (`Default` Profile)

| Action | Command ID | Shortcuts |
| :--- | :--- | :--- |
| **Next Tab (MRU)** | `34062` | `Control + Tab`, `Control + KeyG`, `Control + Shift + KeyD` |
| **Previous Tab (MRU)** | `34063` | `Control + Shift + Tab`, `Control + Shift + KeyG` |
| **Next Tab (Linear)** | `34016` | `Control + PageDown`, `Control + ArrowRight`, `Control + Shift + KeyF` |
| **Previous Tab (Linear)** | `34017` | `Control + PageUp`, `Control + ArrowLeft`, `Control + Shift + KeyS` |
| **Quick Commands / Palette**| `56301` | `Control + Space` |
| **Toggle Vertical Tabs** | `34100` | `Alt + Shift + KeyC` |
| **New Tab** | `34014` | `Control + KeyT` |
| **Close Tab** | `34015` | `Control + KeyW`, `Control + F4` |
| **Reopen Closed Tab** | `34028` | `Control + Shift + KeyT` |
| **Hard Reload (Bypass Cache)**| `33007` | `Control + Shift + KeyR`, `Control + F5`, `Shift + F5` |
| **Focus Address Bar** | `39001` | `Control + KeyL`, `Alt + KeyD` |
| **Toggle Bookmarks Bar** | `40009` | `Control + Shift + KeyB` |
| **Developer Tools** | `40004` | `Control + Shift + KeyI`, `F12` |

### 2. Extension Command Shortcuts (`Default` Profile)

| Extension | Command | Shortcut | Scope |
| :--- | :--- | :--- | :--- |
| **Bitwarden** | Open Popup | `Ctrl + Shift + B` | In-Browser |
| **Bitwarden** | Autofill Login | `Alt + Shift + L` | In-Browser |
| **Bitwarden** | Generate Password | `Alt + Shift + 9` | In-Browser |
| **Dark Reader** | Toggle Dark Mode | `Alt + Shift + D` | In-Browser |
| **Obsidian Web Clipper** | Clip Action | `Alt + Shift + O` | In-Browser |
| **Obsidian Web Clipper** | Toggle Highlighter | `Alt + Shift + H` | In-Browser |
| **Raindrop.io** | Side Panel | `Ctrl + Period` | In-Browser |
| **Raindrop.io** | Bookmark Current Page | `Ctrl + Shift + X` | In-Browser |
| **Simple Translate** | Translate Selection | `Ctrl + Shift + Space` | In-Browser |
| **FireShot** | Capture Visible Page | `Alt + Shift + 3` | In-Browser |
| **FireShot** | Capture Entire Page | `Alt + Shift + 1` | In-Browser |
| **FireShot** | Capture Selection | `Alt + Shift + 4` | In-Browser |

---

## 🧩 In-Extension Keybindings (Vimium & Vimium C)

Custom mappings are extracted to `vimium_keymappings.txt` and `vimium_c_keymappings.txt` within each profile directory.

### Vimium Key Mappings (`Default` Profile)
```text
# Hints & Navigation
map F LinkHints.activateMode
map f LinkHints.activateModeToOpenInNewTab
map h LinkHints.activateMode action=hover
map <a-i> LinkHints.activateMode action=focus
map c LinkHints.activateMode action=copy-text

# History Navigation
map h goBack
map l goForward

# Vomnibar (Fuzzy Search & Bookmarks)
map o Vomnibar.activateInNewTab
map O Vomnibar.activate
map b Vomnibar.activateBookmarksInNewTab
map B Vomnibar.activateBookmarks

# Tab Management
map <a-,> moveTabLeft count=99
map <a-.> moveTabRight count=99
map <a-k> nextTab
map <a-j> previousTab
```

### Vimium C Key Mappings (`Profile 4`)
```text
map f LinkHints.activateOpenInNewTab
map F LinkHints.activateOpen
```

---

## 🔄 Disaster Recovery: Restoring on a Fresh Machine

When setting up a new computer or recovering from a system wipe:

1. **Install Browser**: Install Brave (`brave-origin` or `brave-browser`) and open it once so initial directories exist, then **close it completely**.
2. **Apply Chezmoi**:
   ```bash
   chezmoi apply
   ```
   This deploys `browser-chrome-brave_export-import-settings.sh` into `~/.local/bin/`.
3. **Restore Preferences**:
   ```bash
   browser-chrome-brave_export-import-settings.sh --import --profile all
   ```
   *The script automatically strips stale machine-bound HMAC hashes (`protection`), allowing the browser to adopt your settings without triggering corruption resets.*
4. **Launch Brave**:
   All vertical tab settings, dark mode preferences, shields configurations, native shortcuts, and extension command bindings will be restored.
