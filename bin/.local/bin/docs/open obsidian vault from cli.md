---
title: "New chat"
source: "https://gemini.google.com/app/5696aecfca5fa5bc?hl=en-IN"
author:
published:
created: 2026-08-20
description: "Gemini conversation with 8 messages"
---
**You**

how open obsidian vault from cli

---

**Gemini**

To open an Obsidian vault directly from the command line, use Obsidian's custom URI scheme (`obsidian://open?...`) or OS-specific launch commands.

**1\. Using the URI Protocol (Recommended)**

Pass the URI using your OS default handler. You can identify the vault by its **name** or its **absolute path**.

- **macOS:**
	```
	# By vault name
	open "obsidian://open?vault=MyVaultName"
	# By vault path
	open "obsidian://open?path=/Users/username/Documents/MyVault"
	# Open a specific note inside the vault
	open "obsidian://open?vault=MyVaultName&file=Daily%20Notes%2F2026-08-20"
	```
- **Linux:**
	```
	# By vault name
	xdg-open "obsidian://open?vault=MyVaultName"
	# By vault path
	xdg-open "obsidian://open?path=/home/username/Documents/MyVault"
	```
- **Windows (PowerShell / Command Prompt):**
	```
	# PowerShell
	Start-Process "obsidian://open?vault=MyVaultName"
	# CMD
	start "" "obsidian://open?vault=MyVaultName"
	```
- **WSL2 (Windows Subsystem for Linux):**
	```
	# Using wslview (from wslu package)
	wslview "obsidian://open?vault=MyVaultName"
	# Or via Windows PowerShell interop
	powershell.exe -Command "Start-Process 'obsidian://open?vault=MyVaultName'"
	```

**2\. Open Current Directory (Shell Function / Alias)**

Add this shell helper to your `.bashrc` or `.zshrc` to open the current working directory as a vault by typing `obsidian` or `obs`:

```
# For macOS
obsidian() {
  local target_path="${1:-$PWD}"
  open "obsidian://open?path=$(python3 -c "import urllib.parse, os; print(urllib.parse.quote(os.path.abspath('$target_path')))")"
}

# For Linux
obsidian() {
  local target_path="${1:-$PWD}"
  xdg-open "obsidian://open?path=$(python3 -c "import urllib.parse, os; print(urllib.parse.quote(os.path.abspath('$target_path')))")"
}
```

**3\. Using `obsidian-cli` (Third-Party CLI Utility)**

If you want deeper terminal integration (creating notes, searching, appending tasks directly without GUI focus), install the community CLI wrapper via npm or Homebrew:

```
# Install via npm
npm install -g obsidian-cli

# Usage
obsidian open "MyVaultName"
```

Want to set up shell aliases or automation scripts to create/append daily notes from the terminal?

---

**You**

create a desktop shortcut using xdg-open "obsidian://open?vault=MyVaultName" for ubuntu 26

---

**Gemini**

Here is how to create the `.desktop` shortcut on Ubuntu.

**1\. Create the Desktop Entry File**

Run this command in your terminal to generate `obsidian-vault.desktop` directly on your Desktop:

```
cat << 'EOF' > ~/Desktop/obsidian-vault.desktop
[Desktop Entry]
Version=1.0
Type=Application
Name=Obsidian - MyVaultName
Comment=Open MyVaultName in Obsidian
Exec=xdg-open "obsidian://open?vault=MyVaultName"
Icon=obsidian
Terminal=false
StartupNotify=true
Categories=Office;Utility;
EOF
```

*(Replace `MyVaultName` with your actual vault name. If your vault name contains spaces or special characters, URL-encode them, e.g., `My%20Vault`)*.

**2\. Make It Executable & Allow Launching**

GNOME requires explicit permissions before it will execute desktop files from the Desktop directory:

```
# Make the file executable
chmod +x ~/Desktop/obsidian-vault.desktop

# Trust and allow launching in GNOME
gio set ~/Desktop/obsidian-vault.desktop metadata::trusted true
```

*Alternatively, you can right-click the file on your desktop and select **"Allow Launching"**.*

**3\. (Optional) Add to the Application Launcher / Dash**

If you also want this shortcut searchable in the GNOME app grid/dock alongside your other applications, copy it to your local applications directory:

```
cp ~/Desktop/obsidian-vault.desktop ~/.local/share/applications/
update-desktop-database ~/.local/share/applications/
```

---

**You**

write a bash script to create multiple desktop files for each vault

---

**Gemini**

Here is a bash script that generates `.desktop` shortcuts for your vaults. It automatically URL-encodes vault names (handling spaces and special characters), sets execution permissions, and marks them as trusted for GNOME.

### Option 1: Define Vault Names Manually

Save this as `create_obsidian_shortcuts.sh`:

```
#!/usr/bin/env bash
set -euo pipefail

# 1. Define your vault names here
VAULTS=(
    "Work"
    "Personal Notes"
    "Research & Dev"
)

# 2. Choose destination directories (Desktop, App Menu, or both)
TARGET_DIRS=(
    "$HOME/Desktop"
    "$HOME/.local/share/applications"
)

# Function to URL-encode vault names for the URI scheme
url_encode() {
    python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1]))" "$1"
}

# Function to generate a safe filename (e.g. "Personal Notes" -> "personal-notes")
slugify() {
    echo "$1" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/^-//;s/-$//'
}

# Ensure target directories exist
for dir in "${TARGET_DIRS[@]}"; do
    mkdir -p "$dir"
done

for vault in "${VAULTS[@]}"; do
    encoded_vault=$(url_encode "$vault")
    slug_name=$(slugify "$vault")
    filename="obsidian-${slug_name}.desktop"

    for target_dir in "${TARGET_DIRS[@]}"; do
        file_path="${target_dir}/${filename}"

        cat <<EOF > "$file_path"
[Desktop Entry]
Version=1.0
Type=Application
Name=Obsidian - ${vault}
Comment=Open ${vault} vault in Obsidian
Exec=xdg-open "obsidian://open?vault=${encoded_vault}"
Icon=obsidian
Terminal=false
StartupNotify=true
Categories=Office;Utility;
EOF

        chmod +x "$file_path"

        # Trust the desktop file if it's placed on the Desktop (for GNOME)
        if [[ "$target_dir" == "$HOME/Desktop" ]]; then
            gio set "$file_path" metadata::trusted true 2>/dev/null || true
        fi
    done

    echo "Created shortcut for vault: \"${vault}\""
done

# Refresh desktop database for app menu visibility
update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true

echo "Done! Shortcuts generated on Desktop and in the Application Menu."
```

### Option 2: Auto-Detect All Existing Vaults

Obsidian tracks all registered vaults in `~/.config/obsidian/obsidian.json`. If you have `jq` installed, you can use this script to auto-generate shortcuts for every vault currently recognized by Obsidian without listing them manually:

```
#!/usr/bin/env bash
set -euo pipefail

OBSIDIAN_CONFIG="$HOME/.config/obsidian/obsidian.json"

if [[ ! -f "$OBSIDIAN_CONFIG" ]]; then
    echo "Error: Obsidian configuration not found at $OBSIDIAN_CONFIG"
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo "Error: 'jq' is required for auto-detection. Install via: sudo apt install jq"
    exit 1
fi

mkdir -p "$HOME/Desktop" "$HOME/.local/share/applications"

# Extract absolute paths of all vaults registered in Obsidian
jq -r '.vaults[] | .path' "$OBSIDIAN_CONFIG" | while IFS= read -r vault_path; do
    [[ -z "$vault_path" || ! -d "$vault_path" ]] && continue

    vault_name=$(basename "$vault_path")
    encoded_path=$(python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1]))" "$vault_path")
    slug_name=$(echo "$vault_name" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/^-//;s/-$//')
    filename="obsidian-${slug_name}.desktop"

    for target_dir in "$HOME/Desktop" "$HOME/.local/share/applications"; do
        file_path="${target_dir}/${filename}"

        cat <<EOF > "$file_path"
[Desktop Entry]
Version=1.0
Type=Application
Name=Obsidian - ${vault_name}
Comment=Open ${vault_name} vault in Obsidian
Exec=xdg-open "obsidian://open?path=${encoded_path}"
Icon=obsidian
Terminal=false
StartupNotify=true
Categories=Office;Utility;
EOF

        chmod +x "$file_path"

        if [[ "$target_dir" == "$HOME/Desktop" ]]; then
            gio set "$file_path" metadata::trusted true 2>/dev/null || true
        fi
    done

    echo "Generated: Obsidian - ${vault_name}"
done

update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
echo "All vaults synced successfully."
```

### Running the Script

```
# Make the script executable
chmod +x create_obsidian_shortcuts.sh

# Run it
./create_obsidian_shortcuts.sh
```

---

**You**

why need url\_encode and slugify

---

**Gemini**

They solve two distinct formatting problems: one for the **Obsidian URI protocol** and one for the **Linux filesystem**.

### 1\. Why url\_encode is needed

Obsidian uses a custom URI scheme (`obsidian://...`), which follows standard URL syntax rules (RFC 3986).

- **The Problem:** URLs cannot contain raw spaces, ampersands, question marks, hashes, or non-ASCII characters. If a vault is named `Research & Dev`, a raw URI looks like:
	```
	obsidian://open?vault=Research & Dev
	```
	In standard URI parsing:
	- The space breaks the argument or gets cut off.
		- The `&` is treated as a delimiter for a new query parameter (i.e., `vault=Research` and `Dev` with no value). Obsidian fails to find the vault.
- **The Solution:** URL-encoding converts reserved or unsafe characters into percent-encoded hex values:
	```
	obsidian://open?vault=Research%20%26%20Dev
	```
	Obsidian decodes this back to the exact string `"Research & Dev"`.

### 2\. Why slugify is needed

`slugify` transforms human-readable vault names into clean, predictable filenames for the `.desktop` files (e.g., `~/Desktop/obsidian-research-dev.desktop`).

- **The Problem:** Vault names often include spaces, uppercase letters, slashes, punctuation, or special symbols (e.g., `Work / 2026! (Notes)`). Using raw names in file paths causes several issues:
	- Slashes (`/`) break filesystem paths by creating non-existent subdirectories.
		- Spaces and shell metacharacters (`!`, `(`, `)`, `&`, `$`) require tedious escaping in scripts, aliases, or CLI tab-completion.
		- Inconsistent casing makes shell navigation and cleanup harder.
- **The Solution:** Slugification strips out invalid/problematic characters, replaces spaces with hyphens, and downcases everything:
	- `"Personal Notes"` $\rightarrow$ `obsidian-personal-notes.desktop`
		- `"Research & Dev"` $\rightarrow$ `obsidian-research-dev.desktop`

### Quick Comparison

| Function | Target | Input Example | Output Example | Why It's Critical |
| --- | --- | --- | --- | --- |
| **`url_encode`** | URI string in `Exec=` | `Personal Notes` | `Personal%20Notes` | Prevents URI parsers from breaking on spaces and query delimiters (`&`, `?`). |
| **`slugify`** | Linux filename | `Personal Notes` | `personal-notes` | Prevents filesystem errors, broken paths, and shell escaping headaches. |