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