#!/usr/bin/env bash

set -euo pipefail

BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/.local/share/applications"

# Ensure target directories exist
mkdir -p "$BIN_DIR" "$APP_DIR"

# 1. Create the browser-picker script
PICKER_SCRIPT="$BIN_DIR/browser-picker"
echo "Creating $PICKER_SCRIPT..."

cat << 'EOF' > "$PICKER_SCRIPT"
#!/usr/bin/env bash

URL="$1"

# Define profile mappings. 
declare -A choices=(
    ["brave df"]="brave-origin --profile-directory=Default"
    ["brave secure"]="brave-origin --profile-directory=\"Profile 2\""
    ["brave shop"]="brave-origin --profile-directory=\"Profile 1\""
    ["brave tmp"]="brave-origin --profile-directory=\"Profile 3\""
    ["epiphany"]="epiphany"
    ["ff df"]="firefox -P default"
    ["ff tmp"]="firefox -P tmp"
)

# --- GUI Selection (Zenity for GNOME / kdialog for KDE) ---
if [ "$XDG_CURRENT_DESKTOP" = "KDE" ]; then
    args=()
    for key in "${!choices[@]}"; do
        args+=("$key" "$key")
    done
    choice=$(kdialog --title "Select Profile" --menu "Opening:\n${URL:-New Window}" "${args[@]}")
else
    choice=$(zenity --list --title="Select Profile" --text="Opening:\n${URL:-New Window}" \
        --column="Profile" "${!choices[@]}" --width=450 --height=700)
fi

# Execute with the bound profile flags
# Execute safely without eval 
if [ -n "$choice" ]; then 
  cmd="${choices[$choice]}" 
  if [ -z "$URL" ]; then 
    # Launch browser normally if no URL is provided 
    sh -c "$cmd &" 
  else 
    # Safely pass URL as positional argument $1 to avoid injection 
    sh -c "$cmd \"\$1\" &" _ "$URL" 
  fi 
fi
EOF

# Make the picker script executable
chmod +x "$PICKER_SCRIPT"

# 2. Create the Desktop Entries
echo "Creating .desktop shortcuts in $APP_DIR..."

cat << EOF > "$APP_DIR/browser-picker.desktop"
[Desktop Entry]
Version=1.0
Name=Browser Picker
GenericName=Web Browser Chooser
Exec=$BIN_DIR/browser-picker %u
Icon=$HOME/Desktop/fj/config/app-icons/browser.png
Terminal=false
Type=Application
MimeType=text/html;text/xml;application/xhtml+xml;x-scheme-handler/http;x-scheme-handler/https;
Categories=Network;WebBrowser;
EOF

cat << 'EOF' > "$APP_DIR/ff-df.desktop"
[Desktop Entry]
Type=Application
Name=ff default
Exec=firefox -P default %u
Icon=firefox
Terminal=false
Categories=Network;WebBrowser;
MimeType=text/html;text/xml;application/xhtml+xml;application/xml;
EOF

cat << 'EOF' > "$APP_DIR/ff-tmp.desktop"
[Desktop Entry]
Type=Application
Name=ff tmp
Exec=firefox -P tmp %u
Icon=firefox
Terminal=false
EOF

cat << 'EOF' > "$APP_DIR/bb-p1.desktop"
[Desktop Entry]
Type=Application
Name=bb P1
Comment=Default profile
Exec=brave-origin --profile-directory="Default" %u
Icon=$HOME/Desktop/fj/config/app-icons/brave1.png
Terminal=false
Categories=Network;WebBrowser;
MimeType=text/html;text/xml;application/xhtml+xml;application/xml;
EOF

cat << 'EOF' > "$APP_DIR/bb-secure.desktop"
[Desktop Entry]
Type=Application
Name=bb (Secure)
Comment=brave secure
Exec=brave-origin --profile-directory="Profile 2" %u
Icon=$HOME/Desktop/fj/config/app-icons/brave2.png
Terminal=false
Categories=Network;WebBrowser;
MimeType=text/html;text/xml;application/xhtml+xml;application/xml;
EOF

cat << 'EOF' > "$APP_DIR/bb-shopping.desktop"
[Desktop Entry]
Type=Application
Name=bb (shopping)
Comment=brave shopping
Exec=brave-origin --profile-directory="Profile 1" %u
Icon=$HOME/Desktop/fj/config/app-icons/brave3.png
Terminal=false
Categories=Network;WebBrowser;
MimeType=text/html;text/xml;application/xhtml+xml;application/xml;
EOF

cat << 'EOF' > "$APP_DIR/bb-tmp.desktop"
[Desktop Entry]
Type=Application
Name=bb tmp
Exec=brave-origin --profile-directory="Profile 3" %u
Icon=$HOME/Desktop/fj/config/app-icons/brave4.png
Terminal=false
EOF

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APP_DIR"
    echo "Desktop database updated."
else
    echo "update-desktop-database not found. Skipping mimetype registration."
fi

echo "Deployment complete."
