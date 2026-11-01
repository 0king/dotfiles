# ubuntu_uninstall-app.sh

An interactive, multi-backend application uninstaller for Ubuntu supporting **APT**, **Snap**, and **Flatpak**.

### Key Features

1. **Strict System Package & Runtime Exclusion**:
   - Pre-computes a strict system exclusion set to prevent damaging the system.
   - **APT**: Automatically filters out packages with `Essential: yes`, `Priority: required/important`, auto-installed library dependencies (`apt-mark showauto`), system services, kernel/bootloader/firmware packages, and shared libraries (`lib*`, `gir1.2-*`). Only genuine user-facing applications (manually installed or providing desktop entries) are displayed.
   - **Snap**: Excludes base snaps (`bare`, `core*`), `snapd`, shared frameworks (`gtk-common-themes`, `gnome-*-*`, `kf6-*`, `mesa-*`, `ffmpeg-*`, `webkitgtk-*`), and system utilities.
   - **Flatpak**: Excludes system runtimes (`org.freedesktop.Platform.*`, `Mesa`, etc.) by querying applications exclusively.

2. **Interactive Search & Fuzzy Selection**:
   - Filter by keyword or browse all installed user applications.
   - Supports `fzf` with categorized badges (`[apt]`, `[snap]`, `[flatpak]`), package IDs, versions, and descriptions.
   - Automatic graceful fallback to a numbered terminal menu when `fzf` is unavailable or disabled via `--no-fzf`.

3. **Immediate Removal of App & Orphaned Dependencies / Runtimes**:
   - **APT**: Runs `sudo apt-get purge -y <pkg>` and immediately cleans orphaned dependencies with `sudo apt-get autoremove --purge -y`.
   - **Snap**: Runs `sudo snap remove --purge <pkg>` (preventing lingering snap data snapshots).
   - **Flatpak**: Runs `flatpak uninstall -y <app-id>` and immediately prunes unreferenced runtimes with `flatpak uninstall --unused -y`.

4. **Safe Post-Removal Residual Data Cleanup**:
   - Only prompts for cleanup *after* the application and orphaned dependencies are successfully removed.
   - Scans candidate folders:
     - User paths: `~/.config/<name>`, `~/.cache/<name>`, `~/.local/share/<name>`, `~/.local/state/<name>`, `~/.<name>`, `~/snap/<name>`, `~/.var/app/<app-id>`.
     - System paths: `/etc/<name>`, `/var/log/<name>`, `/var/lib/<name>`, `/var/snap/<name>`.
   - Displays all detected paths and their disk usage (`du -sh`).
   - Uses `gio trash` for user files in `$HOME` (ensuring deleted data can be recovered from the system trash).
   - Uses `sudo rm -rf` for system paths only upon explicit confirmation.

---

### Usage

#### 1. Via Shell Function (Recommended)
Add or use the `uninstall` function in Zsh:
```zsh
# Search and select an app by keyword
uninstall vlc

# Interactively browse all installed user apps
uninstall

# Preview what would be removed without touching the system
uninstall --dry-run discord
```

#### 2. Direct Script Execution
```bash
# Basic keyword search
ubuntu_uninstall-app.sh pinta

# Force numbered terminal menu instead of fzf
ubuntu_uninstall-app.sh --no-fzf celluloid

# Dry-run mode
ubuntu_uninstall-app.sh --dry-run fastfetch

# Skip residual data scan
ubuntu_uninstall-app.sh --no-cleanup obsidian
```

---

### Options Overview

| Flag | Description | Default |
| :--- | :--- | :--- |
| `KEYWORD` | App name or search substring (optional) | Browse all |
| `-d, --dry-run` | Simulate search, removal, and residual detection without changes | `false` |
| `-n, --no-fzf` | Disable fzf and use numbered terminal menu | `false` |
| `--no-cleanup` | Skip residual configuration and user data scanning | `false` |
| `-h, --help` | Display usage instructions and examples | — |
