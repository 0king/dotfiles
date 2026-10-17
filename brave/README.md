# 🌐 Brave & Chrome Profile Backups

This directory contains cloud-safe, sanitized backups of Brave Browser preferences, custom keyboard shortcuts, and in-extension keymappings managed by `chezmoi`.

## 📁 Directory Structure
```text
brave/
├── README.md                          # This file
└── profiles/
    ├── Default/
    │   ├── Preferences.json          # Sanitized full preferences (sorted keys, git-diff friendly)
    │   ├── shortcuts.json            # Human-readable native & extension shortcuts
    │   └── vimium_keymappings.txt    # Extracted Vimium custom keymappings
    ├── Profile 1/
    ├── Profile 2/
    ├── Profile 3/
    └── Profile 4/
```

## 🔒 Cloud-Safety & Security Guarantee
- **Zero Credentials**: Passwords, credential tokens, and secret sync keys are completely stripped.
- **Zero Financial Data**: Credit card autofill, payment tokens, and billing information are removed.
- **Zero Crypto / BAT**: Brave Crypto Wallet keys and Brave Rewards state are not stored.
- **Zero Browsing History**: Site engagement histories and visited domains in content settings exceptions are sanitized.

## 🛠️ Usage
To update or restore these profiles, use the interactive utility:
```bash
~/.local/bin/browser-chrome-brave_export-import-settings.sh
```

See [docs/brave-profile-and-keymap-README.md](../docs/brave-profile-and-keymap-README.md) for full documentation and shortcut cheat sheets.
