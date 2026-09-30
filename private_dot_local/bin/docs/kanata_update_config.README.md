# kanata_update_config

A utility script to deploy the Kanata keyboard remapper configuration from Chezmoi to the system location and restart the Kanata service.

### Overview

Kanata systemd services typically run as a root or system service reading configuration from `/etc/kanata/unicfg.kbd`. This script bridges the gap between dotfiles managed in Chezmoi and the system-wide service directory.

### Key Features

1. **Automatic Chezmoi Source Resolution**:
   - Automatically queries `chezmoi source-path ~/.config/kanata/unicfg.kbd` to find the exact file in your dotfiles repository (`~/.local/share/chezmoi/private_dot_config/kanata/unicfg.kbd`).
   - Does not require any `$CHEZMOI_HOME` variable.
   - Also keeps `~/.config/kanata/unicfg.kbd` in sync when copied from the Chezmoi source repository.

2. **Automated Syntax Validation**:
   - Validates the configuration using `kanata -c <config> --check` before touching system files to prevent deploying broken configurations that could disable keyboard inputs.
   - Can be bypassed using `--no-check` if needed.

3. **Safe System Deployment**:
   - Ensures `/etc/kanata` directory exists.
   - Copies configuration to `/etc/kanata/unicfg.kbd`.
   - Sets root ownership: `sudo chown root:root /etc/kanata/unicfg.kbd`.
   - Restricts file permissions: `sudo chmod 644 /etc/kanata/unicfg.kbd`.
   - Restarts the systemd daemon: `sudo systemctl restart kanata.service`.

4. **Dry Run Support**:
   - Inspect actions before modifying system files with `-n` / `--dry-run`.

---

### Usage

```bash
# Standard run (validates config, copies to /etc/kanata, and restarts service)
kanata_update_config

# Test and preview commands without making changes
kanata_update_config --dry-run

# Skip configuration check
kanata_update_config --no-check

# Display help
kanata_update_config --help
```

### Options Overview

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-n, --dry-run` | Preview actions without making changes | `false` |
| `--no-check` | Skip syntax validation (`kanata --check`) | `false` |
| `-v, --verbose` | Enable verbose output | `false` |
| `-h, --help` | Show usage instructions | — |
