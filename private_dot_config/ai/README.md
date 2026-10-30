# 🤖 Universal AI Configuration System (`~/.config/ai`)

A centralized, version-controlled architecture for managing AI agent instructions (`AGENTS.md`), skills (`SKILL.md`), modular rules, and reusable prompts across all AI tools on this computer.

---

## 📌 Architecture Overview

Rather than maintaining separate rule files and skill directories for every AI tool (Cursor, Gemini/Antigravity, Claude Code, Cline, Aider, Kilo, OpenCode, VS Code Copilot), all configurations live in a single canonical directory:

```text
~/.config/ai/
├── AGENTS.md                  # Canonical global rules and agent guidelines
├── rules/                     # Modular rule files (.md / .mdc)
│   └── README.md
├── skills/                    # Modular agent skills (SKILL.md, scripts, references)
│   ├── audit-threat/
│   ├── audit-rust-threat/
│   └── audit-cpp-node-threat/
└── prompts/                   # Reusable prompt templates and system prompts
    └── README.md
```

### How It Works
1. **Chezmoi Management**: The source state lives in `~/.local/share/chezmoi/private_dot_config/ai/` and is tracked in Git.
2. **Local Deployment**: Chezmoi deploys the files to `~/.config/ai/`.
3. **Automated Symlinking**: The `sync-ai-agents` script (managed in `private_dot_local/bin/executable_sync-ai-agents`) creates symlinks from each tool's native configuration path to `~/.config/ai/`.
4. **Post-Apply Hook**: Chezmoi automatically executes `sync-ai-agents` after every `chezmoi apply`.

---

## 🗺️ Supported Tools & Symlink Reference

| Tool | Native Path | Target in `~/.config/ai` |
| :--- | :--- | :--- |
| **Antigravity / Gemini** | `~/.gemini/config/AGENTS.md`<br>`~/.gemini/config/GEMINI.md`<br>`~/.gemini/config/skills`<br>`~/.gemini/config/rules`<br>`~/.gemini/config/prompts` | `AGENTS.md`<br>`AGENTS.md`<br>`skills/`<br>`rules/`<br>`prompts/` |
| **Cursor** | `~/.cursorrules`<br>`~/.cursor/AGENTS.md`<br>`~/.cursor/skills`<br>`~/.cursor/rules`<br>`~/.cursor/prompts` | `AGENTS.md`<br>`AGENTS.md`<br>`skills/`<br>`rules/`<br>`prompts/` |
| **Claude Code** | `~/.claude/CLAUDE.md`<br>`~/.config/claude/CLAUDE.md`<br>`~/.claude/skills`<br>`~/.claude/rules` | `AGENTS.md`<br>`AGENTS.md`<br>`skills/`<br>`rules/` |
| **VS Code & Copilot** | `~/.config/Code/User/prompts`<br>`~/.config/Code/User/instructions.md`<br>`~/.config/Code/User/AGENTS.md`<br>`~/.config/github-copilot/copilot-instructions.md`<br>`~/.config/github-copilot/AGENTS.md` | `prompts/`<br>`AGENTS.md`<br>`AGENTS.md`<br>`AGENTS.md`<br>`AGENTS.md` |
| **Aider** | `~/.aider/CONVENTIONS.md`<br>`~/.aider/AGENTS.md`<br>`~/.aider.conf.yml` | `AGENTS.md`<br>`AGENTS.md`<br>`read: [~/.config/ai/AGENTS.md]` |
| **Cline** | `~/.cline/AGENTS.md`<br>`~/.cline/rules`<br>`~/.cline/skills` | `AGENTS.md`<br>`rules/`<br>`skills/` |
| **Kilo** | `~/.config/kilo/AGENTS.md`<br>`~/.config/kilo/rules`<br>`~/.config/kilo/skills` | `AGENTS.md`<br>`rules/`<br>`skills/` |
| **OpenCode** | `~/.config/opencode/AGENTS.md`<br>`~/.config/opencode/rules`<br>`~/.config/opencode/skills` | `AGENTS.md`<br>`rules/`<br>`skills/` |
| **Universal Fallbacks** | `~/.agents`<br>`~/.ai`<br>`~/.config/agents` | `~/.config/ai` (directory symlink)<br>`~/.config/ai`<br>`~/.config/ai` |

---

## 🔄 Day-to-Day Operations Guide

### Scenario 1: A File Changed in `$HOME` (or via a Symlink)

If you or an AI agent edit `~/.config/ai/AGENTS.md` (or edit through a symlink like `~/.cursorrules` or `~/.gemini/config/AGENTS.md`):

1. **Check detected changes**:
   ```bash
   chezmoi status
   # Output will show: M .config/ai/AGENTS.md
   ```

2. **Inspect the diff**:
   ```bash
   chezmoi diff
   ```

3. **Sync back to the Chezmoi repository**:
   ```bash
   chezmoi re-add ~/.config/ai
   # Or re-add a specific file:
   chezmoi re-add ~/.config/ai/AGENTS.md
   ```
   *Chezmoi's automated Git hooks will stage, scan with `gitleaks`, commit, and push the update.*

---

### Scenario 2: A File Changed in the Chezmoi Source Repo

If you edit files directly inside `~/.local/share/chezmoi/private_dot_config/ai/`:

1. **Preview the changes that will be written to `$HOME`**:
   ```bash
   chezmoi diff
   ```

2. **Apply the changes**:
   ```bash
   chezmoi apply
   ```
   *When `chezmoi apply` completes, the post-apply hook automatically runs `sync-ai-agents` to ensure all agent symlinks are refreshed.*

---

### Scenario 3: Installing a New AI Agent Tool

When you install a new AI tool on your machine:

1. **Run the sync utility**:
   ```bash
   sync-ai-agents
   ```
   To preview without making any changes:
   ```bash
   sync-ai-agents --check
   ```

2. **If the tool uses an unusual or custom path**:
   Add the tool's path mapping to `~/.local/share/chezmoi/private_dot_local/bin/executable_sync-ai-agents` using the `link_target` helper:
   ```bash
   link_target "$AGENTS_SRC" "$HOME/.newtool/rules.md" "New Tool Rules"
   link_target "$SKILLS_SRC" "$HOME/.newtool/skills" "New Tool Skills"
   ```
   Then run `chezmoi apply` to deploy and execute the updated script.

---

## 🛠️ Instructions for AI Agents: Creating Skills & Rules

### Creating a New Skill

Skills live in `~/.config/ai/skills/<skill-name>/` and must follow this structure:

```text
skills/<skill-name>/
├── SKILL.md          # Required: Main instruction file with YAML frontmatter
├── scripts/          # Optional: Helper scripts (executable)
└── references/       # Optional: In-depth documentation or manuals
```

#### `SKILL.md` Template
```markdown
---
name: my-new-skill
description: >-
  Describe what this skill does and when the agent should use it.
  Always write in third-person (e.g. "Use this skill when auditing Rust crates for security risks.").
---

# My New Skill

Provide clear, step-by-step instructions for the agent here.

## Steps
1. Run the preparation script: `[scan.py](./scripts/scan.py)`
2. Analyze the output and report findings.
```

#### Best Practices for Skills
- **Progressive Disclosure**: Keep `SKILL.md` under 100-150 lines. Store bulky pattern lists, schemas, and manuals in `references/` and link to them.
- **Executable Scripts**: Place non-trivial shell loops, Python parsers, or scanners in `scripts/` and make them executable (`chmod +x`).
- **Validation**: Include verification steps so the agent knows how to verify results.

### Creating a Modular Rule

- **Global Rules**: Edit `~/.config/ai/AGENTS.md` directly.
- **Modular Rules**: Place specialized rules in `~/.config/ai/rules/<rule-name>.md` (or `.mdc` for Cursor).
- Example: `~/.config/ai/rules/testing-standards.md`

### Creating a Reusable Prompt

- Place prompt templates in `~/.config/ai/prompts/<prompt-name>.md`.
- Example: `~/.config/ai/prompts/git-commit-style.md`

---

## 📜 AI Agents Command History & Auditing System

A unified, real-time command logging and auditing system for AI coding agents (**Kilo**, **Cline**, **Copilot**, **Antigravity**, **OpenCode**, **Aider**, **Pi**, **Dsh**).

### Features
- **Zero Configuration Hook**: Transparent non-interactive Bash hook (`~/.config/ai/hooks/ai-agents-bash-hook.sh`) intercepts commands executed by AI agents without polling or modifying agent sources.
- **Dedicated SQLite Storage**: Stored outside Chezmoi at `~/Desktop/fj/Dropbox/archives/backups/terminal/ai-agents-history/ai-agents-history.db` with WAL mode.
- **Rich Auditing Metadata**: Logs command, working directory, ISO-8601 timestamp, executor agent, exit code, and captured command output (where available).
- **Zero Pollution**: Interactive user shells (Ghostty, Kitty, WezTerm, Alacritty) do not trigger logging.
- **Independent from Atuin**: Keeps personal interactive history clean and isolated.

### Key Commands

```bash
# View system and database status
ai_create-ai-agents-history-hook --status

# Re-run or refresh backfill from all agent logs
ai_create-ai-agents-history-hook --backfill

# Browse the most recent 25 commands
ai_view-ai-agents-history

# Search for commands matching a query
ai_view-ai-agents-history -s "git status"

# Filter by agent name
ai_view-ai-agents-history -a opencode -n 50

# Filter only failed commands (exit_code != 0)
ai_view-ai-agents-history --failed

# Show captured output inline
ai_view-ai-agents-history -o

# Show complete details (including full multi-line output) for a record
ai_view-ai-agents-history -i 4882

# Show command statistics and analytics
ai_view-ai-agents-history --stats

# Live follow/stream new commands in real-time
ai_view-ai-agents-history -f
```

---

## 🔍 Verification & Troubleshooting

- **Audit all AI symlinks**:
  ```bash
  sync-ai-agents --check
  ```
- **Inspect canonical rules**:
  ```bash
  cat ~/.config/ai/AGENTS.md
  ```
- **Recover an overwritten file**:
  Pre-execution backups are stored in:
  ```text
  ~/.cache/ai-backups/<timestamp>/
  ~/.cache/chezmoi/backups/<timestamp>/
  ```
