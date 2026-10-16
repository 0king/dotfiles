# Global Agent Guidelines

## Default Behavior & Shortcuts
- **Do not override default behavior without asking**: Never override or disable default system, terminal, or application behaviors (e.g., built-in keybindings, default shortcuts, default shell or emulator actions) without explicitly asking the user first.
- Always investigate and present alternative approaches before modifying default terminal or application shortcuts.

## Documentation of Changes
- **Always document changes made**: Always document all changes made to code, configuration, or files. Clearly describe what was modified, added, or removed, along with the reasoning behind the modifications.

## Proper Documentation Standards
- **Keep proper documentation alongside code**: Every top-level abstraction, public trait/interface, and architectural decision needs a matching doc artifact — rustdoc on public items, a `README.md` or `ARCHITECTURE.md` entry for new crates/modules, and updated contracts when behavior changes.
- A behavior change without a matching doc/test update is incomplete. Prefer editing existing docs over creating new files; never leave `README`/`ARCHITECTURE`/trait docs stale after a refactor.

## Safe File Deletion & System Trash
- **Use trash instead of permanent removal**: When deleting user code, project files, or configuration files, prefer using `trash-put` (from `trash-cli`) or `gio trash` over `rm` / `rm -rf` so files can be recovered from system trash if needed.
- **Permitted uses of `rm` / `rm -rf`**:
  - Ephemeral temporary files in `/tmp` or `/var/tmp`.
  - Disposable build artifacts, dependency directories, and caches (e.g., `target/`, `node_modules/`, `.cache/`, `dist/`, `build/`).
  - When the user explicitly requests permanent deletion or shredding.

## AI Configuration Management (Skills, Rules & Prompts)
All AI configurations on this computer are centralized in `~/.config/ai` and version-controlled via `chezmoi` (`~/.local/share/chezmoi/private_dot_config/ai`). All AI agents (Antigravity/Gemini, Cursor, Claude Code, Cline, Aider, Kilo, OpenCode, VS Code/Copilot) read from this centralized location via symlinks.

### 1. Adding or Editing Skills
- **Directory**: `~/.config/ai/skills/<skill-name>/`
- **File Structure**:
  ```text
  skills/<skill-name>/
  ├── SKILL.md          # Required: Main instruction file with YAML frontmatter
  ├── scripts/          # Optional: Helper scripts and executable utilities
  └── references/       # Optional: Detailed reference docs, manuals, or schemas
  ```
- **SKILL.md Requirements**:
  ```markdown
  ---
  name: <skill-name>
  description: >-
    A clear description of what the skill does and precisely when the agent should use it.
    Always write in third-person (e.g., "Use this skill when the user asks to...").
  ---

  # Skill Title

  Instructions and steps here...
  ```
- **Guidelines**:
  - Keep `SKILL.md` concise. Move bulky logs, API docs, or schemas to `references/` and link to them (progressive disclosure).
  - Encapsulate repetitive shell or script logic into `scripts/` instead of cluttering agent prompts.
  - Test scripts and make them executable (`chmod +x`).

### 2. Adding or Editing Rules
- **Global Rules**: Edit `~/.config/ai/AGENTS.md` directly for rules that apply unconditionally to every agent session across the machine.
- **Modular / Specialized Rules**: Place topic-specific rule files in `~/.config/ai/rules/<rule-name>.md` (or `.mdc` for Cursor).

### 3. Adding or Editing Prompts
- **Directory**: `~/.config/ai/prompts/<prompt-name>.md`
- Store reusable system prompts, task templates, or persona prompts here.

### 4. Day-to-Day Operations & Chezmoi Sync
- **When editing in `$HOME` (`~/.config/ai/` or via any symlink)**:
  Run `chezmoi re-add ~/.config/ai` (or `chezmoi add ~/.config/ai/AGENTS.md`) so the chezmoi source repository captures your changes.
- **When editing in the Chezmoi source repository (`~/.local/share/chezmoi/`)**:
  Run `chezmoi apply` to deploy changes to `$HOME`. The automated post-apply hook will run `sync-ai-agents` to ensure all agent symlinks are refreshed.
- **When a new AI agent tool is installed**:
  Run `sync-ai-agents` (or `sync-ai-agents --check` to preview) to instantly link the new tool to `~/.config/ai`.
