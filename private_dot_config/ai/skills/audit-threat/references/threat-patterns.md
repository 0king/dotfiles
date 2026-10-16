# Threat pattern catalog

This is the reasoning behind each rule family in `scripts/scan_patterns.py`, plus
the false-positive shapes worth knowing before you triage a finding. Read the
relevant section for a rule ID when you're deciding whether a hit is real.

## EXEC-* — Dynamic execution

`eval`, `exec`, `new Function(...)`, `os.system`, `subprocess(shell=True)`,
`child_process.exec`, PowerShell `Invoke-Expression` / `-EncodedCommand`. These
run a string as code or a shell command. They're how almost every payload
actually executes, regardless of how it got onto the machine.

**Common legitimate uses:** template engines evaluating small expressions,
build tooling shelling out to `git`/`make` with a fixed, non-user-controlled
command string, REPLs, math expression parsers. The tell: is the string being
executed built from user input, a network response, or a decoded blob — or is
it a short, static, hardcoded command?

## FETCH-* — Remote fetch-and-run

`curl ... | bash`, `wget ... | sh`, or fetching a URL and piping the response
into `eval`/`exec`. This is the single most common one-liner in real
supply-chain compromises because it lets an attacker change the payload after
the package/repo is already published, without touching the repo again.

**Common legitimate uses:** almost none, honestly — even official install
scripts that use this pattern (e.g. some CLI installers) are considered risky
practice by security researchers. Treat any hit here as worth a close read
regardless of source.

## OBF-* — Obfuscation indicators

- **OBF-001**: base64 decode immediately followed by execution. Legitimate
  base64 use (encoding binary data, JWTs, images) is everywhere — the
  specific tell here is decode-then-execute in the same breath, which has
  very few honest uses.
- **OBF-002**: strings built character-by-character via char codes instead of
  a literal. Sometimes legitimate (generating test fixtures, working around
  a linter), but often used to hide a URL or command name from a simple
  text search.
- **OBF-003**: zero-width characters or the right-to-left override
  (U+202E). These change how code *displays* without changing what it
  *does* — e.g. making `eval` invisible in a diff, or making a filename look
  different than it is. There's essentially no legitimate reason for these
  to appear in source code (as opposed to string literals that are clearly
  meant to contain them, e.g. i18n test fixtures — check context).

## EXFIL-* — Exfiltration heuristics

- **EXFIL-001**: reads a credentials file (`~/.ssh/id_rsa`, `~/.aws/credentials`,
  `.npmrc`, `.git-credentials`). Ask: does this file's stated purpose have any
  reason to touch credentials at all? A deploy script might; a date-formatting
  utility should not.
- **EXFIL-002**: environment variables referenced near an outbound HTTP call.
  Very common false-positive source (e.g. legitimate telemetry/error reporting
  that includes a config flag from env). Read the actual payload being sent.
- **EXFIL-003**: Discord webhooks, pastebin raw links, ngrok tunnels. All have
  legitimate everyday uses (Discord bots, sharing logs, local dev tunnels) —
  but they're also popular because they're free, unauthenticated, and not
  yet on most corporate blocklists. Context is everything here.

## PERSIST-001/002/003 — Persistence

- **PERSIST-001**: writing to a crontab or appending to a shell startup file
  (`.bashrc`, `.zshrc`, `.zshenv`, `.zprofile`, `.profile`). Legitimate
  installers do this too (e.g. adding a tool to PATH) — but for a *library*
  or a script with no stated reason to survive past the current process,
  it's a strong signal.
- **PERSIST-002**: GNOME autostart entries (`~/.config/autostart/*.desktop`),
  systemd `--user` units, or `gsettings`/`dconf` writes. On a Linux desktop
  these are the standard ways to make something run at login or persist
  across sessions — normal for an installer that's supposed to add a
  background service, very much not normal for anything else.
- **PERSIST-003**: `LD_PRELOAD` or `/etc/ld.so.preload`. Injects a shared
  library into every subsequently launched process on the system. This is
  the mechanism behind most Linux userland rootkits; legitimate uses
  (debugging, sandboxing tools) are rare and usually well-labeled.

## SHELL-* — Shell-framework-specific

These matter most in dotfiles repos, plugin managers, and anything meant to
be `source`d into a live interactive shell — that position (running
automatically, with the user's full privileges, on every terminal open) is
exactly what makes shell frameworks a higher-value target than an app you
have to explicitly launch.

- **SHELL-001**: `source <(curl ...)`, `. <(wget ...)`, or `eval "$(curl ...)"`
  — pulls remote content directly into the running shell. Same risk profile
  as FETCH-001, just via shell builtins instead of a pipe to bash.
- **SHELL-002**: redefines a sensitive command (`sudo`, `ssh`, `git`, `curl`,
  `wget`, `su`, `passwd`) as an alias or function. **Known legitimate shape**:
  a wrapper that immediately calls through to the real command via the
  `command` builtin (`git() { command git "$@"; ... }`) purely to add
  logging/error-handling — very common in shell frameworks. The thing to
  check: does the wrapper call through to the real command, or does it do
  something instead of / in addition to the real thing (log credentials,
  redirect to a different host, silently drop the call)?
- **SHELL-003**: a `precmd`/`preexec`/`chpwd`/`PROMPT_COMMAND` hook defined
  in the same file as a network call. These hooks fire on every prompt or
  directory change with no explicit user action — legitimate prompt plugins
  do check local state (git status, tool versions) but shouldn't need to
  make network calls on every keystroke. Read the full hook before deciding.

## SECRET-001/002 — Hardcoded credentials

A private-key block header, or the shape of a live AWS/GitHub token. This is
a lightweight pass, not a real secret scanner (no entropy analysis, no
provider-specific formats beyond these two) — pair with `gitleaks` or
`trufflehog` if thoroughness matters and one is available. A hit could be a
real leaked credential, a planted backdoor for the *maintainer's* systems, or
just a test fixture — check whether it's inside a `test`/`fixture`-named path
before treating it as live.

## GIT-001 — Suspicious git hooks

`.git/hooks/` is skipped by the main content scan (it's not source code) but
checked separately: any file there other than the default `*.sample`
templates that's also executable will run automatically on the matching git
operation (commit, checkout, push) with no prompt and no diff visible in the
normal source tree. Legitimate in projects that use hooks for linting or
formatting — but since it's such an easy place to hide something that only
ever fires locally, it's worth opening and reading in full rather than
pattern-matching its content.

## DROP-001 — Decode, drop to disk, execute

A file that both decodes a blob (`base64 -d`, `openssl enc -d`) *and* marks
something executable (`chmod +x`) is very likely writing a payload to disk
and running it as a separate step — deliberately avoiding the eval/exec
patterns that a naive scan would catch, since the actual malicious code never
appears as a string literal being executed in place. Read the full sequence:
what gets decoded, where it's written, and what runs it.

## SUPPLY-* — Install-time hooks

- **SUPPLY-001**: an npm `preinstall`/`postinstall`/`install` script that
  shells out to `curl`/`wget` or runs inline `node -e` code. These scripts
  run automatically the moment someone runs `npm install`, with no prompt —
  it's one of the most-used real-world supply-chain vectors (see: multiple
  npm package-compromise incidents that shipped exactly this).
- **SUPPLY-002**: `setup.py` doing network or shell activity outside normal
  packaging metadata. `pip install` executes `setup.py` automatically.

## Extensionless shell files

Shell frameworks and plugin managers commonly ship files with no extension at
all (a repo's main executable, files under `functions/` meant to be
autoloaded). The scanner peeks the first line of any file it wouldn't
otherwise scan and treats it as a shell file if it finds a shebang mentioning
`sh`/`bash`/`zsh`/`dash`/`ksh` -- so these get the full `shell`-tagged rule
set even without a `.sh`/`.zsh` extension.

## Scope and limits

This scanner is heuristic pattern matching across several categories --
malicious execution, persistence, exfiltration, install-time hooks, git
hooks, and a light secrets pass -- not a sandboxed behavioral analysis or a
CVE database lookup. It will miss:
- Logic bombs gated on business logic rather than a recognizable pattern
  (e.g. "only misbehave for the 500th customer record").
- Novel obfuscation techniques not covered by the OBF-* rules.
- Malicious behavior implemented through entirely ordinary-looking API calls
  with no red-flag keywords at all.

It is also not a dependency-vulnerability scanner — for known-CVE or
known-malicious-package lookups, pair this with `npm audit`, `pip-audit`, or
checking the package name against recent supply-chain advisories, if those
tools are available in the environment.

By default the scan skips `node_modules`, `vendor`, `venv`, and similar
dependency directories (see `DEFAULT_SKIP_DIRS` in the script) — pass
`--include-deps` to also scan inside them, but expect more noise and a much
longer run.
