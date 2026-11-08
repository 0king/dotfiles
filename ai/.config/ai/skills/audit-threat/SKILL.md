---
name: repo-threat-audit
description: Audit a local repository (a clone, a downloaded package, a dotfiles/shell-framework repo, an unfamiliar codebase) for any kind of hidden malware -- not just obviously malicious code, but also planted persistence (cron, shell rc files, systemd user units, GNOME autostart, LD_PRELOAD), risky install-time and git hooks, hardcoded secrets/private keys, and shell-specific hijacking (aliased commands, prompt hooks, remote-sourced code) in bash/zsh repos. Use this whenever the user asks to audit, scan, or vet a repo for malware, hidden threats, backdoors, or suspicious/malicious code, or asks "is this repo safe", "check this before I install/run it", or similar security-review requests -- including for shell/dotfiles repos, not just app codebases. Produces a structured Markdown report with severity-rated findings. Not for dependency CVE lookups or general code review/linting -- this is specifically about detecting intentionally hidden malicious behavior.
---

# Repo Threat Audit

Heuristic, pattern-based triage for malicious code in a repository. The goal
is to surface *candidates* worth a human's attention fast, not to hand down a
verdict -- pattern matching alone will always have false positives (a
legitimate `eval()` in a template engine) and false negatives (a well-hidden
logic bomb with no recognizable keyword). Treat this as the first pass of a
review, and say so plainly in the report.

## Workflow

### 1. Confirm the target

Get the path to the repo on disk (clone it first if the user only gave a URL).
If they didn't say, ask -- don't guess at a path.

### 2. Run the scanner

```bash
python3 scripts/scan_patterns.py <repo-path> --json /tmp/findings.json
```

This walks the tree and applies the rule catalog in
`references/threat-patterns.md`: dynamic execution, remote fetch-and-run,
obfuscation, decode-and-drop-to-disk payloads, exfiltration heuristics,
persistence (cron/rc files, plus GNOME autostart, systemd `--user` units, and
`LD_PRELOAD` for Linux desktop targets), install-time hooks (npm postinstall,
setup.py, git hooks), and a lightweight secrets pass. For bash/zsh repos it
also checks shell-specific hijacking: aliasing over sensitive commands,
prompt/command hooks paired with network calls, and remote content sourced
directly into the shell. It auto-detects extensionless files as shell scripts
via their shebang, which matters a lot for plugin managers/frameworks where
the main executables often have no file extension.

It skips `node_modules`/`vendor`/`venv`-style directories by default since
those are huge and mostly third-party; pass `--include-deps` if the user
specifically wants dependency/vendored code scanned too (slower, noisier --
warn them).

The script prints JSON to stdout and (with `--json`) writes it to a file. Read
the output; don't just report the raw count to the user.

**Match the checks to where the repo will actually run.** If the user tells
you their target OS/desktop (e.g. Linux with GNOME), weight the relevant
persistence checks accordingly in your triage and report framing -- a
`~/.config/autostart/*.desktop` write matters a lot on a GNOME desktop and is
a no-op everywhere else; a registry-write pattern matters on Windows and is
dead code on Linux. The scanner flags both regardless of target so it stays
useful across environments, but your report should tell the user which
findings are actually live threats *for their setup* versus dead code for a
platform they don't run.

### 3. Triage every finding by reading it in context

This is the step that actually matters -- the scanner's job is recall, yours
is precision. For each finding:

- Open the file around the flagged line and read enough surrounding code to
understand what it's actually doing and why.
- Check `references/threat-patterns.md` for that rule ID's known
false-positive shapes before deciding.
- Ask: does this file's stated purpose have any legitimate reason to do what
it's doing? A deploy script reading AWS credentials is normal; a date-parsing
utility doing the same is not.
- For anything alarming, look at the surrounding function/module to see where
the result goes -- e.g. an `eval()` hit is far more concerning if the string
it evaluates was just decoded from a network response than if it's a fixed
literal.

Downgrade or drop findings that are clearly legitimate use, but say so in the
report rather than silently dropping them -- the user should be able to see
what was flagged and why it was dismissed.

### 4. Look beyond the regex catalog

The scanner can't see everything. While you're already reading the flagged
files and the repo structure, also glance at:

- **Manifest files** (`package.json`, `requirements.txt`, `pyproject.toml`)
for dependencies with typosquat-looking names (`reqeusts` vs `requests`,
`colours` vs `colors`) or pinned to suspicious git URLs instead of a
registry.
- **Recently modified files** relative to the rest of the repo (`git log -1 --format=%ci <file>` or `git diff` against an earlier tag) if it's a git
repo -- a single recently-touched file in an otherwise-dormant project is a
classic injection pattern.
- **Anything that doesn't match its extension** -- a `.png` or `.woff` that's
actually a script, an unusually large "config" file.

You don't need exhaustive manual review of the whole repo -- this is a
targeted look driven by what the automated pass and the repo structure
already pointed you toward.

### 5. Write the report

Use this structure:

```markdown
# Threat Audit: <repo name>

**Scope:** <path scanned, whether deps were included, files scanned>
**Overall risk:** Critical / High / Medium / Low / Clean

## Summary
2-4 sentences: what was found, how serious, and the headline recommendation
(e.g. "do not run `npm install`", "safe modulo one thing worth asking the
maintainer about", "clean pass").

## Findings

### Critical
(repeat for High / Medium / Low as populated)

**<rule id> — <one-line description>**
`path/to/file.js:42`
\`\`\`
<snippet>
\`\`\`
Why this matters here: <your triage reasoning, not just the generic rule
description>. <What you'd want to confirm with the maintainer, or why this is
disqualifying as-is.>

## Reviewed and dismissed
Findings the scanner flagged that you concluded are legitimate, with a
one-line reason each. This shows the user the scanner's full recall, not just
your curated subset.

## Limits of this audit
Restate plainly: heuristic pattern match, not a sandboxed behavioral
analysis, doesn't cover dependency CVEs. Note whether `--include-deps` was
skipped.
```



### Severity rubric

- **Critical** — near-certain malicious intent or a pattern with essentially
no legitimate use in context (remote fetch-piped-to-shell, RTL-override
characters, decode-then-eval of a network-sourced blob).
- **High** — strong red flag that needs a confident explanation to clear
(credential file access near a network call, install-time shell-out,
dynamic execution of anything not clearly static/local).
- **Medium** — worth a mention and a quick look, plausible either way.
- **Low** — technically matched a rule, commonly legitimate; flag for
completeness.

Adjust up or down based on your own reading -- the rubric is a starting point,
not a substitute for judgment. A "high" pattern rule can land as Low in the
report if you've confirmed it's benign in context, and vice versa if the
surrounding code is doing something the rule didn't anticipate.

## Reference

`references/threat-patterns.md` has the full rule catalog: what each rule ID
means, why it's a signal, and the specific false-positive shapes to check for
before you escalate a finding. Read it when triaging, not just when curious.