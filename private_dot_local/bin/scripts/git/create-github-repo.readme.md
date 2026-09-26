# create-github-repo.sh

An interactive Bash script to automate GitHub repository creation and initialization.

### Key Features

1. **GitHub SSH Connectivity & Verification**:
   - Tests SSH connection to GitHub (`ssh -T git@github.com`) before performing operations.
   - Auto-detects your authenticated GitHub username directly from the SSH greeting.
   - Configures the Git remote with the SSH URL: `git@github.com:<owner>/<repo>.git`.

2. **Git Repository Setup & Initialization**:
   - Detects if the current directory is already a Git repository.
   - If not, offers to initialize one (`git init -b main`).
   - Offers to create a starter `.gitignore` (filtering `.env`, logs, build outputs, `node_modules/`, etc.) if none exists.

3. **GitHub Authentication**:
   - **GitHub CLI (`gh`)**: Detects if `gh` is authenticated and offers to use it.
   - **GitHub Personal Access Token (PAT)**: Works universally using standard `curl` without requiring `gh`.
     - Validates the token against GitHub's REST API.
     - Offers to save the token securely to `~/.config/gh-repo-creator/token` (file permission `0600`) so you only enter it once.

4. **Repository Customization**:
   - **Name**: Defaults to the current folder name (sanitized for GitHub name requirements).
   - **Visibility**: Choice between **Private** (default) and **Public**.
   - **Owner**: Personal account or GitHub Organization.
   - **Description**: Optional repository description.

5. **Staging, Committing & Optional Push**:
   - Inspects the working tree for uncommitted changes or untracked files.
   - Offers to create an initial `README.md` if the directory is empty.
   - Prompts to stage and commit changes with a customizable commit message (default: `"Initial commit"`).
   - Asks whether to push the branch to GitHub over SSH immediately (`git push -u origin <branch>`).

---

### Usage

#### 1. Interactive Mode (Default)
Run the script in any project directory:
```bash
./executable_create-github-repo.sh
```
Or specify a target folder:
```bash
./executable_create-github-repo.sh --dir /path/to/my-project
```

#### 2. Non-Interactive / Quick Flags
You can also supply flags to automate or pre-fill parameters:
```bash
# Create a private repo with a custom name and description
./executable_create-github-repo.sh -n "my-app" -d "Application backend service"

# Create a public repo in an organization and push immediately
./executable_create-github-repo.sh -n "shared-utils" -o "my-org" --public --push -m "v1.0 release"

# Display all options
./executable_create-github-repo.sh --help
```

### Options Overview

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-n, --name <name>` | Repository name | Current directory name |
| `-d, --desc <text>` | Repository description | Empty |
| `-p, --public` | Make repository public | Private |
| `--private` | Make repository private | Private |
| `-o, --org <org>` | Create under an organization | Personal user account |
| `-b, --branch <branch>` | Default branch name | Current branch or `main` |
| `-r, --remote <name>` | Git remote name | `origin` |
| `-m, --message <msg>` | Commit message | `"Initial commit"` |
| `--push` / `--no-push` | Push to remote immediately / skip push | Prompted interactively |
| `--dir <path>` | Target directory to initialize | Current directory |
| `--token <token>` | GitHub Personal Access Token | `$GITHUB_TOKEN` or prompt |
| `-y, --yes` | Non-interactive mode (accept defaults) | `false` |
| `-h, --help` | Show usage instructions | — |
