git undo

**Git** does not have a single `git undo` command; instead, it provides several commands to revert changes depending on whether the work is local, staged, or pushed.

**Undoing Local Changes (Uncommitted)**
*   **Discard unstaged changes:** Use `git checkout -- <file>` or `git restore <file>` to revert a specific file. Use `git checkout -- .` to discard all local modifications.
*   **Unstage a file:** Use `git reset HEAD <file>` or `git restore --staged <file>` to move changes back to the working directory.

**Undoing Commits**
*   **Undo last local commit (keep changes):** Use `git reset --soft HEAD~1` to keep changes staged, or `git reset HEAD~1` (default) to keep them unstaged. Use `git reset --hard HEAD~1` to **permanently discard** all changes.
*   **Undo a pushed commit:** Use `git revert <commit-hash>` to create a new commit that reverses the changes, preserving history. Avoid `git reset` on shared branches as it rewrites history.

**Recovering Lost Work**
*   Use `git reflog` to view a log of all HEAD movements. You can then restore a previous state using `git reset --hard <reflog-entry>` or `git checkout <commit-hash>`.
