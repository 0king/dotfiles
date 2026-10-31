# push
git push <remote> <branch>
git push origin main
--set-upstream (-u): first push, then use just git push.
--all: Pushes all local branches to remote. 
--tags: Pushes all local tags.

# add
// Stage all changes in the entire repository
git add -A

// Stage all changes in the current directory
git add .

# undo
see git-undo.md

# log
most recent first

`git log --oneline`
`git log --graph --oneline --decorate` to visualize branch and merge history.
`git log --author="Name"`
`git log --since="2023-01-01"` or `git log --until="2023-12-31"`
`git log --grep="keyword"`.
`git log -- <file-path>` to view changes made to a specific file.
`git log -n 10` most recent 10 commits.

The command utilizes the `less` pager for navigation; use **j/k** or arrow keys to scroll, **space** for page down, and **q** to quit.


