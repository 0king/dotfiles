# neovim

# delete till a char  
| Command | What it does |
|---------|--------------|
| `dt~` | Delete up to (but not including) the **first** `~` forward on the line |
| `dT~` | Delete back up to (but not including) the **previous** `~` on the line |
| `df~x` | Delete **through** the `~` itself (includes the tilde) |
| `c`<char> or `d`<char> works with any motion |

Visual mode
1. Move cursor before the tilde
2. `vft~` — visual select from cursor to just before `~`
   - Or `vf~` to include the tilde itself
3. `d` to delete

# delete from current to start of line
d0 delete from cursor back to column 0
d^ first non-blank char
dgg first line of the file
d{ from cursor back to para start

# move to next char
f~ jump to the next ~ (char)
F~ jump to prev char (~)
t~ jump til just before the next ~
T~ jump back

