# Universal kanata config for all keyboards.
kanata v1.12.0
ubuntu 26

# Problems with HRMs
- accidental rollover (misfires)
- lot of hand switching

# update 30.09.26
- to fix HRM misfires, trying out the [home row mod advanced](https://github.com/jtroo/kanata/blob/3aa9fa535ead451d5fb04c6e8dbd48532250c3ec/cfg_samples/home-row-mod-advanced.kbd):
  - when a home row mod activates tap, the home row mods are disabled while continuing to type rapidly
  - tap-hold-release-keys helps make the hold action more responsive
  - pressing another key on the same half of the keyboard as the home row mod will activate an early tap action
- increase tap-hold timeout for pinky fingers
- chord jk for esc (possible conflict with HRM?)
- mouse layer - scroll to top/bottom.  add a faster mouse scroll key
- left meta - becomes **control**

## can we use chords and tap-hold on same keys?

**Yes**, you can use **`j` and `k` as a chord (combo) for `Esc`** while simultaneously using them as home-row mods (Shift on `j`, Ctrl on `k`).

Kanata (v1.12.0) has built-in support for input chords via **`defchordsv2`**, which cleanly integrates with tap-hold / home-row mods.

---

### How It Works Under the Hood

1. **Processing Order:** In Kanata, `defchordsv2` intercepts raw input events **before** layer actions (including tap-hold HRMs) are evaluated.
2. **When pressing `j` and `k` together (within the chord timeout, e.g., 50ms):**
   - Kanata captures both keys and triggers `esc`.
   - Neither key reaches the HRM tap-hold logic, so `rsft` and `rctl` are never activated, and neither `j` nor `k` is output.
3. **When pressing `j` or `k` individually:**
   - Kanata waits for the chord window (50ms). Once no companion key is pressed (or when released/followed by another key), it routes the key to your base layer.
   - Your existing home-row mod definition (`@j` or `@k`) handles it normally: tapping outputs the letter, and holding activates the modifier.

---

### Required Changes to [`unicfg.kbd`](file:///home/dj/.local/share/chezmoi/private_dot_config/kanata/unicfg.kbd)

To enable this, only two small adjustments are needed:

#### 1. Add `concurrent-tap-hold yes` to `defcfg`
Kanata strictly requires `concurrent-tap-hold yes` when `defchordsv2` is used:

```lisp
(defcfg
  process-unmapped-keys yes
  linux-device-detect-mode keyboard-only
  concurrent-tap-hold yes
)
```

#### 2. Add the `defchordsv2` block
Add this block right before your layers:

```lisp
(defchordsv2
  (j k) esc 50 all-released (lyr-mouse lyr-media lyr-bypass)
)
```

You do **not** need to modify your `@j` and `@k` aliases or touch `lyr-base`.

---

### Important Nuances & Edge Cases

1. **Why `lyr-mouse` is in disabled layers:**
   In your [`lyr-mouse`](file:///home/dj/.local/share/chezmoi/private_dot_config/kanata/unicfg.kbd#L150-L157), `j` is mapped to `@mml` (mouse cursor left) and `k` is mapped to `@mmd` (mouse cursor down). Disabling the chord on `lyr-mouse` prevents accidental `Esc` presses when moving the cursor diagonally down-left.
2. **Chord Timeout (50ms):**
   - `50` ms is the sweet spot for adjacent same-hand fingers.
   - If set too high (e.g., `>80ms`), fast rolling when typing words like `"jack"`, `"joke"`, or `"junk"` could accidentally trigger `Esc`.
   - If set too low (e.g., `<35ms`), you may find it difficult to press both keys simultaneously.
3. **Release Behaviour (`all-released` vs `first-release`):**
   - `all-released` (recommended for `Esc`) keeps the chord active until both keys are released, avoiding stray key emissions.

---

Would you like me to apply this update to your [`unicfg.kbd`](file:///home/dj/.local/share/chezmoi/private_dot_config/kanata/unicfg.kbd)?


# Big questions:
Q: how to setup modifiers?
1. HRM (tap-hold)
2. one-shot
  1. hold space, trigger one-shot mods (jkl;) 🙅‍♂️
    Problems with this approach:
    To type `Q:`: To get capital q, hold space, then tap j, relese space, tap q. Now, to get colon, again hold space, tap j, tap ;
    My common shortcuts are meta + a, meta + w, meta + tab, meta + f4, meta + arrow. A and W are not on the same layer
  2. move one-shot mods to different layer - but this still has a problem - instead of holding shift, tap shift multiple times.
3. chords - tap two keys at once

# Layer triggers:

## hold
1. thumb keys = space (meta and alt keys can also be used)
2. capslock, escape (because it is placed at capslock)

- Caps Lock: tap = Esc, hold = Mouse layer
- Space: tap = Space, hold = Altt layer

## tap
1. meta + esc
2. meta + ccontrol + esc

# Layers:
1. altt
- Not using one shot mods (in their current form)
- HRMs in right side only
- esdf become Arrow keys

- key c becomes space
- home, end = h, g
- tab = t
- pageup, pagedown = r, v

- w = tilde
- q = backtick
- a = enter
- x = backspace
- z = delete
- F3 = Print Scr
- f11/f12 = volume up and down
- f1/f2 = brightness up and down
2. Mouse: hold capsock
3. Media: a easy layer for media playing. 
   arrows, volume, brighness
   Shortcut toggle = Meta + ESC
4. Bypass: bypass kanata completely. 
   Shortcut toggle = Meta + Ctrl + ESC
5. when physical mod keys are held, HRMs and altt layer are not available

# Gotchas
## Layer Stacking Order
Kanata stacks layers based on runtime activation order. The most recently activated layer sits on top and shadows everything beneath it.
Because your physical modifiers activate the no-hrm layer, and your spacebar activates the altt layer, the order in which you press them matters for shortcuts like Meta + Arrow:
Press Meta, THEN Space: no-hrm goes on the stack first. altt goes on top. The altt layer maps s d f to arrows. Result: Meta + Arrows (Works!)
Press Space, THEN Meta: altt goes on the stack first. no-hrm goes on top. The no-hrm layer forcefully maps s d f back to standard letters. Result: Meta + S D F (Fails!)
As long as you press your modifiers before you press the spacebar (which is the standard typing habit anyway), your arrow keys and shortcuts will work flawlessly.
