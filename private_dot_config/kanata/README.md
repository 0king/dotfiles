# Universal kanata config for all keyboards.
kanata v1.12.0
ubuntu 26

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