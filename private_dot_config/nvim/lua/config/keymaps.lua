-- Keymaps are automatically loaded on the VeryLazy event
-- Default keymaps that are always set: https://github.com/LazyVim/LazyVim/blob/main/lua/lazyvim/config/keymaps.lua
-- Add any additional keymaps here

-- Sync paste (p, P) with system clipboard (+) unless an explicit register was provided
vim.keymap.set({ "n", "x" }, "p", function()
  return vim.v.register == '"' and '"+p' or "p"
end, { expr = true, desc = "Paste from clipboard" })

vim.keymap.set({ "n", "x" }, "P", function()
  return vim.v.register == '"' and '"+P' or "P"
end, { expr = true, desc = "Paste before from clipboard" })

vim.keymap.set({ "n", "x" }, "gp", function()
  return vim.v.register == '"' and '"+gp' or "gp"
end, { expr = true, desc = "Paste after cursor from clipboard" })

vim.keymap.set({ "n", "x" }, "gP", function()
  return vim.v.register == '"' and '"+gP' or "gP"
end, { expr = true, desc = "Paste before cursor from clipboard" })

-- Cut (c) operation: remove from editor and copy to system clipboard (+)
vim.keymap.set({ "n", "x" }, "c", function()
  return vim.v.register == '"' and '"+d' or "d"
end, { expr = true, desc = "Cut to clipboard" })

vim.keymap.set("n", "cc", function()
  return vim.v.register == '"' and '"+dd' or "dd"
end, { expr = true, desc = "Cut line to clipboard" })

vim.keymap.set("n", "C", function()
  return vim.v.register == '"' and '"+D' or "D"
end, { expr = true, desc = "Cut to end of line to clipboard" })


