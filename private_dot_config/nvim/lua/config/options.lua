-- Options are automatically loaded before lazy.nvim startup
-- Default options that are always set: https://github.com/LazyVim/LazyVim/blob/main/lua/lazyvim/config/options.lua
-- Add any additional options here

-- Prevent delete/cut/change (d, c, x) from overwriting system clipboard
vim.opt.clipboard = ""

-- Allow cursor to wrap to previous/next line with h, l, <Left>, and <Right>
vim.opt.whichwrap:append("<,>,[,],h,l")

