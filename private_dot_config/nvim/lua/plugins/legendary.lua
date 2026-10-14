return {
  {
    "0king/legendary.nvim",
    priority = 10000,
    lazy = false,
    dependencies = {
      { "kkharji/sqlite.lua" },
    },
    keys = {
      { "<leader>P", "<cmd>CommandPalette<cr>", desc = "Command Palette" },
      { "<C-S-P>", "<cmd>CommandPalette<cr>", mode = { "n", "x", "i" }, desc = "Command Palette" },
    },
    opts = {
      include_builtin = true,
      include_legendary_cmds = true,
      sort = {
        frecency = {
          db_root = string.format("%s/legendary/", vim.fn.stdpath("data")),
          max_timestamps = 10,
        },
      },
      extensions = {
        lazy_nvim = true,
        which_key = {
          auto_register = true,
        },
      },
    },
  },
}
