return {
  {
    "0king/legendary.nvim",
    priority = 10000,
    lazy = false,
    dependencies = {
      { "kkharji/sqlite.lua", lazy = true },
    },
    keys = {
      { "<C-p>", "<cmd>Legendary<cr>", desc = "Command Palette (Legendary)", mode = { "n", "v" } },
      { "<leader>P", "<cmd>Legendary<cr>", desc = "Command Palette (Legendary)", mode = { "n", "v" } },
    },
    opts = {
      include_builtin = true,
      include_legendary_cmds = true,
      extensions = {
        lazy_nvim = true,
        which_key = {
          auto_register = true,
        },
      },
    },
  },
}
