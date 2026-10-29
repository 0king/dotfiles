return {
  {
    "0king/legendary.nvim",
    priority = 10000,
    lazy = false,
    dependencies = {
      { "kkharji/sqlite.lua" },
    },
    keys = {
      { "<leader>p", "<cmd>CommandPalette<cr>", desc = "Command Palette" },
      { "<A-x>", "<cmd>CommandPalette<cr>", mode = { "n", "x", "i" }, desc = "Command Palette" },
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
      commands = {
        {
          ":ToggleWrap",
          function()
            if Snacks and Snacks.toggle then
              Snacks.toggle.option("wrap", { name = "Wrap" }):toggle()
            else
              vim.wo.wrap = not vim.wo.wrap
              vim.notify("Wrap " .. (vim.wo.wrap and "enabled" or "disabled"), vim.log.levels.INFO, { title = "Option" })
            end
          end,
          description = "Toggle word wrap",
          keywords = { "wrap", "word wrap", "line wrap", "soft wrap", "toggle" },
          category = "UI",
          opts = { force = true },
        },
        {
          ":ToggleWordWrap",
          function()
            if Snacks and Snacks.toggle then
              Snacks.toggle.option("wrap", { name = "Wrap" }):toggle()
            else
              vim.wo.wrap = not vim.wo.wrap
              vim.notify("Wrap " .. (vim.wo.wrap and "enabled" or "disabled"), vim.log.levels.INFO, { title = "Option" })
            end
          end,
          description = "Toggle word wrap",
          keywords = { "wrap", "word wrap", "line wrap", "soft wrap", "toggle" },
          category = "UI",
          opts = { force = true },
        },
        {
          ":WrapToggle",
          function()
            if Snacks and Snacks.toggle then
              Snacks.toggle.option("wrap", { name = "Wrap" }):toggle()
            else
              vim.wo.wrap = not vim.wo.wrap
              vim.notify("Wrap " .. (vim.wo.wrap and "enabled" or "disabled"), vim.log.levels.INFO, { title = "Option" })
            end
          end,
          description = "Toggle word wrap",
          keywords = { "wrap", "word wrap", "line wrap", "soft wrap", "toggle" },
          category = "UI",
          opts = { force = true },
        },
      },
    },
  },
}
