return {
  {
    "folke/snacks.nvim",
    opts = {
      picker = {
        layouts = {
          -- Responsive layout for the legendary.nvim command palette.
          -- width/height are fractions of the editor, so the popup scales with the window.
          legendary = {
            layout = {
              backdrop = false,
              width = 0.8,
              min_width = 80,
              height = 0.6,
              min_height = 10,
              box = "vertical",
              border = true,
              title = "{title}",
              title_pos = "center",
              { win = "input", height = 1, border = "bottom" },
              { win = "list", border = "none" },
            },
          },
        },
        sources = {
          select = {
            kinds = {
              -- legendary.nvim opens vim.ui.select() with this kind;
              -- scope the larger popup to it so other selects stay unchanged.
              ["legendary.nvim"] = { layout = { preset = "legendary" } },
            },
          },
        },
      },
    },
  },
}
