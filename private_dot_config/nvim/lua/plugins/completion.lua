return {
  {
    "saghen/blink.cmp",
    opts = {
      completion = {
        menu = {
          auto_show = function(ctx)
            local bufnr = ctx and ctx.bufnr or 0
            return not vim.tbl_contains({ "text", "markdown", "plaintext" }, vim.bo[bufnr].filetype)
          end,
        },
      },
    },
  },
  {
    "hrsh7th/nvim-cmp",
    optional = true,
    opts = function(_, opts)
      local cmp = require("cmp")
      cmp.setup.filetype({ "markdown", "text", "plaintext" }, {
        completion = {
          autocomplete = false,
        },
      })
    end,
  },
}
