return {
  {
    "saghen/blink.cmp",
    opts = function(_, opts)
      local is_plain_text = function(bufnr)
        bufnr = (bufnr and bufnr ~= 0) and bufnr or vim.api.nvim_get_current_buf()
        return vim.tbl_contains({ "text", "markdown", "plaintext" }, vim.bo[bufnr].filetype)
      end

      opts.completion = opts.completion or {}
      opts.completion.menu = opts.completion.menu or {}
      opts.completion.menu.auto_show = function(ctx)
        return not is_plain_text(ctx and ctx.bufnr)
      end

      opts.completion.ghost_text = opts.completion.ghost_text or {}
      opts.completion.ghost_text.enabled = function()
        if is_plain_text(0) then
          return false
        end
        return vim.g.ai_cmp
      end
    end,
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
