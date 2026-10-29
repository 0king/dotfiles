return {
  {
    "nvim-lualine/lualine.nvim",
    opts = function(_, opts)
      opts.sections.lualine_z = {
        {
          function()
            return vim.api.nvim_buf_line_count(0)
          end,
          icon = "", -- line symbol (Powerline LN). Alternative: use icon = "#L" or ""
        },
      }
    end,
  },
}
