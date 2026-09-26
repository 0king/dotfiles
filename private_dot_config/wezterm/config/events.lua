local wezterm = require("wezterm")
local mux = wezterm.mux

local M = {}

function M.apply_to_config(config)
	-- Open with a horizontal split (side-by-side) on startup
	wezterm.on("gui-startup", function(cmd)
		local tab, pane, window = mux.spawn_window(cmd or {})
		pane:split({ direction = "Right" })
		pane:activate()
	end)

	-- Remember window size across launches
	local cache_file = wezterm.home_dir .. "/.cache/wezterm_window_size.txt"
	local f = io.open(cache_file, "r")
	if f then
		local cols, rows = f:read("*n", "*n")
		f:close()
		if cols and rows then
			config.initial_cols = cols
			config.initial_rows = rows
		end
	end

	-- Save updated dimensions when resized
	wezterm.on("window-resized", function(window, pane)
		local tab = window:active_tab()
		local cols, rows
		if tab then
			local size = tab:get_size()
			cols = size.cols
			rows = size.rows
		else
			local dims = pane:get_dimensions()
			cols = dims.cols
			rows = dims.viewport_rows
		end
		local out = io.open(cache_file, "w")
		if out then
			out:write(string.format("%d %d\n", cols, rows))
			out:close()
		end
	end)
end

return M
