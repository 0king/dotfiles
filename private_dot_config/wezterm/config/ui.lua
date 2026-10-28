local wezterm = require("wezterm")

local M = {}

function M.apply_to_config(config)
	-- Color scheme & opacity
	-- config.color_scheme = "GitHub Dark"
	config.window_background_opacity = 0.8
	-- Window background gradient
	-- config.window_background_gradient = {
	--	colors = { "#000000", "#3F0C4B" },
	--	orientation = { Linear = { angle = -45.0 } },
	-- }

	-- Window frame styling
	-- config.window_frame = {
	-- 	inactive_titlebar_bg = "#353535",
	-- 	active_titlebar_bg = "#074f01",
	-- }

	-- Font configuration
	config.font = wezterm.font("FiraCode Nerd Font")
	config.font_size = 12.0
	config.adjust_window_size_when_changing_font_size = false
	config.line_height = 1.2

	-- Cursor configuration
	config.default_cursor_style = "BlinkingBar"
	config.cursor_blink_rate = 500

	-- Tab bar: hide when there is only one tab
	config.hide_tab_bar_if_only_one_tab = true
	config.show_tab_index_in_tab_bar = true

	-- Permanent scrollbar (inherits theme's native colors without hardcoding)
	config.enable_scroll_bar = true
	config.min_scroll_bar_height = "1.5cell"

	-- Window padding (reserving space for right scrollbar gutter)
	config.window_padding = {
		left = 8,
		right = 10,
		top = 8,
		bottom = 8,
	}

	-- Command palette styling
	config.command_palette_bg_color = "#000000"
	config.command_palette_fg_color = "#686767"
end

return M
