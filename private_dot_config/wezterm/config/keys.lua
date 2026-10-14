local wezterm = require("wezterm")
local act = wezterm.action

local M = {}

function M.apply_to_config(config)
	config.keys = config.keys or {}

	-- Action: Copy entire scrollback to clipboard
	local select_all_and_copy = wezterm.action_callback(function(window, pane)
		local dims = pane:get_dimensions()
		local text = pane:get_lines_as_text(dims.scrollback_rows)
		-- Strip trailing blank lines
		text = text:gsub("%s+$", "")
		window:copy_to_clipboard(text, "Clipboard")
		window:copy_to_clipboard(text, "PrimarySelection")
	end)

	-- Action: Visual select all in Copy Mode
	local select_all_in_copy_mode = act.Multiple({
		act.ActivateCopyMode,
		act.CopyMode("MoveToScrollbackTop"),
		act.CopyMode({ SetSelectionMode = "Cell" }),
		act.CopyMode("MoveToScrollbackBottom"),
	})

	-- Action: Toggle Auto-Wrap (DECAWM) in the terminal
	-- Mode 7 (DECAWM): 'tput rmam' disables wrap (truncates at margin); 'tput smam' enables wrap
	local pane_wrap_state = {}
	local toggle_autowrap = wezterm.action_callback(function(window, pane)
		local pane_id = pane:pane_id()
		local is_wrapped = pane_wrap_state[pane_id] ~= false -- default is true
		if is_wrapped then
			pane:send_text("tput rmam\r")
			pane_wrap_state[pane_id] = false
			window:toast_notification("WezTerm", "Line wrap disabled (tput rmam)", nil, 2000)
		else
			pane:send_text("tput smam\r")
			pane_wrap_state[pane_id] = true
			window:toast_notification("WezTerm", "Line wrap enabled (tput smam)", nil, 2000)
		end
	end)

	-- Action: View current scrollback in pager without wrapping (horizontal scroll)
	local view_scrollback_unwrapped = wezterm.action_callback(function(window, pane)
		local dims = pane:get_dimensions()
		local text = pane:get_lines_as_text(dims.scrollback_rows)
		local tmp = os.tmpname()
		local f = io.open(tmp, "w+")
		if f then
			f:write(text)
			f:flush()
			f:close()
			window:perform_action(
				act.SpawnCommandInNewTab({
					args = { "less", "-S", "+G", tmp },
				}),
				pane
			)
		end
	end)

	-- Shortcut: Ctrl + Shift + A (Select All & Copy)
	table.insert(config.keys, {
		key = "a",
		mods = "CTRL|SHIFT",
		action = select_all_and_copy,
	})
	table.insert(config.keys, {
		key = "A",
		mods = "CTRL|SHIFT",
		action = select_all_and_copy,
	})

	-- Register in Command Palette (Ctrl + Shift + P)
	wezterm.on("augment-command-palette", function(window, pane)
		return {
			{
				brief = "Select All: Copy entire scrollback to clipboard",
				doc = "Copies all text from current pane's scrollback history to clipboard",
				icon = "md_content_copy",
				action = select_all_and_copy,
			},
			{
				brief = "Select All: Highlight all in Copy Mode",
				doc = "Enters Copy Mode and highlights all text from top to bottom",
				icon = "md_select_all",
				action = select_all_in_copy_mode,
			},
			{
				brief = "Toggle Line Wrap (DECAWM: tput rmam / smam)",
				doc = "Toggles terminal auto-wrap so lines truncate at margin instead of wrapping",
				icon = "md_wrap",
				action = toggle_autowrap,
			},
			{
				brief = "View Scrollback Unwrapped (less -S)",
				doc = "Opens scrollback in a new tab without wrapping, allowing horizontal scrolling",
				icon = "md_arrow_expand_horizontal",
				action = view_scrollback_unwrapped,
			},
		}
	end)
end

return M
