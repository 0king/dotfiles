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

	-- Copy-on-select: Copy directly to Clipboard and PrimarySelection on mouse release
	config.mouse_bindings = config.mouse_bindings or {}
	table.insert(config.mouse_bindings, {
		event = { Up = { streak = 1, button = "Left" } },
		mods = "NONE",
		action = act.CompleteSelectionOrOpenLinkAtMouseCursor("ClipboardAndPrimarySelection"),
	})
	table.insert(config.mouse_bindings, {
		event = { Up = { streak = 2, button = "Left" } },
		mods = "NONE",
		action = act.CompleteSelection("ClipboardAndPrimarySelection"),
	})
	table.insert(config.mouse_bindings, {
		event = { Up = { streak = 3, button = "Left" } },
		mods = "NONE",
		action = act.CompleteSelection("ClipboardAndPrimarySelection"),
	})

	-- Unified Line Scrolling (Arrow keys & Vim keys)
	table.insert(config.keys, { key = "Up", mods = "CTRL|SHIFT", action = act.ScrollByLine(-1) })
	table.insert(config.keys, { key = "Down", mods = "CTRL|SHIFT", action = act.ScrollByLine(1) })
	-- Explicitly override Ctrl+Shift+K to prevent WezTerm's default ClearScrollback
	table.insert(config.keys, { key = "k", mods = "CTRL|SHIFT", action = act.ScrollByLine(-1) })
	table.insert(config.keys, { key = "K", mods = "CTRL|SHIFT", action = act.ScrollByLine(-1) })
	table.insert(config.keys, { key = "j", mods = "CTRL|SHIFT", action = act.ScrollByLine(1) })
	table.insert(config.keys, { key = "J", mods = "CTRL|SHIFT", action = act.ScrollByLine(1) })

	-- Unified Page Scrolling
	table.insert(config.keys, { key = "PageUp", mods = "SHIFT", action = act.ScrollByPage(-1) })
	table.insert(config.keys, { key = "PageDown", mods = "SHIFT", action = act.ScrollByPage(1) })
	table.insert(config.keys, { key = "PageUp", mods = "CTRL|SHIFT", action = act.ScrollByPage(-1) })
	table.insert(config.keys, { key = "PageDown", mods = "CTRL|SHIFT", action = act.ScrollByPage(1) })

	-- Unified Boundary Scrolling
	table.insert(config.keys, { key = "Home", mods = "SHIFT", action = act.ScrollToTop })
	table.insert(config.keys, { key = "End", mods = "SHIFT", action = act.ScrollToBottom })
	table.insert(config.keys, { key = "Home", mods = "CTRL|SHIFT", action = act.ScrollToTop })
	table.insert(config.keys, { key = "End", mods = "CTRL|SHIFT", action = act.ScrollToBottom })

	-- Unified Vim Mode (ActivateCopyMode)
	table.insert(config.keys, { key = "Space", mods = "CTRL|SHIFT", action = act.ActivateCopyMode })
	table.insert(config.keys, { key = "phys:Space", mods = "CTRL|SHIFT", action = act.ActivateCopyMode })
	table.insert(config.keys, { key = "x", mods = "CTRL|SHIFT", action = act.ActivateCopyMode })
	table.insert(config.keys, { key = "X", mods = "CTRL|SHIFT", action = act.ActivateCopyMode })

	-- Unified Copy & Paste
	table.insert(config.keys, { key = "c", mods = "CTRL|SHIFT", action = act.CopyTo("Clipboard") })
	table.insert(config.keys, { key = "C", mods = "CTRL|SHIFT", action = act.CopyTo("Clipboard") })
	table.insert(config.keys, { key = "v", mods = "CTRL|SHIFT", action = act.PasteFrom("Clipboard") })
	table.insert(config.keys, { key = "V", mods = "CTRL|SHIFT", action = act.PasteFrom("Clipboard") })
	table.insert(config.keys, { key = "Insert", mods = "SHIFT", action = act.PasteFrom("PrimarySelection") })
	table.insert(config.keys, { key = "Insert", mods = "CTRL", action = act.CopyTo("Clipboard") })

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
