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
	table.insert(config.keys, { key = "UpArrow", mods = "CTRL|SHIFT", action = act.ScrollByLine(-1) })
	table.insert(config.keys, { key = "DownArrow", mods = "CTRL|SHIFT", action = act.ScrollByLine(1) })
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

	-- Action: Smart Paste (paste whichever clipboard has the latest data)
	local last_cb_content = ""
	local last_pr_content = ""
	local last_cb_time = 0
	local last_pr_time = 0

	local smart_paste = wezterm.action_callback(function(window, pane)
		local is_wayland = os.getenv("WAYLAND_DISPLAY") ~= nil
		local cb_text = ""
		local pr_text = ""

		if is_wayland then
			local ok_cb, out_cb = wezterm.run_child_process({ "wl-paste", "--no-newline" })
			if ok_cb and out_cb then
				cb_text = out_cb
			end
			local ok_pr, out_pr = wezterm.run_child_process({ "wl-paste", "--primary", "--no-newline" })
			if ok_pr and out_pr then
				pr_text = out_pr
			end
		elseif os.getenv("DISPLAY") ~= nil then
			local ok_cb, out_cb = wezterm.run_child_process({ "xclip", "-selection", "clipboard", "-o" })
			if ok_cb and out_cb then
				cb_text = out_cb
			end
			local ok_pr, out_pr = wezterm.run_child_process({ "xclip", "-selection", "primary", "-o" })
			if ok_pr and out_pr then
				pr_text = out_pr
			end
		end

		local now = os.time()
		if cb_text ~= "" and cb_text ~= last_cb_content then
			last_cb_content = cb_text
			last_cb_time = now
		end
		if pr_text ~= "" and pr_text ~= last_pr_content then
			last_pr_content = pr_text
			last_pr_time = now
		end

		local text_to_paste = ""
		if cb_text ~= "" and pr_text ~= "" then
			if last_pr_time > last_cb_time then
				text_to_paste = pr_text
			else
				text_to_paste = cb_text
			end
		elseif cb_text ~= "" then
			text_to_paste = cb_text
		elseif pr_text ~= "" then
			text_to_paste = pr_text
		end

		if text_to_paste ~= "" then
			pane:send_paste(text_to_paste)
		else
			-- Fallback to native WezTerm action if external tools are absent or returned empty
			window:perform_action(act.PasteFrom("Clipboard"), pane)
		end
	end)

	-- Unified Copy & Paste
	table.insert(config.keys, { key = "c", mods = "CTRL|SHIFT", action = act.CopyTo("Clipboard") })
	table.insert(config.keys, { key = "C", mods = "CTRL|SHIFT", action = act.CopyTo("Clipboard") })
	table.insert(config.keys, { key = "v", mods = "CTRL|SHIFT", action = act.PasteFrom("Clipboard") })
	table.insert(config.keys, { key = "Insert", mods = "SHIFT", action = act.PasteFrom("PrimarySelection") })
	table.insert(config.keys, { key = "Insert", mods = "CTRL", action = act.CopyTo("Clipboard") })

	-- Window Management
	table.insert(config.keys, { key = "n", mods = "CTRL|SHIFT", action = act.SpawnWindow })
	table.insert(config.keys, { key = "N", mods = "CTRL|SHIFT", action = act.SpawnWindow })

	-- Register in Command Palette (Ctrl + Shift + P)
	wezterm.on("augment-command-palette", function(window, pane)
		return {
			-- Pane - All Select
			{
				brief = "Pane Select (pin)",
				doc = "Show letter overlay across all panes to select and jump to any pane",
				icon = "md_bookmark",
				action = act.PaneSelect({ mode = "Activate" }),
			},
			-- Close Pane
			{
				brief = "Close Pane (pin)",
				doc = "Close the currently active pane with confirmation",
				icon = "md_bookmark",
				action = act.CloseCurrentPane({ confirm = true }),
			},
			-- Smart Paste (uses existing smart_paste action)
			{
				brief = "Smart Paste (pin)",
				doc = "Pastes text from whichever buffer (Clipboard or Primary Selection) has newer data",
				icon = "md_bookmark",
				action = smart_paste,
			},
			-- All Scroll Variants
			{
				brief = "Scroll to Top (pin)",
				doc = "Scroll all the way to the top of the scrollback buffer",
				icon = "md_bookmark",
				action = act.ScrollToTop,
			},
			{
				brief = "Scroll to Bottom (pin)",
				doc = "Scroll all the way to the bottom of the scrollback buffer",
				icon = "md_bookmark",
				action = act.ScrollToBottom,
			},
			{
				brief = "Scroll Page Up (pin)",
				doc = "Scroll viewport up by one full page",
				icon = "md_bookmark",
				action = act.ScrollByPage(-1),
			},
			{
				brief = "Scroll Page Down (pin)",
				doc = "Scroll viewport down by one full page",
				icon = "md_bookmark",
				action = act.ScrollByPage(1),
			},
			{
				brief = "Scroll Half Page Up (pin)",
				doc = "Scroll viewport up by half a page",
				icon = "md_bookmark",
				action = act.ScrollByPage(-0.5),
			},
			{
				brief = "Scroll Half Page Down (pin)",
				doc = "Scroll viewport down by half a page",
				icon = "md_bookmark",
				action = act.ScrollByPage(0.5),
			},
			{
				brief = "Scroll Line Up (pin)",
				doc = "Scroll viewport up by one line",
				icon = "md_bookmark",
				action = act.ScrollByLine(-1),
			},
			{
				brief = "Scroll Line Down (pin)",
				doc = "Scroll viewport down by one line",
				icon = "md_bookmark",
				action = act.ScrollByLine(1),
			},
			{
				brief = "Scroll to Previous Prompt (pin)",
				doc = "Scroll backward to the previous shell prompt zone",
				icon = "md_bookmark",
				action = act.ScrollToPrompt(-1),
			},
			{
				brief = "Scroll to Next Prompt (pin)",
				doc = "Scroll forward to the next shell prompt zone",
				icon = "md_bookmark",
				action = act.ScrollToPrompt(1),
			},
			-- Select All (uses existing select_all actions)
			{
				brief = "Select All (pin)",
				doc = "Copies all text from current pane's scrollback history to clipboard",
				icon = "md_bookmark",
				action = select_all_and_copy,
			},
			{
				brief = "Select All in Copy Mode (pin)",
				doc = "Enters Copy Mode and highlights all text from top to bottom",
				icon = "md_bookmark",
				action = select_all_in_copy_mode,
			},
			-- Vim Mode
			{
				brief = "Vim Mode (pin)",
				doc = "Enter modal copy mode with Vim keybindings (hjkl navigation, v/V to select, y to copy)",
				icon = "md_bookmark",
				action = act.ActivateCopyMode,
			},
			-- Highlight Mode
			{
				brief = "Highlight Mode (pin)",
				doc = "Highlight URLs, paths, and git hashes with jump hints for one-key copying",
				icon = "md_bookmark",
				action = act.QuickSelect,
			},
			-- Existing Helper Actions
			{
				brief = "Toggle Line Wrap (pin)",
				doc = "Toggles terminal auto-wrap so lines truncate at margin instead of wrapping",
				icon = "md_bookmark",
				action = toggle_autowrap,
			},
			{
				brief = "View Scrollback Unwrapped (pin)",
				doc = "Opens scrollback in a new tab without wrapping, allowing horizontal scrolling",
				icon = "md_bookmark",
				action = view_scrollback_unwrapped,
			},
		}
	end)
end

return M
