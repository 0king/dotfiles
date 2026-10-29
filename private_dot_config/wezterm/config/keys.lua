local wezterm = require("wezterm")
local act = wezterm.action

local M = {}

function M.apply_to_config(config)
	config.keys = config.keys or {}

	-- In-window subtle notification system
	-- Displays messages directly in the window title bar without triggering OS desktop toasts
	local active_notification = nil
	local notification_token = 0

	wezterm.on("format-window-title", function(tab, pane, tabs, panes, config)
		if active_notification then
			return active_notification
		end
		local title = (pane and pane.title) or (tab and tab.active_pane and tab.active_pane.title) or "WezTerm"
		if title == "" then
			title = "WezTerm"
		end
		return title
	end)

	local function notify(window, pane, message, duration_secs)
		duration_secs = duration_secs or 2.5
		notification_token = notification_token + 1
		local current_token = notification_token
		active_notification = "📋 " .. message

		-- Update right_status for subtle in-window feedback
		pcall(function()
			window:set_right_status(wezterm.format({
				{ Attribute = { Intensity = "Bold" } },
				{ Background = { Color = "#2e3440" } },
				{ Foreground = { Color = "#88c0d0" } },
				{ Text = "  " .. active_notification .. "  " },
			}))
		end)

		-- Auto-clear after duration_secs
		wezterm.time.call_after(duration_secs, function()
			if notification_token == current_token then
				active_notification = nil
				pcall(function()
					window:set_right_status("")
				end)
			end
		end)
	end

	-- Action: Single unified Select All command
	-- Identifies pane state, selects everything beyond the viewport (from Row 1, Column 1 to bottom), and copies it
	local select_all = wezterm.action_callback(function(window, pane)
		local is_copy_mode = window:active_key_table() == "copy_mode"
		local is_alt = pane.is_alt_screen_active and pane:is_alt_screen_active()
		local dims = pane:get_dimensions()
		local total_lines = dims.scrollback_rows
		local viewport_lines = dims.viewport_rows
		local beyond_viewport = math.max(0, total_lines - viewport_lines)

		if is_copy_mode then
			-- State: Currently in Copy Mode
			-- Visually select from Row 1, Column 1 to bottom end, copy to clipboard, and close
			window:perform_action(act.CopyMode("MoveToScrollbackTop"), pane)
			window:perform_action(act.CopyMode("MoveToStartOfLine"), pane)
			window:perform_action(act.CopyMode({ SetSelectionMode = "Cell" }), pane)
			window:perform_action(act.CopyMode("MoveToScrollbackBottom"), pane)
			window:perform_action(act.CopyMode("MoveToEndOfLineContent"), pane)
			window:perform_action(act.CopyTo("ClipboardAndPrimarySelection"), pane)
			window:perform_action(act.CopyMode("Close"), pane)
		end

		-- Extract all text:
		-- In alternate screen, only active viewport rows exist.
		-- In normal screen, retrieves all lines (including everything beyond the viewport up to Row 1).
		local lines_to_get = is_alt and viewport_lines or total_lines
		local text = pane:get_lines_as_text(lines_to_get)
		if text then
			text = text:gsub("%s+$", "")
			window:copy_to_clipboard(text, "Clipboard")
			window:copy_to_clipboard(text, "PrimarySelection")
		end

		-- Provide clear, subtle in-window feedback
		if is_alt then
			notify(
				window,
				pane,
				string.format("Copied active viewport (%d lines - fullscreen app active)", viewport_lines),
				2.5
			)
		elseif beyond_viewport > 0 then
			notify(
				window,
				pane,
				string.format("Copied all (%d lines beyond viewport)", total_lines, beyond_viewport),
				2.5
			)
		else
			notify(window, pane, string.format("Copied all %d lines from Row 1", total_lines), 2.5)
		end
	end)

	-- Action: Scroll to Top (Row 1, Column 1) across normal mode and Copy Mode
	local scroll_to_top = wezterm.action_callback(function(window, pane)
		local is_alt = pane.is_alt_screen_active and pane:is_alt_screen_active()
		if is_alt then
			notify(window, pane, "NB: scrollback managed inside app", 2.5)
		end
		window:perform_action(act.ScrollToTop, pane)
		window:perform_action(act.CopyMode("MoveToScrollbackTop"), pane)
		window:perform_action(act.CopyMode("MoveToStartOfLine"), pane)
	end)

	-- Action: Scroll to Bottom across normal mode and Copy Mode
	local scroll_to_bottom = wezterm.action_callback(function(window, pane)
		window:perform_action(act.ScrollToBottom, pane)
		window:perform_action(act.CopyMode("MoveToScrollbackBottom"), pane)
		window:perform_action(act.CopyMode("MoveToEndOfLineContent"), pane)
	end)

	-- Action: Toggle Auto-Wrap (DECAWM) in the terminal
	-- Mode 7 (DECAWM): 'tput rmam' disables wrap (truncates at margin); 'tput smam' enables wrap
	local pane_wrap_state = {}
	local toggle_autowrap = wezterm.action_callback(function(window, pane)
		local pane_id = pane:pane_id()
		local is_wrapped = pane_wrap_state[pane_id] ~= false -- default is true
		if is_wrapped then
			pane:send_text("tput rmam\r")
			pane_wrap_state[pane_id] = false
			notify(window, pane, "Line wrap disabled (tput rmam)", 2.0)
		else
			pane:send_text("tput smam\r")
			pane_wrap_state[pane_id] = true
			notify(window, pane, "Line wrap enabled (tput smam)", 2.0)
		end
	end)

	-- Action: Open scrollback in Neovim pager with full ANSI color support (dismisses with 'q')
	local function create_scrollback_pager_action(with_numbers)
		return wezterm.action_callback(function(window, pane)
			local dims = pane:get_dimensions()
			local is_alt = pane.is_alt_screen_active and pane:is_alt_screen_active()
			local lines = is_alt and dims.viewport_rows or dims.scrollback_rows
			if not lines or lines <= 0 then
				lines = dims.viewport_rows or 2000
			end

			-- Capture lines with ANSI color escape sequences
			local text = pane:get_lines_as_escapes(lines)
			if not text or text == "" then
				text = pane:get_lines_as_text(lines) or ""
			end

			local tmp = string.format("/tmp/wezterm_scrollback_%d_%d.txt", pane:pane_id(), os.time())
			local f = io.open(tmp, "w+")
			if not f then
				notify(window, pane, "Error: unable to write temporary scrollback", 2.5)
				return
			end
			f:write(text)
			f:flush()
			f:close()

			-- Check if nvim is available; fall back to less with ANSI support if not
			local has_nvim = true
			local ok_nvim, nvim_path = pcall(function()
				return wezterm.run_child_process({ "which", "nvim" })
			end)
			if not ok_nvim or not nvim_path or nvim_path == "" then
				has_nvim = false
			end

			local pager_args
			if has_nvim then
				pager_args = {
					"nvim",
					"--cmd",
					"set eventignore=FileType",
					"+let ch = nvim_open_term(0, {})",
					"+call chansend(ch, join(readfile('" .. tmp .. "', 'b'), \"\\r\\n\"))",
					"+sleep 50m",
					"+nnoremap <buffer> q :qa!<CR>",
					"+nnoremap <buffer> <Esc> :qa!<CR>",
					"+set nomodified nolist",
				}
				if with_numbers then
					table.insert(pager_args, "+set number")
				else
					table.insert(pager_args, "+set nonumber")
				end
				table.insert(pager_args, "+$")
				table.insert(pager_args, "+autocmd VimLeave * call delete('" .. tmp .. "')")
			else
				pager_args = {
					"less",
					with_numbers and "-N" or "-S",
					"-R",
					"-S",
					"+G",
					tmp,
				}
			end

			window:perform_action(
				act.SpawnCommandInNewTab({
					args = pager_args,
				}),
				pane
			)

			-- Safety garbage collection for temporary buffer
			wezterm.time.call_after(60, function()
				pcall(os.remove, tmp)
			end)

			if is_alt then
				notify(window, pane, "Scrollback pager: active viewport (fullscreen app active)", 2.5)
			end
		end)
	end

	local view_scrollback_pager = create_scrollback_pager_action(false)
	local view_scrollback_numbered = create_scrollback_pager_action(true)

	-- Shortcut: Ctrl + Shift + A (Select All & Copy)
	table.insert(config.keys, {
		key = "a",
		mods = "CTRL|SHIFT",
		action = select_all,
	})
	table.insert(config.keys, {
		key = "A",
		mods = "CTRL|SHIFT",
		action = select_all,
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

	-- Unified Boundary Scrolling (handles normal viewport and Copy Mode cursor)
	table.insert(config.keys, { key = "Home", mods = "SHIFT", action = scroll_to_top })
	table.insert(config.keys, { key = "End", mods = "SHIFT", action = scroll_to_bottom })
	table.insert(config.keys, { key = "Home", mods = "CTRL|SHIFT", action = scroll_to_top })
	table.insert(config.keys, { key = "End", mods = "CTRL|SHIFT", action = scroll_to_bottom })

	-- Unified Vim Mode (ActivateCopyMode)
	table.insert(config.keys, { key = "Space", mods = "CTRL|SHIFT", action = act.ActivateCopyMode })
	table.insert(config.keys, { key = "phys:Space", mods = "CTRL|SHIFT", action = act.ActivateCopyMode })
	table.insert(config.keys, { key = "x", mods = "CTRL|SHIFT", action = act.ActivateCopyMode })
	table.insert(config.keys, { key = "X", mods = "CTRL|SHIFT", action = act.ActivateCopyMode })

	-- Unified Scrollback Pager with Line Numbers in Neovim (Ctrl + Shift + H)
	table.insert(config.keys, { key = "h", mods = "CTRL|SHIFT", action = view_scrollback_numbered })
	table.insert(config.keys, { key = "H", mods = "CTRL|SHIFT", action = view_scrollback_numbered })

	-- Setup Copy Mode key table without breaking default keybindings
	local key_tables = {}
	if wezterm.gui then
		key_tables = wezterm.gui.default_key_tables()
	end
	key_tables.copy_mode = key_tables.copy_mode or {}

	local move_to_top_col1 = act.Multiple({
		act.CopyMode("MoveToScrollbackTop"),
		act.CopyMode("MoveToStartOfLine"),
	})
	local move_to_bottom_end = act.Multiple({
		act.CopyMode("MoveToScrollbackBottom"),
		act.CopyMode("MoveToEndOfLineContent"),
	})
	local select_all_cells = act.Multiple({
		act.CopyMode("MoveToScrollbackTop"),
		act.CopyMode("MoveToStartOfLine"),
		act.CopyMode({ SetSelectionMode = "Cell" }),
		act.CopyMode("MoveToScrollbackBottom"),
		act.CopyMode("MoveToEndOfLineContent"),
	})
	local select_all_lines = act.Multiple({
		act.CopyMode("MoveToScrollbackTop"),
		act.CopyMode({ SetSelectionMode = "Line" }),
		act.CopyMode("MoveToScrollbackBottom"),
	})

	-- Copy Mode: Jump to Row 1, Column 1
	table.insert(key_tables.copy_mode, { key = "Home", mods = "NONE", action = move_to_top_col1 })
	table.insert(key_tables.copy_mode, { key = "Home", mods = "SHIFT", action = move_to_top_col1 })
	table.insert(key_tables.copy_mode, { key = "Home", mods = "CTRL", action = move_to_top_col1 })
	table.insert(key_tables.copy_mode, { key = "Home", mods = "CTRL|SHIFT", action = move_to_top_col1 })
	table.insert(key_tables.copy_mode, { key = "g", mods = "NONE", action = move_to_top_col1 })

	-- Copy Mode: Jump to Bottom, End of Line
	table.insert(key_tables.copy_mode, { key = "End", mods = "NONE", action = move_to_bottom_end })
	table.insert(key_tables.copy_mode, { key = "End", mods = "SHIFT", action = move_to_bottom_end })
	table.insert(key_tables.copy_mode, { key = "End", mods = "CTRL", action = move_to_bottom_end })
	table.insert(key_tables.copy_mode, { key = "End", mods = "CTRL|SHIFT", action = move_to_bottom_end })
	table.insert(key_tables.copy_mode, { key = "G", mods = "NONE", action = move_to_bottom_end })
	table.insert(key_tables.copy_mode, { key = "G", mods = "SHIFT", action = move_to_bottom_end })

	-- Copy Mode: Select All shortcuts (Ctrl+A, Ctrl+Shift+A, a, A)
	table.insert(key_tables.copy_mode, { key = "a", mods = "CTRL", action = select_all_cells })
	table.insert(key_tables.copy_mode, { key = "a", mods = "CTRL|SHIFT", action = select_all_cells })
	table.insert(key_tables.copy_mode, { key = "A", mods = "CTRL|SHIFT", action = select_all_cells })
	table.insert(key_tables.copy_mode, { key = "a", mods = "NONE", action = select_all_cells })
	table.insert(key_tables.copy_mode, { key = "A", mods = "NONE", action = select_all_lines })
	table.insert(key_tables.copy_mode, { key = "A", mods = "SHIFT", action = select_all_lines })

	config.key_tables = key_tables

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
			{
				brief = "Pane Select (pin)",
				doc = "Show letter overlay across all panes",
				icon = "md_bookmark",
				action = act.PaneSelect({ mode = "Activate" }),
			},
			{
				brief = "Close Pane (pin)",
				doc = "Close the currently active pane",
				icon = "md_bookmark",
				action = act.CloseCurrentPane({ confirm = true }),
			},
			{
				brief = "Smart Paste (pin)",
				doc = "Pastes from the newest buffer (Clipboard or Primary Selection)",
				icon = "md_bookmark",
				action = smart_paste,
			},
			-- All Scroll Variants
			{
				brief = "Scroll to Top (pin) (Row 1, Col 1)",
				icon = "md_bookmark",
				action = scroll_to_top,
			},
			{
				brief = "Scroll to Bottom (pin)",
				icon = "md_bookmark",
				action = scroll_to_bottom,
			},
			{
				brief = "Scroll Page Up (pin)",
				icon = "md_bookmark",
				action = act.ScrollByPage(-1),
			},
			{
				brief = "Scroll Page Down (pin)",
				icon = "md_bookmark",
				action = act.ScrollByPage(1),
			},
			{
				brief = "Scroll Half Page Up (pin)",
				icon = "md_bookmark",
				action = act.ScrollByPage(-0.5),
			},
			{
				brief = "Scroll Half Page Down (pin)",
				icon = "md_bookmark",
				action = act.ScrollByPage(0.5),
			},
			{
				brief = "Scroll Line Up (pin)",
				icon = "md_bookmark",
				action = act.ScrollByLine(-1),
			},
			{
				brief = "Scroll Line Down (pin)",
				icon = "md_bookmark",
				action = act.ScrollByLine(1),
			},
			{
				brief = "Scroll to Previous Prompt (pin)",
				icon = "md_bookmark",
				action = act.ScrollToPrompt(-1),
			},
			{
				brief = "Scroll to Next Prompt (pin)",
				icon = "md_bookmark",
				action = act.ScrollToPrompt(1),
			},
			{
				brief = "Select All (pin)",
				doc = " - copies entire scrollback history",
				icon = "md_bookmark",
				action = select_all,
			},
			{
				brief = "Vim Mode (pin) (QuickSelectMode) (ESC-quit) <C-S-space>",
				icon = "md_bookmark",
				action = act.ActivateCopyMode,
			},
			{
				brief = "Highlight Mode (pin)",
				doc = "Highlight URLs, paths, and git hashes",
				icon = "md_bookmark",
				action = act.QuickSelect,
			},
			{
				brief = "Toggle Line Wrap (pin)",
				icon = "md_bookmark",
				action = toggle_autowrap,
			},
			-- {
			-- 	brief = "Open Scrollback in Pager (pin)",
			-- 	doc = "Opens scrollback buffer with ANSI colors in Neovim (press q to quit)",
			-- 	icon = "md_bookmark",
			-- 	action = view_scrollback_pager,
			-- },
			{
				brief = "Open Scrollback with Line Numbers (pin) (q=quit) <C-S-h>",
				--doc = "Opens scrollback buffer with line numbers in Neovim (press q to quit)",
				icon = "md_format_list_numbered",
				action = view_scrollback_numbered,
			},
		}
	end)
end

return M
