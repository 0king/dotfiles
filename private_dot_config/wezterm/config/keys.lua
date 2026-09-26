local wezterm = require("wezterm")
local act = wezterm.action

local M = {}

function M.apply_to_config(config)
	-- Keybindings configuration
	--
	-- Example Leader key:
	-- config.leader = { key = "a", mods = "CTRL", timeout_milliseconds = 1000 }
	--
	-- Example custom key assignments:
	-- config.keys = {
	-- 	{ key = "v", mods = "CTRL|SHIFT", action = act.PasteFrom("Clipboard") },
	-- 	{ key = "c", mods = "CTRL|SHIFT", action = act.CopyTo("Clipboard") },
	-- }
end

return M
