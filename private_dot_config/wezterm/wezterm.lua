-- Pull in the WezTerm API
local wezterm = require("wezterm")

-- This table will hold the configuration.
local config = {}

-- In newer versions of WezTerm, use the config_builder which gives clearer error messages
if wezterm.config_builder then
	config = wezterm.config_builder()
end

-- Modular configuration by category
require("config.ui").apply_to_config(config)
-- require("config.events").apply_to_config(config)
require("config.keys").apply_to_config(config)

-- Return the configuration table to WezTerm
return config
