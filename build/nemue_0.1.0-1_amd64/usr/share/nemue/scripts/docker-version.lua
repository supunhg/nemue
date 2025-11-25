-- Docker version detection
description = [[
Detects Docker daemon version and checks for known vulnerabilities
in the exposed Docker API.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"version", "safe"}

portrule = function(port)
    return port.number == 2375 or 
           port.number == 2376 or
           (port.service and port.service:lower():match("docker"))
end

action = function(host, port)
    local http = require "http"
    local json = require "json"
    local result = {}
    
    -- Try to get version info
    local response = http.get(host, port, "/version")
    
    if response and response.status == 200 then
        local success, data = pcall(json.decode, response.body)
        
        if success and data then
            table.insert(result, "Docker daemon exposed!")
            
            if data.Version then
                table.insert(result, string.format("Version: %s", data.Version))
            end
            
            if data.ApiVersion then
                table.insert(result, string.format("API Version: %s", data.ApiVersion))
            end
            
            if data.Os then
                table.insert(result, string.format("OS: %s", data.Os))
            end
            
            if data.Arch then
                table.insert(result, string.format("Architecture: %s", data.Arch))
            end
            
            if data.KernelVersion then
                table.insert(result, string.format("Kernel: %s", data.KernelVersion))
            end
            
            -- Check if TLS is enabled
            if port.number == 2375 then
                table.insert(result, "")
                table.insert(result, "WARNING: Docker API exposed without TLS!")
                table.insert(result, "Risk: Unauthenticated remote code execution")
            end
            
            -- Try to list containers
            local containers = http.get(host, port, "/containers/json?all=true")
            if containers and containers.status == 200 then
                local success, container_data = pcall(json.decode, containers.body)
                if success and container_data then
                    table.insert(result, string.format("Containers visible: %d", #container_data))
                end
            end
            
            return table.concat(result, "\n")
        end
    end
    
    return nil
end
