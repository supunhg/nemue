-- Kubernetes API server check
description = [[
Detects Kubernetes API servers and checks for anonymous access
or misconfigurations.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe"}

portrule = function(port)
    return port.number == 6443 or 
           port.number == 8080 or 
           port.number == 10250 or
           (port.service and port.service:lower():match("kubernetes"))
end

action = function(host, port)
    local http = require "http"
    local json = require "json"
    local result = {}
    
    -- Try to access API server
    local paths = {
        "/api",
        "/api/v1",
        "/version",
        "/healthz"
    }
    
    for _, path in ipairs(paths) do
        local response = http.get(host, port, path)
        
        if response and response.status == 200 then
            table.insert(result, string.format("Kubernetes API accessible: %s", path))
            
            if path == "/version" then
                local success, data = pcall(json.decode, response.body)
                if success and data then
                    if data.major and data.minor then
                        table.insert(result, string.format("Version: %s.%s", data.major, data.minor))
                    end
                    if data.gitVersion then
                        table.insert(result, string.format("Git Version: %s", data.gitVersion))
                    end
                end
            end
        elseif response and response.status == 401 then
            table.insert(result, string.format("API requires authentication: %s (secure)", path))
        end
    end
    
    -- Check for anonymous access
    local namespaces = http.get(host, port, "/api/v1/namespaces")
    if namespaces and namespaces.status == 200 then
        table.insert(result, "")
        table.insert(result, "CRITICAL: Anonymous access enabled!")
        table.insert(result, "Namespaces are listable without authentication")
        
        local success, data = pcall(json.decode, namespaces.body)
        if success and data and data.items then
            table.insert(result, string.format("Namespaces found: %d", #data.items))
        end
    end
    
    -- Check kubelet port (10250)
    if port.number == 10250 then
        local pods = http.get(host, port, "/pods")
        if pods and pods.status == 200 then
            table.insert(result, "Kubelet API exposed on port 10250")
            table.insert(result, "WARNING: Potential unauthorized pod access")
        end
    end
    
    if #result > 0 then
        return table.concat(result, "\n")
    end
    
    return nil
end
