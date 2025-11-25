-- Tomcat Manager interface check
description = [[
Checks if Tomcat Manager interface is accessible and attempts
to identify default or weak credentials.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"auth", "intrusive"}

portrule = function(port)
    return port.number == 8080 or 
           port.number == 8443 or
           (port.service and port.service:lower():match("http"))
end

action = function(host, port)
    local http = require "http"
    local result = {}
    
    -- Common Tomcat manager paths
    local paths = {
        "/manager/html",
        "/manager/text",
        "/host-manager/html"
    }
    
    -- Common credentials
    local creds = {
        {"tomcat", "tomcat"},
        {"admin", "admin"},
        {"tomcat", "s3cret"},
        {"admin", "tomcat"},
        {"manager", "manager"}
    }
    
    for _, path in ipairs(paths) do
        local response = http.get(host, port, path)
        
        if response and response.status == 401 then
            table.insert(result, string.format("Manager interface found: %s (Requires auth)", path))
            
            -- Try common credentials
            for _, cred in ipairs(creds) do
                local auth_response = http.get(host, port, path, {
                    header = {
                        Authorization = "Basic " .. base64.encode(cred[1] .. ":" .. cred[2])
                    }
                })
                
                if auth_response and auth_response.status == 200 then
                    table.insert(result, string.format("VULNERABLE: Default credentials work: %s:%s", cred[1], cred[2]))
                end
            end
        elseif response and response.status == 200 then
            table.insert(result, string.format("CRITICAL: Manager accessible without authentication: %s", path))
        end
    end
    
    if #result > 0 then
        return table.concat(result, "\n")
    end
    
    return nil
end
