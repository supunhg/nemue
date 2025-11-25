-- HTTP TRACE method vulnerability check
description = [[
Checks if the HTTP TRACE method is enabled, which can be used
for cross-site tracing (XST) attacks to steal cookies.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "safe"}

portrule = function(port)
    return port.service and port.service:lower():match("http")
end

action = function(host, port)
    local http = require "http"
    local result = {}
    
    -- Send TRACE request
    local response = http.generic_request(host, port, "TRACE", "/")
    
    if response and response.status == 200 then
        table.insert(result, "VULNERABLE: TRACE method is enabled")
        table.insert(result, "Risk: Cross-Site Tracing (XST) attacks possible")
        table.insert(result, "Remediation: Disable TRACE method in web server configuration")
        
        -- Check if request is echoed
        if response.body and response.body:match("TRACE") then
            table.insert(result, "Confirmed: Server echoes TRACE requests")
        end
    end
    
    -- Also check OPTIONS for allowed methods
    local options = http.generic_request(host, port, "OPTIONS", "/")
    if options and options.header and options.header.allow then
        if options.header.allow:upper():match("TRACE") then
            table.insert(result, "Allow header includes TRACE method")
        end
        table.insert(result, "Allowed methods: " .. options.header.allow)
    end
    
    if #result > 0 then
        return table.concat(result, "\n")
    end
    
    return "TRACE method disabled (secure)"
end
