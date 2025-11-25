-- CORS Misconfiguration Detection
-- Checks for insecure CORS configurations
-- @output
-- 443/tcp open  https
-- | http-cors:
-- |   CORS Issues Found:
-- |     Access-Control-Allow-Origin: * (allows any origin)
-- |     Access-Control-Allow-Credentials: true (credentials with wildcard origin - HIGH RISK)
-- |_    Missing Access-Control-Max-Age header

description = [[
Detects Cross-Origin Resource Sharing (CORS) misconfigurations that could
allow unauthorized cross-domain requests. Checks for:
- Wildcard origins with credentials
- Reflected origin values
- Null origin acceptance
- Missing security headers
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "safe", "default"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https" or
           port.number == 80 or port.number == 443 or port.number == 8080
end

action = function(host, port)
    local http = require "http"
    local shortport = require "shortport"
    
    local issues = {}
    local scheme = "http"
    if port.number == 443 or port.service == "https" then
        scheme = "https"
    end
    
    local test_origin = "https://evil.com"
    local null_origin = "null"
    
    -- Test 1: Check for wildcard origin with credentials
    local options = {
        header = {
            Origin = test_origin,
            ["Access-Control-Request-Method"] = "GET"
        }
    }
    
    local response = http.get(host, port, "/", options)
    
    if response and response.header then
        local allow_origin = response.header["access-control-allow-origin"]
        local allow_creds = response.header["access-control-allow-credentials"]
        local max_age = response.header["access-control-max-age"]
        
        -- Critical: Wildcard with credentials
        if allow_origin == "*" and allow_creds == "true" then
            table.insert(issues, "CRITICAL: Access-Control-Allow-Credentials: true with wildcard origin")
            table.insert(issues, "  This allows any website to make credentialed requests")
        elseif allow_origin == "*" then
            table.insert(issues, "Access-Control-Allow-Origin: * (allows any origin)")
        end
        
        -- Check for reflected origin
        if allow_origin == test_origin then
            table.insert(issues, "Origin reflection detected: " .. test_origin)
            if allow_creds == "true" then
                table.insert(issues, "  HIGH RISK: Credentials enabled with reflected origin")
            end
        end
        
        -- Check for null origin acceptance
        options.header.Origin = null_origin
        local null_response = http.get(host, port, "/", options)
        if null_response and null_response.header then
            local null_allow = null_response.header["access-control-allow-origin"]
            if null_allow == "null" then
                table.insert(issues, "Null origin accepted (sandbox escape risk)")
            end
        end
        
        -- Check for missing max-age
        if allow_origin and not max_age then
            table.insert(issues, "Missing Access-Control-Max-Age header")
        end
        
        -- Check for overly permissive methods
        local allow_methods = response.header["access-control-allow-methods"]
        if allow_methods then
            local dangerous_methods = {"PUT", "DELETE", "PATCH", "TRACE"}
            for _, method in ipairs(dangerous_methods) do
                if allow_methods:find(method) then
                    table.insert(issues, "Dangerous method allowed: " .. method)
                end
            end
        end
    end
    
    if #issues > 0 then
        local result = "CORS Issues Found:\n"
        for _, issue in ipairs(issues) do
            result = result .. "  " .. issue .. "\n"
        end
        return result
    end
    
    return nil
end
