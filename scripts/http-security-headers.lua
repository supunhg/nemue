-- HTTP Security Headers Check Script
-- Checks for presence of important security headers

local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Checks HTTP response for important security headers:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy
]]

categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and (
        port.service == "http" or 
        port.service == "https" or
        port.number == 80 or 
        port.number == 443 or
        port.number == 8080 or
        port.number == 8443
    )
end

action = function(host, port)
    local response = http.get(host, port, "/")
    
    if not response or not response.status then
        return nil
    end
    
    local output = {}
    local warnings = {}
    
    -- Check each security header
    local headers_to_check = {
        {"Strict-Transport-Security", "HSTS", true},
        {"Content-Security-Policy", "CSP", true},
        {"X-Frame-Options", "Clickjacking Protection", true},
        {"X-Content-Type-Options", "MIME Sniffing Protection", true},
        {"X-XSS-Protection", "XSS Protection", false},
        {"Referrer-Policy", "Referrer Policy", true},
        {"Permissions-Policy", "Permissions Policy", false},
    }
    
    for _, header_info in ipairs(headers_to_check) do
        local header_name = header_info[1]
        local display_name = header_info[2]
        local important = header_info[3]
        
        local value = response.header[header_name:lower()]
        if value then
            table.insert(output, "[+] " .. display_name .. ": " .. value)
        else
            local status = important and "MISSING" or "Not set"
            table.insert(output, "[-] " .. display_name .. ": " .. status)
            if important then
                table.insert(warnings, display_name .. " is missing")
            end
        end
    end
    
    -- Check server header information leakage
    if response.header["server"] then
        table.insert(output, "[i] Server: " .. response.header["server"])
    end
    
    -- Check X-Powered-By
    if response.header["x-powered-by"] then
        table.insert(output, "[i] X-Powered-By: " .. response.header["x-powered-by"])
        table.insert(warnings, "X-Powered-By header reveals technology")
    end
    
    -- Summary
    if #warnings > 0 then
        table.insert(output, "")
        table.insert(output, "Warnings:")
        for _, warning in ipairs(warnings) do
            table.insert(output, "  - " .. warning)
        end
    end
    
    return stdnse.format_output(true, output)
end
