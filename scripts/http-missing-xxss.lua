-- Missing X-XSS-Protection Detection
-- Checks for missing XSS protection header

local http = require("http")
local stdnse = require("stdnse")

description = [[
Checks for missing X-XSS-Protection header which enables
browser-level XSS filtering (legacy, but still useful for older browsers).
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "web"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080)
end

action = function(host, port)
    local output = {}
    local response = http.get(host.ip, port, "/")

    if not response then
        return "No HTTP response received"
    end

    table.insert(output, "X-XSS-Protection Check")
    table.insert(output, "")

    local xxss = response.header and response.header["x-xss-protection"]

    if xxss then
        table.insert(output, "[+] X-XSS-Protection: " .. xxss)
        if xxss:find("0") then
            table.insert(output, "[!] XSS filter is disabled (set to 0)")
        elseif xxss:find("1; mode=block") then
            table.insert(output, "[+] XSS filter in block mode (good)")
        elseif xxss == "1" then
            table.insert(output, "[!] XSS filter enabled but not in block mode")
        end
    else
        table.insert(output, "[-] X-XSS-Protection: MISSING")
        table.insert(output, "")
        table.insert(output, "[!] LOW: No browser XSS filter header")
        table.insert(output, "[!] Add header: X-XSS-Protection: 1; mode=block")
        table.insert(output, "[!] Note: CSP is preferred over X-XSS-Protection")
    end

    return stdnse.format_output(true, output)
end
