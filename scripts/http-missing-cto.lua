-- Missing X-Content-Type-Options Detection
-- Checks for missing MIME sniffing protection

local http = require("http")
local stdnse = require("stdnse")

description = [[
Checks for missing X-Content-Type-Options header which prevents
MIME type sniffing attacks.
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

    table.insert(output, "X-Content-Type-Options Check")
    table.insert(output, "")

    local cto = response.header and response.header["x-content-type-options"]

    if cto then
        table.insert(output, "[+] X-Content-Type-Options: " .. cto)
        if cto:lower() ~= "nosniff" then
            table.insert(output, "[!] Should be set to 'nosniff'")
        end
    else
        table.insert(output, "[-] X-Content-Type-Options: MISSING")
        table.insert(output, "")
        table.insert(output, "[!] LOW: No MIME sniffing protection")
        table.insert(output, "[!] Add header: X-Content-Type-Options: nosniff")
    end

    return stdnse.format_output(true, output)
end
