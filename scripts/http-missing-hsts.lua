-- Missing HSTS Detection
-- Checks for missing HTTP Strict Transport Security header

local http = require("http")
local stdnse = require("stdnse")

description = [[
Checks for missing HTTP Strict Transport Security (HSTS) header
which is essential for preventing protocol downgrade attacks.
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

    table.insert(output, "HSTS Check")
    table.insert(output, "")

    local hsts = response.header and response.header["strict-transport-security"]

    if hsts then
        table.insert(output, "[+] HSTS Header Present: " .. hsts)
    else
        table.insert(output, "[-] HSTS: MISSING")

        if port.service == "https" or port.number == 443 then
            table.insert(output, "")
            table.insert(output, "[!] MEDIUM: HTTPS without HSTS is vulnerable to downgrade attacks")
            table.insert(output, "[!] Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains")
        end
    end

    return stdnse.format_output(true, output)
end
