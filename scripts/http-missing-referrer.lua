-- Missing Referrer-Policy Detection
-- Checks for missing referrer policy header

local http = require("http")
local stdnse = require("stdnse")

description = [[
Checks for missing Referrer-Policy header which controls how much
referrer information is sent with requests.
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

    table.insert(output, "Referrer-Policy Check")
    table.insert(output, "")

    local referrer = response.header and response.header["referrer-policy"]

    if referrer then
        table.insert(output, "[+] Referrer-Policy: " .. referrer)
        if referrer:lower() == "unsafe-url" then
            table.insert(output, "[!] unsafe-url leaks full URLs to external sites")
        elseif referrer:lower() == "no-referrer-when-downgrade" then
            table.insert(output, "[!] Consider stricter policy like 'strict-origin-when-cross-origin'")
        end
    else
        table.insert(output, "[-] Referrer-Policy: MISSING")
        table.insert(output, "")
        table.insert(output, "[!] LOW: No referrer policy configured")
        table.insert(output, "[!] Browser defaults may leak sensitive URL data")
        table.insert(output, "[!] Add header: Referrer-Policy: strict-origin-when-cross-origin")
    end

    return stdnse.format_output(true, output)
end
