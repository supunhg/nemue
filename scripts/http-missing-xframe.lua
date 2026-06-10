-- Missing X-Frame-Options Detection
-- Checks for missing clickjacking protection

local http = require("http")
local stdnse = require("stdnse")

description = [[
Checks for missing X-Frame-Options header which protects against
clickjacking attacks by controlling iframe embedding.
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

    table.insert(output, "X-Frame-Options Check")
    table.insert(output, "")

    local xfo = response.header and response.header["x-frame-options"]
    local csp = response.header and response.header["content-security-policy"]
    local frame_ancestors = csp and csp:find("frame%-ancestors")

    if xfo then
        table.insert(output, "[+] X-Frame-Options: " .. xfo)
        if xfo:upper() == "ALLOW-FROM" then
            table.insert(output, "[!] ALLOW-FROM is deprecated, use CSP frame-ancestors instead")
        end
    elseif frame_ancestors then
        table.insert(output, "[+] CSP frame-ancestors directive present (preferred)")
    else
        table.insert(output, "[-] X-Frame-Options: MISSING")
        table.insert(output, "[-] CSP frame-ancestors: MISSING")
        table.insert(output, "")
        table.insert(output, "[!] MEDIUM: No clickjacking protection")
        table.insert(output, "[!] Add header: X-Frame-Options: DENY or SAMEORIGIN")
    end

    return stdnse.format_output(true, output)
end
