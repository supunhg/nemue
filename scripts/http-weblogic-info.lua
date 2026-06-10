-- Oracle WebLogic Information Disclosure
-- Extracts WebLogic version and configuration details

local http = require("http")
local stdnse = require("stdnse")

description = [[
Detects Oracle WebLogic server information disclosure including version,
console paths, and configuration through headers and error pages.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "web"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 7001 or port.number == 7002)
end

action = function(host, port)
    local output = {}
    local response = http.get(host.ip, port, "/")

    if not response then
        return "No HTTP response received"
    end

    table.insert(output, "Oracle WebLogic Information Disclosure")
    table.insert(output, "")

    local server = response.header and response.header["server"]
    local is_weblogic = false

    if server and server:lower():find("weblogic") then
        is_weblogic = true
        table.insert(output, "[!] Server: " .. server)
    end

    local paths = {
        {"/console", "WebLogic Server Administration Console"},
        {"/wls-wsat/CoordinatorPortType", "WS-AT endpoint"},
        {"/bea_wls_internal/", "Internal documentation"},
        {"/uddiexplorer/", "UDDI Explorer"},
    }

    for _, check in ipairs(paths) do
        local r = http.get(host.ip, port, check[1])
        if r and r.status and r.status ~= 404 then
            is_weblogic = true
            table.insert(output, "[!] " .. check[2] .. " found at " .. check[1] .. " (HTTP " .. r.status .. ")")
        end
    end

    if response.body and response.body:find("WebLogic") then
        is_weblogic = true
        table.insert(output, "[!] WebLogic branding detected in page body")
    end

    if not is_weblogic then
        table.insert(output, "[-] WebLogic not detected")
    end

    table.insert(output, "")
    table.insert(output, "[!] WebLogic disclosure aids CVE targeting (e.g., CVE-2017-10271)")

    return stdnse.format_output(true, output)
end
