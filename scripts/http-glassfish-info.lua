-- Eclipse GlassFish Information Disclosure
-- Extracts GlassFish version and admin console details

local http = require("http")
local stdnse = require("stdnse")

description = [[
Detects Eclipse GlassFish/Payara server information disclosure
including version, admin console, and REST management endpoints.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "web"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 4848 or port.number == 8080)
end

action = function(host, port)
    local output = {}
    local response = http.get(host.ip, port, "/")

    if not response then
        return "No HTTP response received"
    end

    table.insert(output, "GlassFish/Payara Information Disclosure")
    table.insert(output, "")

    local server = response.header and response.header["server"]
    local is_glassfish = false

    if server and (server:lower():find("glassfish") or server:lower():find("payara")) then
        is_glassfish = true
        table.insert(output, "[!] Server: " .. server)
    end

    local paths = {
        {"/common/index.jsf", "Admin Console"},
        {"/management/domain", "REST Management API"},
        {"/__admin", "Admin endpoint"},
    }

    for _, check in ipairs(paths) do
        local r = http.get(host.ip, port, check[1])
        if r and r.status and r.status ~= 404 then
            is_glassfish = true
            table.insert(output, "[!] " .. check[2] .. " found at " .. check[1] .. " (HTTP " .. r.status .. ")")
        end
    end

    if response.body and (response.body:find("GlassFish") or response.body:find("Payara")) then
        is_glassfish = true
        table.insert(output, "[!] GlassFish/Payara branding in page body")
    end

    if not is_glassfish then
        table.insert(output, "[-] GlassFish/Payara not detected")
    end

    table.insert(output, "")
    table.insert(output, "[!] GlassFish disclosure aids admin console attack targeting")

    return stdnse.format_output(true, output)
end
