-- IIS Server Information Disclosure
-- Extracts IIS version and configuration details

local http = require("http")
local stdnse = require("stdnse")

description = [[
Detects Microsoft IIS server information disclosure including version,
ASP.NET details, and configuration through headers and error pages.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "web"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080 or port.number == 8443)
end

action = function(host, port)
    local output = {}
    local response = http.get(host.ip, port, "/")

    if not response then
        return "No HTTP response received"
    end

    table.insert(output, "IIS Server Information Disclosure")
    table.insert(output, "")

    local server = response.header and response.header["server"]
    if not server or not server:upper():find("IIS") then
        table.insert(output, "[-] IIS not detected")
        return stdnse.format_output(true, output)
    end

    table.insert(output, "[!] Server: " .. server)

    local version = server:match("IIS/([%d%.]+)")
    if version then
        table.insert(output, "[!] IIS Version: " .. version)
    end

    local asp_version = response.header and response.header["x-aspnet-version"]
    if asp_version then
        table.insert(output, "[!] ASP.NET Version: " .. asp_version)
    end

    local powered = response.header and response.header["x-powered-by"]
    if powered then
        table.insert(output, "[!] X-Powered-By: " .. powered)
    end

    local err_response = http.get(host.ip, port, "/nonexistent_page_12345")
    if err_response and err_response.body then
        if err_response.body:find("IIS/") then
            table.insert(output, "[!] Version leaked in error page")
        end
        if err_response.body:find("Microsoft%-IIS") then
            table.insert(output, "[!] IIS branding in error page")
        end
    end

    table.insert(output, "")
    table.insert(output, "[!] IIS version disclosure aids CVE targeting")

    return stdnse.format_output(true, output)
end
