-- ASP.NET Application Information Disclosure
-- Detects ASP.NET version and configuration details

local http = require("http")
local stdnse = require("stdnse")

description = [[
Detects ASP.NET information disclosure including version, framework
details, and debug information through headers and error pages.
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

    table.insert(output, "ASP.NET Application Information Disclosure")
    table.insert(output, "")

    local is_aspnet = false

    local asp_version = response.header and response.header["x-aspnet-version"]
    if asp_version then
        is_aspnet = true
        table.insert(output, "[!] X-AspNet-Version: " .. asp_version)
    end

    local asp_mvc = response.header and response.header["x-aspnetmvc-version"]
    if asp_mvc then
        is_aspnet = true
        table.insert(output, "[!] X-AspNetMVC-Version: " .. asp_mvc)
    end

    local powered = response.header and response.header["x-powered-by"]
    if powered and powered:lower():find("asp%.net") then
        is_aspnet = true
        table.insert(output, "[!] X-Powered-By: " .. powered)
    end

    local server = response.header and response.header["server"]
    if server and server:lower():find("microsoft%-iis") then
        is_aspnet = true
        table.insert(output, "[!] Server: " .. server)
    end

    local err_response = http.get(host.ip, port, "/nonexistent_page_12345.aspx")
    if err_response and err_response.body then
        if err_response.body:find("ASP%.NET") then
            is_aspnet = true
            table.insert(output, "[!] ASP.NET error page detected")
        end
        if err_response.body:find("Version Information:") then
            table.insert(output, "[!] Version information leaked in error page")
        end
        if err_response.body:find("Stack Trace:") then
            table.insert(output, "[!] Stack trace exposed in error page")
        end
    end

    if not is_aspnet then
        table.insert(output, "[-] ASP.NET not detected")
    end

    table.insert(output, "")
    table.insert(output, "[!] ASP.NET disclosure aids CVE targeting")

    return stdnse.format_output(true, output)
end
