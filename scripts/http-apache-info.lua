-- Apache Server Information Disclosure
-- Extracts Apache version, modules, and configuration details

local http = require("http")
local stdnse = require("stdnse")
local string = require("string")

description = [[
Detects Apache HTTP server information disclosure including version,
modules, OS details, and configuration through headers and error pages.
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

    table.insert(output, "Apache Server Information Disclosure")
    table.insert(output, "")

    local server = response.header and response.header["server"]
    if not server or not server:lower():find("apache") then
        table.insert(output, "[-] Apache not detected")
        return stdnse.format_output(true, output)
    end

    table.insert(output, "[!] Server: " .. server)

    local version = server:match("Apache/([%d%.]+)")
    if version then
        table.insert(output, "[!] Apache Version: " .. version)
    end

    local os = server:match("%(([^)]+)%)")
    if os then
        table.insert(output, "[!] OS Details: " .. os)
    end

    local modules = server:match("%(([^)]*)%)")
    if modules then
        for mod in modules:gmatch("(%S+)%/?[%d%.]*") do
            table.insert(output, "[!] Module: " .. mod)
        end
    end

    local powered = response.header and response.header["x-powered-by"]
    if powered then
        table.insert(output, "[!] X-Powered-By: " .. powered)
    end

    local err_response = http.get(host.ip, port, "/nonexistent_page_12345")
    if err_response and err_response.body then
        if err_response.body:find("Apache/") then
            table.insert(output, "[!] Version leaked in error page")
        end
        if err_response.body:find("Server at") then
            table.insert(output, "[!] Server name leaked in error page")
        end
    end

    table.insert(output, "")
    table.insert(output, "[!] Apache version disclosure aids CVE targeting")

    return stdnse.format_output(true, output)
end
