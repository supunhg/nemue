-- Server Information Disclosure
-- Extracts server software and version information

local http = require("http")
local stdnse = require("stdnse")
local string = require("string")

description = [[
Analyzes HTTP response headers and content to identify
server software, versions, and technology stack.
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

    table.insert(output, "Server Information Disclosure Scan")
    table.insert(output, "")

    if response.header then
        local server = response.header["server"]
        if server then
            table.insert(output, "[!] Server: " .. server)
        end

        local powered = response.header["x-powered-by"]
        if powered then
            table.insert(output, "[!] X-Powered-By: " .. powered)
        end

        local asp = response.header["x-aspnet-version"]
        if asp then
            table.insert(output, "[!] ASP.NET Version: " .. asp)
        end

        local runtime = response.header["x-runtime"]
        if runtime then
            table.insert(output, "[!] X-Runtime: " .. runtime)
        end

        local generator = response.header["x-generator"]
        if generator then
            table.insert(output, "[!] X-Generator: " .. generator)
        end
    end

    local body = response.body or ""

    local generators = {
        {"WordPress", "wp%-content"},
        {"Joomla", "joomla"},
        {"Drupal", "drupal"},
        {"Laravel", "laravel"},
        {"Django", "csrfmiddlewaretoken"},
        {"React", "react"},
        {"Angular", "ng%-"},
        {"Vue.js", "vue"},
        {"Bootstrap", "bootstrap"},
        {"jQuery", "jquery"}
    }

    for _, gen in ipairs(generators) do
        if body:lower():find(gen[2]:lower()) then
            table.insert(output, "[!] Technology: " .. gen[1])
        end
    end

    table.insert(output, "")
    table.insert(output, "[!] Server information disclosure aids attackers in targeting vulnerabilities")

    return stdnse.format_output(true, output)
end
