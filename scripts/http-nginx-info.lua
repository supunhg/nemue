-- Nginx Server Information Disclosure
-- Extracts Nginx version and configuration details

local http = require("http")
local stdnse = require("stdnse")

description = [[
Detects Nginx HTTP server information disclosure including version,
modules, and configuration through headers and error pages.
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

    table.insert(output, "Nginx Server Information Disclosure")
    table.insert(output, "")

    local server = response.header and response.header["server"]
    if not server or not server:lower():find("nginx") then
        table.insert(output, "[-] Nginx not detected")
        return stdnse.format_output(true, output)
    end

    table.insert(output, "[!] Server: " .. server)

    local version = server:match("nginx/([%d%.]+)")
    if version then
        table.insert(output, "[!] Nginx Version: " .. version)
    end

    local err_response = http.get(host.ip, port, "/nonexistent_page_12345")
    if err_response and err_response.body then
        if err_response.body:find("nginx/") then
            table.insert(output, "[!] Version leaked in error page")
        end
        if err_response.body:find("<center>nginx") then
            table.insert(output, "[!] Default nginx error page detected")
        end
    end

    local status_response = http.get(host.ip, port, "/nginx_status")
    if status_response and status_response.status == 200 then
        table.insert(output, "[!] Nginx status page accessible at /nginx_status")
    end

    table.insert(output, "")
    table.insert(output, "[!] Nginx version disclosure aids CVE targeting")

    return stdnse.format_output(true, output)
end
