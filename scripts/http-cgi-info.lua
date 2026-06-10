-- CGI Information Disclosure
-- Detects CGI script details and environment leaks

local http = require("http")
local stdnse = require("stdnse")

description = [[
Detects CGI script information disclosure including environment
variables, script versions, and configuration through common CGI paths.
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

    table.insert(output, "CGI Information Disclosure")
    table.insert(output, "")

    local is_cgi = false

    local paths = {
        {"/cgi-bin/", "CGI bin directory"},
        {"/cgi-sys/", "CGI system directory"},
        {"/cgi-mod/", "CGI module directory"},
        {"/cgi-bin/test-cgi", "test-cgi script"},
        {"/cgi-bin/printenv", "printenv script"},
        {"/cgi-bin/env.cgi", "Environment CGI"},
        {"/scripts/", "IIS Scripts directory"},
        {"/scripts/test.cgi", "Test CGI script"},
    }

    for _, check in ipairs(paths) do
        local r = http.get(host.ip, port, check[1])
        if r and r.status and r.status ~= 404 then
            is_cgi = true
            table.insert(output, "[!] " .. check[2] .. " found at " .. check[1] .. " (HTTP " .. r.status .. ")")
            if r.body and r.body:find("SERVER_") and r.body:find("GATEWAY_INTERFACE") then
                table.insert(output, "[!]   Environment variables exposed")
            end
        end
    end

    local server = response.header and response.header["server"]
    if server and server:lower():find("cgi") then
        is_cgi = true
        table.insert(output, "[!] CGI reference in server header: " .. server)
    end

    if not is_cgi then
        table.insert(output, "[-] CGI scripts not detected")
    end

    table.insert(output, "")
    table.insert(output, "[!] CGI disclosure aids shellshock and environment attack targeting")

    return stdnse.format_output(true, output)
end
