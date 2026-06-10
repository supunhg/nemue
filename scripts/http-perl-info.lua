-- Perl Application Information Disclosure
-- Detects Perl/CGI application details

local http = require("http")
local stdnse = require("stdnse")

description = [[
Detects Perl web application information disclosure including
framework versions and configuration through headers and error pages.
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

    table.insert(output, "Perl Application Information Disclosure")
    table.insert(output, "")

    local is_perl = false

    local server = response.header and response.header["server"]
    if server and (server:lower():find("perl") or server:lower():find("mod_perl")) then
        is_perl = true
        table.insert(output, "[!] Server: " .. server)
    end

    local powered = response.header and response.header["x-powered-by"]
    if powered and powered:lower():find("perl") then
        is_perl = true
        table.insert(output, "[!] X-Powered-By: " .. powered)
    end

    local paths = {
        {"/cgi-bin/", "CGI bin with Perl scripts"},
        {"/perl/", "Perl scripts directory"},
    }

    for _, check in ipairs(paths) do
        local r = http.get(host.ip, port, check[1])
        if r and r.status and r.status ~= 404 then
            is_perl = true
            table.insert(output, "[!] " .. check[2] .. " at " .. check[1])
        end
    end

    local err_response = http.get(host.ip, port, "/nonexistent_page_12345.pl")
    if err_response and err_response.body then
        if err_response.body:find("perl") or err_response.body:find("Perl") then
            is_perl = true
            table.insert(output, "[!] Perl error page detected")
        end
        if err_response.body:find("Software error") or err_response.body:find("at %S+ line %d+") then
            table.insert(output, "[!] Perl script error details exposed")
        end
    end

    if not is_perl then
        table.insert(output, "[-] Perl not detected")
    end

    table.insert(output, "")
    table.insert(output, "[!] Perl disclosure aids code injection attack targeting")

    return stdnse.format_output(true, output)
end
