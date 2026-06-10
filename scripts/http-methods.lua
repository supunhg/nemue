-- HTTP Methods Enumeration
-- Enumerates allowed HTTP methods on web servers

local http = require("http")
local stdnse = require("stdnse")
local string = require("string")

description = [[
Sends OPTIONS requests to enumerate allowed HTTP methods
and identify potentially dangerous methods.
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
    local allowed_methods = {}

    table.insert(output, "HTTP Methods Enumeration")
    table.insert(output, "Target: " .. host.ip .. ":" .. port.number)
    table.insert(output, "")

    local methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}

    local options_response = http.generic_request(host.ip, port, "OPTIONS / HTTP/1.1\r\nHost: " .. host.ip .. "\r\n\r\n")

    if options_response and options_response.header then
        local allow = options_response.header["allow"]
        if allow then
            table.insert(output, "Allowed Methods (from Allow header):")
            for method in allow:gmatch("[A-Z]+") do
                table.insert(allowed_methods, method)
                table.insert(output, "  * " .. method)
            end
        end
    end

    if #allowed_methods == 0 then
        table.insert(output, "Testing individual methods...")
        table.insert(output, "")

        for _, method in ipairs(methods) do
            local response = http.generic_request(host.ip, port, method .. " / HTTP/1.1\r\nHost: " .. host.ip .. "\r\n\r\n")

            if response and response.status ~= 405 and response.status ~= 501 then
                table.insert(allowed_methods, method)
                table.insert(output, "[+] " .. method .. " allowed (Status: " .. response.status .. ")")
            end
        end
    end

    table.insert(output, "")

    local dangerous = {"PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND", "MKCOL", "COPY", "MOVE"}

    local found_dangerous = false
    for _, method in ipairs(allowed_methods) do
        for _, d in ipairs(dangerous) do
            if method == d then
                if not found_dangerous then
                    table.insert(output, "[!] Potentially dangerous methods found:")
                    found_dangerous = true
                end
                table.insert(output, "  * " .. method)
            end
        end
    end

    if not found_dangerous then
        table.insert(output, "[+] No dangerous HTTP methods detected")
    end

    table.insert(output, "")
    table.insert(output, "Total allowed methods: " .. #allowed_methods)

    return stdnse.format_output(true, output)
end
