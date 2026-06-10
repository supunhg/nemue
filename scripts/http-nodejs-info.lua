-- Node.js Application Information Disclosure
-- Detects Node.js/Express and related framework details

local http = require("http")
local stdnse = require("stdnse")

description = [[
Detects Node.js application information disclosure including
Express, framework versions, and debug/development endpoints.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "web"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 3000 or port.number == 8080)
end

action = function(host, port)
    local output = {}
    local response = http.get(host.ip, port, "/")

    if not response then
        return "No HTTP response received"
    end

    table.insert(output, "Node.js Application Information Disclosure")
    table.insert(output, "")

    local powered = response.header and response.header["x-powered-by"]
    local is_node = false

    if powered and powered:lower():find("express") then
        is_node = true
        table.insert(output, "[!] X-Powered-By: " .. powered)
    end

    local server = response.header and response.header["server"]
    if server and server:lower():find("node") then
        is_node = true
        table.insert(output, "[!] Server: " .. server)
    end

    local paths = {
        {"/env", "Environment variables exposed"},
        {"/debug", "Debug endpoint"},
        {"/status", "Status endpoint"},
        {"/health", "Health check endpoint"},
        {"/info", "Info endpoint"},
        {"/api-docs", "API documentation"},
    }

    for _, check in ipairs(paths) do
        local r = http.get(host.ip, port, check[1])
        if r and r.status == 200 and r.body then
            if r.body:find("express") or r.body:find("node") then
                is_node = true
                table.insert(output, "[!] " .. check[2] .. " at " .. check[1])
            end
        end
    end

    if response.body and response.body:find("__NEXT_DATA__") then
        is_node = true
        table.insert(output, "[!] Next.js application detected")
    end

    if not is_node then
        table.insert(output, "[-] Node.js not detected")
    end

    table.insert(output, "")
    table.insert(output, "[!] Node.js disclosure aids framework-specific attack targeting")

    return stdnse.format_output(true, output)
end
