local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Detects WebSocket endpoints by checking for WebSocket upgrade headers
and common WebSocket paths on the target server.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or port.number == 8080)
end

local ws_paths = {
    "/ws",
    "/websocket",
    "/socket",
    "/socket.io/?EIO=3&transport=polling",
    "/ws/",
    "/api/ws",
    "/chat",
}

action = function(host, port)
    local output = {}
    local endpoints = {}

    for _, path in ipairs(ws_paths) do
        local options = {
            header = {
                ["Upgrade"] = "websocket",
                ["Connection"] = "Upgrade",
                ["Sec-WebSocket-Key"] = "dGhlIHNhbXBsZSBub25jZQ==",
                ["Sec-WebSocket-Version"] = "13",
            },
        }

        local response = http.generic_request(host, port, "GET", path, options)

        if response then
            local upgrade = response.header["upgrade"]
            if upgrade and upgrade:lower() == "websocket" then
                table.insert(endpoints, path .. " (Status: " .. response.status .. ")")
            end

            if response.status == 101 then
                table.insert(endpoints, path .. " (WebSocket upgrade accepted)")
            end
        end
    end

    if #endpoints > 0 then
        table.insert(output, "WebSocket Endpoints Found:")
        for _, ep in ipairs(endpoints) do
            table.insert(output, "  " .. ep)
        end
    else
        table.insert(output, "No WebSocket endpoints detected on common paths")
    end

    return stdnse.format_output(true, output)
end
