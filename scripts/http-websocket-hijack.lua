-- WebSocket Hijacking Detection
-- Tests for cross-site WebSocket hijacking vulnerabilities

local http = require("http")
local stdnse = require("stdnse")

description = [[
Tests for cross-site WebSocket hijacking (CSWSH) and WebSocket
security issues including missing origin validation.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "exploit"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080)
end

action = function(host, port)
    local output = {}
    local findings = {}

    local ws_paths = {"/ws", "/websocket", "/socket", "/socket.io/",
                      "/ws/chat", "/ws/events", "/api/ws", "/signalr"}

    for _, path in ipairs(ws_paths) do
        local upgrade_headers = {
            ["Upgrade"] = "websocket",
            ["Connection"] = "Upgrade",
            ["Sec-WebSocket-Key"] = "dGhlIHNhbXBsZSBub25jZQ==",
            ["Sec-WebSocket-Version"] = "13",
            ["Origin"] = "http://evil.com"
        }

        local r = http.get(host.ip, port, path, upgrade_headers)
        if r then
            if r.status == 101 then
                table.insert(findings, {
                    path = path,
                    type = "WebSocket upgrade with arbitrary origin",
                    severity = "HIGH"
                })
            elseif r.status == 200 then
                local r2 = http.get(host.ip, port, path)
                if r2 and r2.body and (r2.body:find("websocket") or r2.body:find("WebSocket")) then
                    table.insert(findings, {
                        path = path,
                        type = "WebSocket endpoint detected",
                        severity = "INFO"
                    })
                end
            end
        end
    end

    local check = http.get(host.ip, port, "/socket.io/?EIO=4&transport=polling")
    if check and check.status == 200 then
        table.insert(findings, {
            path = "/socket.io/",
            type = "Socket.IO detected (check for CORS misconfig)",
            severity = "MEDIUM"
        })
    end

    if #findings > 0 then
        table.insert(output, "WebSocket Security Issues Found:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] Path: " .. f.path)
            table.insert(output, "[!]   Issue: " .. f.type)
            table.insert(output, "[!]   Severity: " .. f.severity)
            table.insert(output, "")
        end
        table.insert(output, "[!] Missing origin validation allows cross-site hijacking")
        return stdnse.format_output(true, output)
    end

    return nil
end
