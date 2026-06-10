-- VNC No Authentication Test
-- Tests if VNC server allows connections without authentication

local nmap = require("nmap")
local stdnse = require("stdnse")
local string = require("string")
local table = require("table")

description = [[
Tests if a VNC server allows connections without requiring
authentication, which would allow unauthorized remote access.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "auth", "vuln"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "vnc" or port.number == 5900 or
            port.number == 5901)
end

action = function(host, port)
    local output = {}
    local socket = nmap.new_socket()
    socket:set_timeout(10000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return stdnse.format_output(true, "Connection failed: " .. (err or "unknown"))
    end

    local status, banner = socket:receive_lines(1)
    if not status then
        socket:close()
        return stdnse.format_output(true, "Failed to receive VNC banner")
    end

    table.insert(output, "VNC Banner: " .. banner)

    local version = banner:match("RFB (%d+%.%d+)")
    if version then
        table.insert(output, "Protocol Version: " .. version)
    end

    socket:send("RFB 003.008\n")
    local status, security = socket:receive_lines(1)
    if not status then
        socket:close()
        return stdnse.format_output(true, "Failed to negotiate security type")
    end

    table.insert(output, "Security Response: " .. security)

    if security:find("\x01") then
        table.insert(output, "\n[!] NO AUTHENTICATION REQUIRED")
        table.insert(output, "Severity: CRITICAL")
        table.insert(output, "Anyone can connect to this VNC server")
    elseif security:find("\x02") then
        table.insert(output, "Authentication: VNC password required")
    elseif security:find("\x16") then
        table.insert(output, "Authentication: TLSVnc")
    elseif security:find("\x1e") then
        table.insert(output, "Authentication: TLSPlain")
    end

    socket:close()
    return stdnse.format_output(true, output)
end
