-- SMTP VRFY User Enumeration
-- Tests SMTP VRFY command for user enumeration

local nmap = require("nmap")
local stdnse = require("stdnse")
local string = require("string")
local table = require("table")

description = [[
Tests if an SMTP server supports the VRFY command which can
be used to enumerate valid usernames.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "auth"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "smtp" or port.number == 25 or
            port.number == 587)
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
    if status then
        table.insert(output, "SMTP Banner: " .. banner)
    end

    socket:send("EHLO nemue-test\r\n")
    local status, ehlo = socket:receive_lines(1)
    if status then
        table.insert(output, "EHLO Response: " .. ehlo)
    end

    local test_users = {"root", "admin", "postmaster", "webmaster", "test", "user"}
    local vrfy_supported = false

    for _, user in ipairs(test_users) do
        socket:send("VRFY " .. user .. "\r\n")
        local status, response = socket:receive_lines(1)
        if not status then break end

        table.insert(output, "VRFY " .. user .. ": " .. response)

        if response:match("^250") or response:match("^252") then
            vrfy_supported = true
        end
    end

    if vrfy_supported then
        table.insert(output, "\n[!] VRFY command is ENABLED")
        table.insert(output, "[!] User enumeration is possible")
    else
        table.insert(output, "\nVRFY command appears disabled or restricted")
    end

    socket:send("QUIT\r\n")
    socket:close()

    return stdnse.format_output(true, output)
end
