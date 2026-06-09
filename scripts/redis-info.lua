-- Redis Server Information
-- Extracts Redis server details

local nmap = require("nmap")
local stdnse = require("stdnse")

description = [[
Connects to Redis server and extracts version, OS, memory,
and other configuration information using the INFO command.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 6379 or port.service == "redis")
end

action = function(host, port)
    local output = {}

    local socket = nmap.new_socket()
    local status, err = socket:connect(host, port)

    if not status then
        return stdnse.format_output(false, "Could not connect: " .. err)
    end

    socket:send("INFO\r\n")
    local response = ""
    local line

    while true do
        status, line = socket:receive_lines(1)
        if not status or line:find("^$") then
            break
        end
        response = response .. line .. "\n"
    end

    socket:close()

    if response and #response > 0 then
        table.insert(output, "Redis Server Information:")

        local version = response:match("redis_version:([^\r\n]+)")
        if version then
            table.insert(output, "  Version: " .. version)
        end

        local os_info = response:match("os:([^\r\n]+)")
        if os_info then
            table.insert(output, "  OS: " .. os_info)
        end

        local mode = response:match("redis_mode:([^\r\n]+)")
        if mode then
            table.insert(output, "  Mode: " .. mode)
        end

        local mem = response:match("used_memory_human:([^\r\n]+)")
        if mem then
            table.insert(output, "  Memory Used: " .. mem)
        end

        local clients = response:match("connected_clients:([^\r\n]+)")
        if clients then
            table.insert(output, "  Connected Clients: " .. clients)
        end

        local uptime = response:match("uptime_in_seconds:([^\r\n]+)")
        if uptime then
            local days = math.floor(tonumber(uptime) / 86400)
            table.insert(output, "  Uptime: " .. days .. " days")
        end

        table.insert(output, "\nSecurity Check:")
        if response:find("requirepass:") then
            local pass = response:match("requirepass:([^\r\n]+)")
            if pass == "" then
                table.insert(output, "  [!] CRITICAL: No authentication required")
            end
        end
    else
        table.insert(output, "No response received (may require authentication)")
    end

    return stdnse.format_output(true, output)
end
