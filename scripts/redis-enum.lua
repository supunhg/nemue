-- Redis Enumeration
-- Enumerates Redis server information and configuration

local nmap = require("nmap")
local stdnse = require("stdnse")
local string = require("string")

description = [[
Connects to Redis server to enumerate version, configuration,
databases, and potential security issues.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 6379 or port.service == "redis")
end

action = function(host, port)
    local output = {}

    table.insert(output, "Redis Server Enumeration")
    table.insert(output, "Target: " .. host.ip .. ":6379")
    table.insert(output, "")

    local sock = nmap.new_socket()
    sock:set_timeout(5000)

    local status, err = sock:connect(host.ip, 6379)

    if not status then
        table.insert(output, "[!] Could not connect to Redis port")
        sock:close()
        return stdnse.format_output(true, output)
    end

    local function send_command(cmd)
        local parts = {}
        for word in cmd:gmatch("%S+") do
            table.insert(parts, word)
        end

        local msg = "*" .. #parts .. "\r\n"
        for _, part in ipairs(parts) do
            msg = msg .. "$" .. #part .. "\r\n" .. part .. "\r\n"
        end

        sock:send(msg)
        local status, response = sock:receive()
        return status, response
    end

    local status, response = send_command("INFO server")

    if status and response then
        if response:find("redis_version") then
            table.insert(output, "[+] Redis service confirmed (no auth required)")

            local version = response:match("redis_version:([^\r\n]+)")
            if version then
                table.insert(output, "    Redis Version: " .. version)
            end

            local os = response:match("os:([^\r\n]+)")
            if os then
                table.insert(output, "    Operating System: " .. os)
            end

            local mode = response:match("redis_mode:([^\r\n]+)")
            if mode then
                table.insert(output, "    Redis Mode: " .. mode)
            end

            table.insert(output, "")
            table.insert(output, "[!] CRITICAL: Redis accessible without authentication")
            table.insert(output, "[!] Attackers can:")
            table.insert(output, "    - Read all data in databases")
            table.insert(output, "    - Write SSH keys to authorized_keys")
            table.insert(output, "    - Write crontab for reverse shell")
            table.insert(output, "    - Use SLAVEOF for replication attacks")
        elseif response:find("NOAUTH") then
            table.insert(output, "[+] Redis requires authentication")
            table.insert(output, "[!] Recommendation: Use strong password")
        elseif response:find("ERR") then
            table.insert(output, "[!] Redis error: " .. response)
        end
    else
        table.insert(output, "[!] No Redis response received")
    end

    sock:close()
    return stdnse.format_output(true, output)
end
