-- Redis Command Execution Test
-- Tests Redis server for command execution capabilities

local nmap = require("nmap")
local stdnse = require("stdnse")
local string = require("string")
local table = require("table")

description = [[
Tests if a Redis server allows unauthenticated command execution
and retrieves server information.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default", "vuln"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "redis" or port.number == 6379)
end

local function redis_command(socket, cmd)
    local parts = {}
    for word in cmd:gmatch("%S+") do
        table.insert(parts, word)
    end

    local payload = "*" .. #parts .. "\r\n"
    for _, part in ipairs(parts) do
        payload = payload .. "$" .. #part .. "\r\n" .. part .. "\r\n"
    end

    socket:send(payload)
    local status, response = socket:receive()
    return status, response
end

action = function(host, port)
    local output = {}
    local socket = nmap.new_socket()
    socket:set_timeout(10000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return stdnse.format_output(true, "Connection failed: " .. (err or "unknown"))
    end

    local status, response = redis_command(socket, "PING")
    if status and response then
        table.insert(output, "PING Response: " .. response)
    end

    if response and response:find("+PONG") then
        table.insert(output, "\n[!] REDIS ACCEPTS COMMANDS WITHOUT AUTHENTICATION")

        local status, info = redis_command(socket, "INFO server")
        if status and info then
            table.insert(output, "\nServer Information:")
            for line in info:gmatch("[^\r\n]+") do
                if line:find("redis_version") or
                   line:find("os:") or
                   line:find("tcp_port") or
                   line:find("config_file") then
                    table.insert(output, "  " .. line)
                end
            end
        end

        local status, config = redis_command(socket, "CONFIG GET bind")
        if status and config then
            table.insert(output, "\nBind Configuration: " .. config)
        end

        local status, dbsize = redis_command(socket, "DBSIZE")
        if status and dbsize then
            table.insert(output, "Database Size: " .. dbsize)
        end

        table.insert(output, "\n[!] Severity: HIGH")
        table.insert(output, "[!] Unauthenticated Redis access can lead to RCE")
    elseif response and response:find("NOAUTH") then
        table.insert(output, "Redis requires authentication")
        table.insert(output, "Response: " .. response)
    end

    socket:close()
    return stdnse.format_output(true, output)
end
