-- Redis Pub/Sub Test
-- Tests Redis server for pub/sub capabilities and open access

local nmap = require("nmap")
local stdnse = require("stdnse")

description = [[
Connects to a Redis server and tests pub/sub functionality.
Checks if the server requires authentication and attempts
to subscribe to a test channel to verify pub/sub is enabled.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 6379 or port.service == "redis")
end

local function redis_command(socket, cmd)
    local parts = {}
    for word in cmd:gmatch("%S+") do
        table.insert(parts, word)
    end

    local msg = "*" .. #parts .. "\r\n"
    for _, part in ipairs(parts) do
        msg = msg .. "$" .. #part .. "\r\n" .. part .. "\r\n"
    end

    socket:send(msg)

    local response = ""
    local status, line = socket:receive_lines(1)
    if not status then return nil end
    response = line

    if line:sub(1, 1) == "$" then
        local len = tonumber(line:sub(2))
        if len and len > 0 then
            status, line = socket:receive_lines(1)
            if status then
                response = response .. "\r\n" .. line
            end
        end
    elseif line:sub(1, 1) == "*" then
        local count = tonumber(line:sub(2))
        if count and count > 0 then
            for i = 1, count do
                status, line = socket:receive_lines(1)
                if status then
                    response = response .. "\r\n" .. line
                    if line:sub(1, 1) == "$" then
                        local len = tonumber(line:sub(2))
                        if len and len > 0 then
                            status, line = socket:receive_lines(1)
                            if status then
                                response = response .. "\r\n" .. line
                            end
                        end
                    end
                end
            end
        end
    end

    return response
end

action = function(host, port)
    local results = {}

    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    local status, err = socket:connect(host, port)

    if not status then
        return stdnse.format_output(false, "Could not connect: " .. err)
    end

    local ping_resp = redis_command(socket, "PING")
    if ping_resp and ping_resp:match("PONG") then
        table.insert(results, "Redis server responded to PING (no auth required)")
    elseif ping_resp and ping_resp:match("NOAUTH") then
        table.insert(results, "Redis server requires authentication")
        socket:close()
        return stdnse.format_output(true, results)
    else
        table.insert(results, "Unexpected response: " .. (ping_resp or "nil"))
        socket:close()
        return stdnse.format_output(true, results)
    end

    local info_resp = redis_command(socket, "INFO server")
    if info_resp then
        local version = info_resp:match("redis_version:([%d%.]+)")
        if version then
            table.insert(results, "Redis version: " .. version)
        end
        local mode = info_resp:match("redis_mode:(%S+)")
        if mode then
            table.insert(results, "Mode: " .. mode)
        end
    end

    redis_command(socket, "SUBSCRIBE nemue_test_channel")
    local sub_resp
    status, sub_resp = socket:receive_lines(1)
    if status and sub_resp then
        if sub_resp:match("%*3") then
            table.insert(results, "Pub/Sub is enabled")
            table.insert(results, "WARNING: Open Redis allows pub/sub without authentication")

            redis_command(socket, "UNSUBSCRIBE nemue_test_channel")
            socket:close()

            local pub_socket = nmap.new_socket()
            pub_socket:set_timeout(3000)
            status, err = pub_socket:connect(host, port)
            if status then
                redis_command(pub_socket, "PUBLISH nemue_test_channel nemue_probe")
                table.insert(results, "Test message published to nemue_test_channel")
                pub_socket:close()
            end
        end
    end

    local role_resp = redis_command(socket, "ROLE")
    if role_resp then
        local role = role_resp:match("^(%S+)")
        if role then
            table.insert(results, "Role: " .. role)
        end
    end

    if socket then socket:close() end

    if #results == 0 then
        return nil
    end

    return stdnse.format_output(true, results)
end
