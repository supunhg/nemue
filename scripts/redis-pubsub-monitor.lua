-- Redis Pub/Sub Monitor
-- Monitors Redis pub/sub channels for active message traffic

local nmap = require("nmap")
local stdnse = require("stdnse")

description = [[
Connects to a Redis server and lists active pub/sub channels.
Monitors for recent message activity and reports channel patterns.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 6379 or port.service == "redis")
end

local function send_redis(socket, args)
    local msg = "*" .. #args .. "\r\n"
    for _, arg in ipairs(args) do
        msg = msg .. "$" .. #arg .. "\r\n" .. arg .. "\r\n"
    end
    return socket:send(msg)
end

local function read_redis(socket)
    local line
    local status, data = socket:receive_lines(1)
    if not status then return nil end

    if data:sub(1, 1) == "*" then
        local count = tonumber(data:sub(2))
        if not count or count <= 0 then return {} end
        local results = {}
        for i = 1, count do
            status, line = socket:receive_lines(1)
            if not status then break end
            if line:sub(1, 1) == "$" then
                local len = tonumber(line:sub(2))
                if len and len > 0 then
                    status, line = socket:receive_lines(1)
                    if status then table.insert(results, line) end
                else
                    table.insert(results, "")
                end
            else
                table.insert(results, line)
            end
        end
        return results
    elseif data:sub(1, 1) == "$" then
        local len = tonumber(data:sub(2))
        if len and len > 0 then
            status, line = socket:receive_lines(1)
            if status then return line end
        end
        return ""
    end

    return data
end

action = function(host, port)
    local results = {}

    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    local status, err = socket:connect(host, port)

    if not status then
        return stdnse.format_output(false, "Could not connect: " .. err)
    end

    send_redis(socket, {"PING"})
    local resp = read_redis(socket)
    if not resp or (type(resp) == "string" and resp:match("NOAUTH")) then
        socket:close()
        table.insert(results, "Server requires authentication")
        return stdnse.format_output(true, results)
    end

    send_redis(socket, {"PUBSUB", "CHANNELS"})
    local channels = read_redis(socket)

    if channels and type(channels) == "table" and #channels > 0 then
        table.insert(results, "Active pub/sub channels found: " .. #channels)
        for i, ch in ipairs(channels) do
            if i > 20 then
                table.insert(results, "  ... and " .. (#channels - 20) .. " more")
                break
            end
            table.insert(results, "  " .. ch)
        end
    else
        table.insert(results, "No active pub/sub channels")
    end

    send_redis(socket, {"PUBSUB", "NUMSUB"})
    local numsub = read_redis(socket)
    if numsub and type(numsub) == "table" then
        local pairs_count = math.floor(#numsub / 2)
        if pairs_count > 0 then
            table.insert(results, "\nChannel subscriber counts:")
            for i = 1, #numsub, 2 do
                if numsub[i + 1] and numsub[i + 1] ~= "0" then
                    table.insert(results, "  " .. numsub[i] .. ": " .. numsub[i + 1] .. " subscribers")
                end
            end
        end
    end

    send_redis(socket, {"PUBSUB", "NUMPAT"})
    local numpat = read_redis(socket)
    if numpat and type(numpat) == "string" and numpat ~= "0" then
        table.insert(results, "\nActive pattern subscriptions: " .. numpat)
    end

    send_redis(socket, {"CONFIG", "GET", "notify-keyspace-events"})
    local notify = read_redis(socket)
    if notify and type(notify) == "table" and #notify > 0 then
        table.insert(results, "\nKeyspace notifications: " .. (notify[1] or "disabled"))
    end

    socket:close()

    return stdnse.format_output(true, results)
end
