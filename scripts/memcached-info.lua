local nmap = require("nmap")
local stdnse = require("stdnse")

description = [[
Connects to Memcached server and extracts version, stats, and
configuration information using the stats command.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 11211 or port.service == "memcache")
end

action = function(host, port)
    local output = {}
    local issues = {}

    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host, port)
    if not status then
        return stdnse.format_output(false, "Could not connect: " .. err)
    end

    socket:send("version\r\n")
    local response
    status, response = socket:receive_lines(1)

    if status and response then
        local version = response:match("VERSION ([^\r\n]+)")
        if version then
            table.insert(output, "Memcached Version: " .. version)
        end
    end

    socket:send("stats\r\n")
    local stats = ""
    while true do
        status, response = socket:receive_lines(1)
        if not status or response:find("^END") then
            break
        end
        stats = stats .. response .. "\n"
    end

    socket:close()

    if stats and #stats > 0 then
        table.insert(output, "\nServer Statistics:")

        local curr_conns = stats:match("curr_connections (%d+)")
        if curr_conns then
            table.insert(output, "  Current Connections: " .. curr_conns)
        end

        local total_items = stats:match("total_items (%d+)")
        if total_items then
            table.insert(output, "  Total Items: " .. total_items)
        end

        local bytes = stats:match("bytes (%d+)")
        if bytes then
            table.insert(output, "  Memory Used: " .. bytes .. " bytes")
        end

        local cmd_get = stats:match("cmd_get (%d+)")
        local get_hits = stats:match("get_hits (%d+)")
        if cmd_get and get_hits and tonumber(cmd_get) > 0 then
            local hit_rate = math.floor(tonumber(get_hits) / tonumber(cmd_get) * 100)
            table.insert(output, "  Cache Hit Rate: " .. hit_rate .. "%")
        end

        local evictions = stats:match("evictions (%d+)")
        if evictions and tonumber(evictions) > 0 then
            table.insert(output, "  Evictions: " .. evictions)
        end
    end

    table.insert(output, "\nSecurity Check:")
    table.insert(output, "  Memcached listens on all interfaces by default")
    table.insert(output, "  Ensure firewall restricts access to trusted hosts only")

    return stdnse.format_output(true, output)
end
