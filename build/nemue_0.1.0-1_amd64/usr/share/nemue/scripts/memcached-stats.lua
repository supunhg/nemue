-- Memcached Statistics
-- Retrieves Memcached server statistics
-- @output
-- 11211/tcp open  memcache
-- | memcached-stats:
-- |   Version: 1.6.9
-- |   Uptime: 86400 seconds (1 day)
-- |   Current Items: 1234
-- |   Total Items: 5678
-- |_  Current Connections: 5

description = [[
Connects to Memcached servers and retrieves statistics including
version, uptime, item counts, and connection information.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe", "default"}

portrule = function(host, port)
    return port.number == 11211 or port.service == "memcache"
end

action = function(host, port)
    local socket = nse.new_socket()
    socket:set_timeout(5000)
    
    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end
    
    -- Send stats command
    socket:send("stats\r\n")
    
    local status, response = socket:receive()
    socket:close()
    
    if not status or not response then
        return nil
    end
    
    local results = {}
    
    -- Parse stats response
    for line in response:gmatch("[^\r\n]+") do
        local stat, value = line:match("STAT ([%w_]+) (.+)")
        if stat and value then
            if stat == "version" then
                table.insert(results, "Version: " .. value)
            elseif stat == "uptime" then
                local uptime_sec = tonumber(value) or 0
                local days = math.floor(uptime_sec / 86400)
                local hours = math.floor((uptime_sec % 86400) / 3600)
                if days > 0 then
                    table.insert(results, string.format("Uptime: %d seconds (%d days, %d hours)", 
                                                       uptime_sec, days, hours))
                else
                    table.insert(results, "Uptime: " .. uptime_sec .. " seconds")
                end
            elseif stat == "curr_items" then
                table.insert(results, "Current Items: " .. value)
            elseif stat == "total_items" then
                table.insert(results, "Total Items: " .. value)
            elseif stat == "curr_connections" then
                table.insert(results, "Current Connections: " .. value)
            elseif stat == "bytes" then
                local bytes = tonumber(value) or 0
                local mb = bytes / 1048576
                if mb > 1 then
                    table.insert(results, string.format("Memory Used: %.2f MB", mb))
                end
            end
        end
    end
    
    if #results > 0 then
        return table.concat(results, "\n")
    end
    
    return "Memcached server detected (no stats available)"
end
