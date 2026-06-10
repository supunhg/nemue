-- Redis Unprotected Access Check Script
-- Checks if Redis allows unauthenticated access

local nmap = require("nmap")
local stdnse = require("stdnse")

description = [[
Checks if Redis server allows unauthenticated access by attempting
to run INFO command without authentication.
]]

categories = {"auth", "default", "safe"}

portrule = function(host, port)
    return port.number == 6379 or port.service == "redis"
end

action = function(host, port)
    local output = {}
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    
    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end
    
    -- Send INFO command
    socket:send("*1\r\n$4\r\nINFO\r\n")
    
    local response = socket:receive()
    socket:close()
    
    if not response then
        return nil
    end
    
    -- Check if we got a valid response (not an auth error)
    if response:match("^%%-ERR.*operation not permitted") or 
       response:match("^%%-NOAUTH") then
        table.insert(output, "[+] Redis requires authentication")
        table.insert(output, "    (Access is properly protected)")
    elseif response:match("^%%$") or response:match("^redis_version") then
        table.insert(output, "[!] VULNERABLE: Redis allows unauthenticated access!")
        table.insert(output, "")
        
        -- Extract version info
        local version = response:match("redis_version:([%d%.]+)")
        if version then
            table.insert(output, "    Version: " .. version)
        end
        
        local mode = response:match("redis_mode:(%w+)")
        if mode then
            table.insert(output, "    Mode: " .. mode)
        end
        
        local os = response:match("os:(.+)")
        if os then
            table.insert(output, "    OS: " .. os)
        end
        
        table.insert(output, "")
        table.insert(output, "    Recommendation: Set a password in redis.conf")
        table.insert(output, "    Command: CONFIG SET requirepass <strong_password>")
    end
    
    return stdnse.format_output(true, output)
end
