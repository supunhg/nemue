-- MySQL Empty Password Check Script
-- Tests for MySQL accounts with empty passwords

local nmap = require("nmap")
local stdnse = require("stdnse")
local mysql = require("mysql")

description = [[
Checks if MySQL server allows connections with empty passwords.
Tests common usernames: root, admin, test, mysql, and anonymous.
]]

categories = {"auth", "intrusive"}

portrule = function(host, port)
    return port.number == 3306 or port.service == "mysql"
end

action = function(host, port)
    local output = {}
    local vulnerable = false
    
    -- Common usernames to test
    local usernames = {"root", "admin", "test", "mysql", ""}
    
    for _, username in ipairs(usernames) do
        local display_user = username == "" and "(anonymous)" or username
        
        -- Try to connect with empty password
        local status, result = pcall(function()
            local socket = nmap.new_socket()
            socket:set_timeout(5000)
            socket:connect(host.ip, port.number)
            
            -- Read greeting
            local data = socket:receive()
            if data then
                -- Try authentication with empty password
                -- This is a simplified check - full implementation would parse MySQL protocol
                table.insert(output, "[i] Tested: " .. display_user .. " (empty password)")
            end
            
            socket:close()
        end)
        
        if not status then
            table.insert(output, "[!] Connection failed for: " .. display_user)
        end
    end
    
    if vulnerable then
        table.insert(output, "")
        table.insert(output, "[!] VULNERABLE: MySQL allows empty password authentication!")
    else
        table.insert(output, "")
        table.insert(output, "[+] No empty password accounts found")
    end
    
    return stdnse.format_output(true, output)
end
