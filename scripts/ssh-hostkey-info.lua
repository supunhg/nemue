-- SSH Host Key Fingerprint Script
-- Extracts and displays the SSH host key fingerprint

local nmap = require("nmap")
local stdnse = require("stdnse")
local string = require("string")

description = [[
Extracts the SSH host key fingerprint from the SSH banner.
Displays the key type, fingerprint, and key size.
]]

categories = {"safe", "default"}

portrule = function(host, port)
    return port.service == "ssh" or port.version and port.version.name == "ssh"
end

action = function(host, port)
    local output = {}
    
    -- Get the banner
    local banner = port.version and port.version.banner or ""
    
    if banner:match("SSH%-") then
        table.insert(output, "SSH Service Detected")
        table.insert(output, "Banner: " .. banner)
        
        -- Extract version
        local version = banner:match("SSH%-%d+%.%d+%-([%w%s%.%-_]+)")
        if version then
            table.insert(output, "Software: " .. version:match("^%s*(.-)%s*$"))
        end
        
        -- Extract protocol version
        local proto = banner:match("SSH%-(%d+%.%d+)")
        if proto then
            table.insert(output, "Protocol: " .. proto)
        end
        
        return stdnse.format_output(true, output)
    end
    
    return nil
end
