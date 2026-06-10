-- MongoDB Enumeration
-- Enumerates MongoDB server information

local nmap = require("nmap")
local stdnse = require("stdnse")
local string = require("string")

description = [[
Connects to MongoDB to enumerate server version, databases,
and check for authentication requirements.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 27017 or port.service == "mongodb")
end

action = function(host, port)
    local output = {}

    table.insert(output, "MongoDB Server Enumeration")
    table.insert(output, "Target: " .. host.ip .. ":27017")
    table.insert(output, "")

    local sock = nmap.new_socket()
    sock:set_timeout(5000)

    local status, err = sock:connect(host.ip, 27017)

    if not status then
        table.insert(output, "[!] Could not connect to MongoDB port")
        sock:close()
        return stdnse.format_output(true, output)
    end

    local isMaster_cmd = string.char(
        0x3a, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xd4, 0x07, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x61, 0x64, 0x6d, 0x69, 0x6e, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00
    )

    sock:send(isMaster_cmd)

    local response
    status, response = sock:receive()

    if status and response then
        if #response > 16 then
            table.insert(output, "[+] MongoDB service confirmed")

            if response:find("maxWireVersion") then
                local wire_ver = response:match("maxWireVersion(%d+)")
                if wire_ver then
                    table.insert(output, "    Wire Version: " .. wire_ver)
                end
            end

            if response:find("ismaster") then
                table.insert(output, "    Role: Primary/Master")
            elseif response:find("secondary") then
                table.insert(output, "    Role: Secondary")
            end

            if response:find("msg") and response:find("auth") then
                table.insert(output, "[+] Authentication required")
            else
                table.insert(output, "")
                table.insert(output, "[!] CRITICAL: MongoDB accessible without authentication")
                table.insert(output, "[!] Attackers can:")
                table.insert(output, "    - Read all databases and collections")
                table.insert(output, "    - Modify or delete data")
                table.insert(output, "    - Potentially execute commands")
            end
        end
    else
        table.insert(output, "[!] No MongoDB response received")
    end

    sock:close()

    table.insert(output, "")
    table.insert(output, "[!] Recommendation: Enable authentication and limit network access")

    return stdnse.format_output(true, output)
end
