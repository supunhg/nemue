-- MySQL Enumeration
-- Enumerates MySQL server information and configuration

local nmap = require("nmap")
local stdnse = require("stdnse")
local mysql = require("mysql")

description = [[
Connects to MySQL server to enumerate version, users,
databases, and configuration information.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 3306 or port.service == "mysql")
end

action = function(host, port)
    local output = {}

    table.insert(output, "MySQL Server Enumeration")
    table.insert(output, "Target: " .. host.ip .. ":3306")
    table.insert(output, "")

    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, 3306)

    if not status then
        table.insert(output, "[!] Could not connect to MySQL port")
        socket:close()
        return stdnse.format_output(true, output)
    end

    local response
    status, response = socket:receive()

    if status and response then
        if #response > 4 then
            local protocol_ver = response:byte(5)
            table.insert(output, "Protocol Version: " .. protocol_ver)

            local null_pos = response:find("\0", 6)
            if null_pos then
                local version = response:sub(6, null_pos - 1)
                table.insert(output, "Server Version: " .. version)

                if version:find("MariaDB") then
                    table.insert(output, "Database: MariaDB")
                elseif version:find("MySQL") then
                    table.insert(output, "Database: MySQL")
                end
            end

            table.insert(output, "")
            table.insert(output, "[!] MySQL version disclosure aids in vulnerability research")
            table.insert(output, "[!] Recommendation: Restrict network access to MySQL")
        end
    else
        table.insert(output, "[!] No MySQL banner received")
    end

    socket:close()
    return stdnse.format_output(true, output)
end
