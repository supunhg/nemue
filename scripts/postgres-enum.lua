-- PostgreSQL Enumeration
-- Enumerates PostgreSQL server information

local nmap = require("nmap")
local stdnse = require("stdnse")
local string = require("string")

description = [[
Connects to PostgreSQL server to enumerate version,
databases, and configuration information.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 5432 or port.service == "postgresql")
end

action = function(host, port)
    local output = {}

    table.insert(output, "PostgreSQL Server Enumeration")
    table.insert(output, "Target: " .. host.ip .. ":5432")
    table.insert(output, "")

    local sock = nmap.new_socket()
    sock:set_timeout(5000)

    local status, err = sock:connect(host.ip, 5432)

    if not status then
        table.insert(output, "[!] Could not connect to PostgreSQL port")
        sock:close()
        return stdnse.format_output(true, output)
    end

    local startup_msg = string.char(
        0x00, 0x00, 0x00, 0x08,
        0x04, 0xd2, 0x16, 0x2f
    )

    local ssl_request = string.char(
        0x00, 0x00, 0x00, 0x08,
        0x04, 0xd2, 0x16, 0x2f
    )

    sock:send(ssl_request)

    local response
    status, response = sock:receive()

    if status and response then
        if response:byte(1) == string.byte("N") then
            table.insert(output, "[+] SSL not supported")
        elseif response:byte(1) == string.byte("S") then
            table.insert(output, "[+] SSL supported")
        end
    end

    local auth_msg = string.char(
        0x00, 0x00, 0x00, 0x26,
        0x00, 0x03, 0x00, 0x00,
        0x75, 0x73, 0x65, 0x72, 0x00,
        0x70, 0x6f, 0x73, 0x74, 0x67, 0x72, 0x65, 0x73, 0x00,
        0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00,
        0x70, 0x6f, 0x73, 0x74, 0x67, 0x72, 0x65, 0x73, 0x00,
        0x00
    )

    sock:send(auth_msg)
    status, response = sock:receive()

    if status and response then
        if response:byte(1) == string.byte("R") then
            table.insert(output, "[+] PostgreSQL service confirmed")
            table.insert(output, "[!] Authentication required")

            if #response >= 9 then
                local auth_type = response:byte(5) * 256 + response:byte(6)
                if auth_type == 0 then
                    table.insert(output, "    Auth Type: OK (no password)")
                elseif auth_type == 3 then
                    table.insert(output, "    Auth Type: Cleartext Password")
                elseif auth_type == 5 then
                    table.insert(output, "    Auth Type: MD5 Password")
                elseif auth_type == 10 then
                    table.insert(output, "    Auth Type: SASL")
                end
            end
        elseif response:byte(1) == string.byte("E") then
            table.insert(output, "[!] PostgreSQL error: Authentication failed")
        end
    end

    sock:close()

    table.insert(output, "")
    table.insert(output, "[!] PostgreSQL enumeration helps identify attack vectors")
    table.insert(output, "[!] Recommendation: Use strong passwords and limit network access")

    return stdnse.format_output(true, output)
end
