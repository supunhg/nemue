-- SNMP sysDescr Retrieval
-- Gets SNMP sysDescr and system information

local nmap = require("nmap")
local stdnse = require("stdnse")
local snmp = require("snmp")
local table = require("table")

description = [[
Retrieves the sysDescr and other system information from an
SNMP agent using common community strings.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default", "discovery"}

portrule = function(host, port)
    return port.protocol == "udp" and
           (port.number == 161 or port.service == "snmp")
end

local function snmp_get(host, port, community, oid)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host.ip, port.number, "udp")
    if not status then
        return nil, err
    end

    local payload = string.char(
        0x30, 0x26,
        0x02, 0x01, 0x00,
        0x04, #community
    ) .. community .. string.char(
        0xa0, 0x19,
        0x02, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x01, 0x00,
        0x02, 0x01, 0x00,
        0x30, 0x0b,
        0x30, 0x09,
        0x06, #oid
    ) .. oid .. string.char(0x05, 0x00)

    socket:send(payload)
    local status, response = socket:receive()
    socket:close()

    if status and response then
        return response
    end
    return nil, "No response"
end

action = function(host, port)
    local output = {}
    local community_strings = {"public", "private", "community"}

    table.insert(output, "Testing SNMP community strings...")

    for _, community in ipairs(community_strings) do
        table.insert(output, "\nCommunity: \"" .. community .. "\"")

        local response = snmp_get(host, port, community, "\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00")

        if response then
            table.insert(output, "[+] Community string accepted: " .. community)

            local sysdescr = response:match("\x04(.+)$")
            if sysdescr then
                table.insert(output, "sysDescr: " .. sysdescr)
            end

            table.insert(output, "\n[!] SNMP agent is accessible")
            break
        else
            table.insert(output, "  No response or timeout")
        end
    end

    return stdnse.format_output(true, output)
end
