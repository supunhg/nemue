-- SNMP Trap Detection
-- Checks for common SNMP community strings and agent info

local nmap = require("nmap")
local stdnse = require("stdnse")
local snmp = require("snmp")

description = [[
Sends SNMP requests to detect SNMP agent configuration and
checks for common community strings (public, private, etc).
Reports SNMPv1/v2c community string exposure.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe"}

portrule = function(host, port)
    return port.protocol == "udp" and
           (port.number == 161 or port.number == 162 or
            port.service == "snmp" or port.service == "snmptrap")
end

local community_strings = {
    "public", "private", "community", "manager", "secret",
    "admin", "cisco", "snmp", "monitor", "all",
}

action = function(host, port)
    local results = {}
    local valid_communities = {}

    for _, community in ipairs(community_strings) do
        local status, response = snmp.get(host.ip, port.number, community, "1.3.6.1.2.1.1.1.0")

        if status and response then
            table.insert(valid_communities, community)
        end
    end

    if #valid_communities > 0 then
        table.insert(results, "Valid SNMP community strings found:")
        for _, cs in ipairs(valid_communities) do
            table.insert(results, "  " .. cs)
            if cs == "public" or cs == "private" then
                table.insert(results, "    WARNING: Default community string in use")
            end
        end

        table.insert(results, "")
        table.insert(results, "Total valid: " .. #valid_communities)

        local status, sysdescr = snmp.get(host.ip, port.number, valid_communities[1], "1.3.6.1.2.1.1.1.0")
        if status and sysdescr then
            table.insert(results, "System description: " .. tostring(sysdescr))
        end

        local status2, sysname = snmp.get(host.ip, port.number, valid_communities[1], "1.3.6.1.2.1.1.5.0")
        if status2 and sysname then
            table.insert(results, "System name: " .. tostring(sysname))
        end
    else
        table.insert(results, "No valid community strings found from common list")
    end

    return stdnse.format_output(true, results)
end
