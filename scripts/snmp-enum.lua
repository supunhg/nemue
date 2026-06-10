-- SNMP Enumeration
-- Enumerates SNMP information using common community strings

local nmap = require("nmap")
local stdnse = require("stdnse")
local snmp = require("snmp")

description = [[
Attempts SNMP enumeration using common community strings
to extract system information and configuration.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "udp" and
           (port.number == 161 or port.service == "snmp")
end

action = function(host, port)
    local output = {}
    local community_strings = {"public", "private", "community", "manager", "admin"}

    table.insert(output, "SNMP Enumeration")
    table.insert(output, "Target: " .. host.ip .. ":161")
    table.insert(output, "")

    local sysDescr = "1.3.6.1.2.1.1.1.0"
    local sysName = "1.3.6.1.2.1.1.5.0"
    local sysContact = "1.3.6.1.2.1.1.4.0"
    local sysLocation = "1.3.6.1.2.1.1.6.0"

    for _, community in ipairs(community_strings) do
        local status, result = snmp.get(host.ip, 161, community, sysDescr)

        if status and result then
            table.insert(output, "[+] Valid community string: " .. community)
            table.insert(output, "    System Description: " .. tostring(result))

            local status2, name = snmp.get(host.ip, 161, community, sysName)
            if status2 and name then
                table.insert(output, "    System Name: " .. tostring(name))
            end

            local status3, contact = snmp.get(host.ip, 161, community, sysContact)
            if status3 and contact then
                table.insert(output, "    System Contact: " .. tostring(contact))
            end

            local status4, location = snmp.get(host.ip, 161, community, sysLocation)
            if status4 and location then
                table.insert(output, "    System Location: " .. tostring(location))
            end

            table.insert(output, "")
            table.insert(output, "[!] Weak SNMP community strings allow information disclosure")
            table.insert(output, "[!] Recommendation: Use SNMPv3 with authentication")
            break
        end
    end

    if #output == 3 then
        table.insert(output, "[+] No common community strings worked")
        table.insert(output, "[+] SNMP may be properly secured")
    end

    return stdnse.format_output(true, output)
end
