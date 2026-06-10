-- SNMP Community String Brute Force
-- Tests common SNMP community strings

local nmap = require("nmap")
local stdnse = require("stdnse")
local snmp = require("snmp")

description = [[
Tests common SNMP community strings to identify weak or default
configurations on SNMP-enabled devices.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "udp" and
           (port.number == 161 or port.service == "snmp")
end

action = function(host, port)
    local output = {}
    local valid_communities = {}

    local communities = {
        "public",
        "private",
        "manager",
        "admin",
        "community",
        "snmp",
        "secret",
        "cisco",
        "switch",
        "monitor"
    }

    table.insert(output, "Testing SNMP Community Strings:")

    for _, community in ipairs(communities) do
        local status, response = snmp.get(host.ip, port.number, community, "1.3.6.1.2.1.1.1.0")

        if status and response then
            table.insert(valid_communities, community)
            table.insert(output, "  [+] Valid: " .. community)
        else
            table.insert(output, "  [-] Invalid: " .. community)
        end
    end

    if #valid_communities > 0 then
        table.insert(output, "\n[!] Weak SNMP community strings found:")
        for _, comm in ipairs(valid_communities) do
            table.insert(output, "  - " .. comm)
        end
        table.insert(output, "\nRecommendation: Use SNMPv3 with authentication")
    else
        table.insert(output, "\nNo weak community strings detected")
    end

    return stdnse.format_output(true, output)
end
