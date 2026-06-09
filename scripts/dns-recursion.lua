-- DNS Recursion Test
-- Tests if DNS server allows recursive queries

local nmap = require("nmap")
local stdnse = require("stdnse")
local dns = require("dns")
local string = require("string")
local table = require("table")

description = [[
Tests if a DNS server allows recursive queries from external
sources, which could be used for DNS amplification attacks.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "vuln"}

portrule = function(host, port)
    return port.protocol == "udp" and
           (port.number == 53 or port.service == "dns")
end

action = function(host, port)
    local output = {}

    local status, response = dns.query("www.example.com", {
        type = "A",
        host = host.ip,
        port = port.number,
        dtype = "recursive"
    })

    if status and response then
        table.insert(output, "[!] RECURSION IS ENABLED")
        table.insert(output, "Query: www.example.com (A)")
        table.insert(output, "Response: " .. tostring(response))
        table.insert(output, "\nRisk: Server may be used for DNS amplification attacks")
        table.insert(output, "Recommendation: Disable recursion for external clients")
    else
        table.insert(output, "Recursion appears to be disabled or query failed")

        local status2, response2 = dns.query("example.com", {
            type = "NS",
            host = host.ip,
            port = port.number
        })

        if status2 then
            table.insert(output, "Server responds to non-recursive queries")
        end
    end

    return stdnse.format_output(true, output)
end
