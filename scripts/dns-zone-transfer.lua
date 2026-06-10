-- DNS Zone Transfer Test
-- Attempts DNS zone transfer (AXFR) to enumerate all records

local nmap = require("nmap")
local stdnse = require("stdnse")
local dns = require("dns")

description = [[
Attempts a DNS zone transfer (AXFR) against the target DNS server.
Zone transfers can expose all DNS records for a domain including
internal hostnames, IP addresses, and service records.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "intrusive", "vuln"}

portrule = function(host, port)
    return port.protocol == "udp" and port.number == 53
end

action = function(host, port)
    local results = {}
    local domain = stdnse.get_script_args("dns-zone-transfer.domain")

    if not domain then
        if host.name and #host.name > 0 then
            domain = host.name
        else
            domain = host.ip
        end
    end

    table.insert(results, "Testing zone transfer for: " .. domain)

    local status, response = dns.query(domain, {
        type = "AXFR",
        server = host.ip,
    })

    if status and response then
        if response.answers and #response.answers > 0 then
            table.insert(results, "VULNERABLE: Zone transfer successful!")
            table.insert(results, "Records found: " .. #response.answers)
            table.insert(results, "")

            for i, record in ipairs(response.answers) do
                if i > 50 then
                    table.insert(results, "... and " .. (#response.answers - 50) .. " more records")
                    break
                end
                local entry = (record.name or "?") .. " " ..
                              (record.ttl or "?") .. " " ..
                              (record.class or "IN") .. " " ..
                              (record.type or "?") .. " " ..
                              (record[1] or "")
                table.insert(results, "  " .. entry)
            end
        else
            table.insert(results, "Zone transfer denied (no records returned)")
        end
    else
        table.insert(results, "Zone transfer failed or denied")
        if response then
            table.insert(results, "Response: " .. tostring(response))
        end
    end

    return stdnse.format_output(true, results)
end
