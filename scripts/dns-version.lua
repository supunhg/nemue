-- DNS Version Detection
-- Queries DNS server for version information

local nmap = require("nmap")
local stdnse = require("stdnse")
local dns = require("dns")

description = [[
Queries the DNS server for its version using the VERSION.BIND
CHAOS TXT record technique.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "udp" and
           (port.number == 53 or port.service == "dns")
end

action = function(host, port)
    local output = {}

    local status, response = dns.query("version.bind", {
        type = "TXT",
        class = "CHAOS",
        host = host.ip,
        port = port.number
    })

    if status and response then
        table.insert(output, "DNS Version: " .. tostring(response))

        local version = tostring(response):lower()
        if version:find("bind") then
            table.insert(output, "Server Software: ISC BIND")
        elseif version:find("microsoft") then
            table.insert(output, "Server Software: Microsoft DNS")
        elseif version:find("dnsmasq") then
            table.insert(output, "Server Software: Dnsmasq")
        end

        table.insert(output, "\n[!] Version disclosure may aid attackers")
    else
        table.insert(output, "Version query not supported or blocked")
    end

    return stdnse.format_output(true, output)
end
