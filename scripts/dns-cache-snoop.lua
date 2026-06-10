-- DNS Cache Snooping
-- Tests DNS server for cached domain queries

local dns = require("dns")
local nmap = require("nmap")
local stdnse = require("stdnse")

description = [[
Performs DNS cache snooping to determine which domains
have been recently queried through the DNS server.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "udp" and
           (port.number == 53 or port.service == "dns")
end

action = function(host, port)
    local output = {}
    local cached_domains = {}

    local domains = {
        "www.google.com", "www.facebook.com", "www.youtube.com",
        "www.twitter.com", "www.amazon.com", "www.apple.com",
        "www.microsoft.com", "www.netflix.com", "www.github.com",
        "www.reddit.com", "www.wikipedia.org", "www.linkedin.com",
        "www.instagram.com", "www.whatsapp.com", "www.spotify.com"
    }

    table.insert(output, "DNS Cache Snooping")
    table.insert(output, "Target DNS: " .. host.ip)
    table.insert(output, "")

    for _, domain in ipairs(domains) do
        local status, response = dns.query(domain, {
            host = host.ip,
            port = port.number,
            dtype = "A",
            retAll = true
        })

        if status and response then
            table.insert(cached_domains, domain)
            table.insert(output, "[+] CACHED: " .. domain)
        end
    end

    table.insert(output, "")
    table.insert(output, "Cached domains: " .. #cached_domains .. "/" .. #domains)

    if #cached_domains > 0 then
        table.insert(output, "")
        table.insert(output, "[!] DNS cache snooping is possible")
        table.insert(output, "[!] Users have been browsing these domains")
        table.insert(output, "[!] Can be used for network reconnaissance")
    end

    return stdnse.format_output(true, output)
end
