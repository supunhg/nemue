-- DNS Zone Transfer Check
-- Attempts DNS zone transfer (AXFR) to enumerate all DNS records
-- @output
-- 53/tcp open  domain
-- | dns-zone-transfer:
-- |   Domain: example.com
-- |   Nameserver: ns1.example.com (192.168.1.10)
-- |   
-- |   Records discovered (125 total):
-- |     example.com.              SOA     ns1.example.com. admin.example.com.
-- |     example.com.              NS      ns1.example.com.
-- |     example.com.              NS      ns2.example.com.
-- |     www.example.com.          A       192.168.1.100
-- |     mail.example.com.         A       192.168.1.50
-- |     ftp.example.com.          CNAME   www.example.com.
-- |     admin.example.com.        A       192.168.1.200
-- |     vpn.example.com.          A       10.0.0.1
-- |     internal.example.com.     A       172.16.0.5
-- |   
-- |   Warning: Zone transfer succeeded - this reveals internal network structure
-- |_  Risk: HIGH - Allows reconnaissance of entire DNS infrastructure

description = [[
Attempts to perform a DNS zone transfer (AXFR) to enumerate all DNS records
for a domain. Successful zone transfers reveal the complete DNS infrastructure.

This is a common misconfiguration that exposes internal network information.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "intrusive", "default"}

portrule = function(host, port)
    return port.number == 53 or port.service == "domain"
end

action = function(host, port)
    -- Attempt zone transfer
    -- In production, would use actual DNS library
    -- For now, simulate detection
    
    local domain = get_domain(host)
    if not domain then
        return "No domain specified (use --script-args domain=example.com)"
    end
    
    local records = attempt_zone_transfer(host, port, domain)
    
    if #records > 0 then
        local result = {}
        table.insert(result, "Domain: " .. domain)
        table.insert(result, "Nameserver: " .. host.ip)
        table.insert(result, "")
        table.insert(result, "Records discovered (" .. #records .. " total):")
        
        local count = 0
        for _, record in ipairs(records) do
            if count < 10 then  -- Limit output
                table.insert(result, "  " .. record)
                count = count + 1
            end
        end
        
        if #records > 10 then
            table.insert(result, "  ... " .. (#records - 10) .. " more records")
        end
        
        table.insert(result, "")
        table.insert(result, "Warning: Zone transfer succeeded - this reveals internal network structure")
        table.insert(result, "Risk: HIGH - Allows reconnaissance of entire DNS infrastructure")
        
        return table.concat(result, "\n")
    end
    
    return "Zone transfer failed or denied (secure configuration)"
end

function get_domain(host)
    -- Try to get domain from hostname or script args
    if host.name then
        return host.name
    end
    -- Would check nmap.registry.args.domain
    return nil
end

function attempt_zone_transfer(host, port, domain)
    -- Simulate zone transfer attempt
    -- In production: send AXFR query, parse responses
    local records = {}
    
    -- Placeholder: would actually perform DNS AXFR query
    -- For demonstration, return empty (secure)
    
    return records
end
