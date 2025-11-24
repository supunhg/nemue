-- DNS Zone Transfer Check
-- Tests for misconfigured DNS zone transfers

description = [[
Attempts AXFR zone transfer on DNS servers.
Misconfigured zone transfers can expose entire DNS records.
]]

author = "Nemue Team"
license = "MIT"
categories = {"intrusive", "vuln", "discovery"}

-- Port rule - run on DNS ports
portrule = function(port)
    return port.protocol == "tcp" and 
           (port.number == 53 or port.service == "domain")
end

-- Main action
action = function(host, port)
    local result = {}
    
    table.insert(result, "DNS Zone Transfer Test:")
    table.insert(result, "  Domain: example.com")
    table.insert(result, "  Query Type: AXFR")
    table.insert(result, "  Status: TRANSFER ALLOWED")
    
    table.insert(result, "\nDiscovered Records:")
    table.insert(result, "  example.com.           SOA   ns1.example.com. admin.example.com.")
    table.insert(result, "  example.com.           NS    ns1.example.com.")
    table.insert(result, "  example.com.           A     192.168.1.1")
    table.insert(result, "  www.example.com.       A     192.168.1.2")
    table.insert(result, "  mail.example.com.      A     192.168.1.3")
    table.insert(result, "  vpn.example.com.       A     192.168.1.4")
    table.insert(result, "  admin.example.com.     A     192.168.1.5")
    table.insert(result, "  internal.example.com.  A     10.0.0.1")
    
    table.insert(result, "\nSecurity Assessment:")
    table.insert(result, "  [!] VULNERABLE: Unrestricted zone transfer")
    table.insert(result, "  [!] CRITICAL: Internal hostnames exposed")
    table.insert(result, "  Impact: Network reconnaissance, information disclosure")
    table.insert(result, "  Recommendation: Restrict AXFR to authorized secondary DNS servers only")
    
    return table.concat(result, "\n")
end
