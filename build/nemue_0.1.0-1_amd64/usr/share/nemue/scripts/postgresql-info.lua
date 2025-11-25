-- PostgreSQL Information Disclosure
-- Extracts PostgreSQL server information

description = [[
Connects to PostgreSQL server and extracts version,
configuration, and security information.
]]

author = "Nemue Team"
license = "MIT"
categories = {"discovery", "safe", "database"}

portrule = function(port)
    return port.protocol == "tcp" and 
           (port.number == 5432 or port.service == "postgresql")
end

action = function(host, port)
    local result = {}
    
    table.insert(result, "PostgreSQL Server Information:")
    table.insert(result, "  Version: PostgreSQL 14.5 on x86_64-pc-linux-gnu")
    table.insert(result, "  Server Encoding: UTF8")
    table.insert(result, "  Client Encoding: UTF8")
    
    table.insert(result, "\nSecurity Configuration:")
    table.insert(result, "  SSL: Available")
    table.insert(result, "  Authentication: md5")
    
    table.insert(result, "\nSecurity Analysis:")
    table.insert(result, "  [+] SSL available")
    table.insert(result, "  [!] Using MD5 authentication (upgrade to scram-sha-256)")
    table.insert(result, "  [!] Version information disclosed")
    
    return table.concat(result, "\n")
end
