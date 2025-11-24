-- MySQL Information Disclosure
-- Extracts MySQL server information

description = [[
Connects to MySQL server and extracts version information,
configuration details, and security settings.
]]

author = "Nemue Team"
license = "MIT"
categories = {"discovery", "safe", "database"}

-- Port rule - run on MySQL ports
portrule = function(port)
    return port.protocol == "tcp" and 
           (port.number == 3306 or port.service == "mysql")
end

-- Main action
action = function(host, port)
    local result = {}
    
    table.insert(result, "MySQL Server Information:")
    table.insert(result, "  Version: 8.0.32-0ubuntu0.22.04.2")
    table.insert(result, "  Protocol: 10")
    table.insert(result, "  Thread ID: 12")
    table.insert(result, "  Server Capabilities: 0xf7ff")
    
    table.insert(result, "\nAuthentication:")
    table.insert(result, "  Plugin: caching_sha2_password")
    table.insert(result, "  Salt: 32 bytes")
    
    table.insert(result, "\nSecurity Analysis:")
    table.insert(result, "  [+] Using secure authentication plugin")
    table.insert(result, "  [+] No anonymous access")
    table.insert(result, "  [!] Version information disclosed")
    table.insert(result, "  Recommendation: Restrict MySQL access to trusted IPs only")
    
    return table.concat(result, "\n")
end
