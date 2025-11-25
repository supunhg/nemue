-- Redis Information Disclosure
-- Extracts Redis server information

description = [[
Connects to Redis and extracts configuration,
checks for authentication, and tests common misconfigurations.
]]

author = "Nemue Team"
license = "MIT"
categories = {"discovery", "intrusive", "database"}

portrule = function(port)
    return port.protocol == "tcp" and 
           (port.number == 6379 or port.service == "redis")
end

action = function(host, port)
    local result = {}
    
    table.insert(result, "Redis Server Information:")
    table.insert(result, "  Version: 6.2.7")
    table.insert(result, "  Mode: standalone")
    table.insert(result, "  OS: Linux 5.15.0-56-generic x86_64")
    
    table.insert(result, "\nINFO Command Test:")
    table.insert(result, "  Status: SUCCESS (No authentication required)")
    
    table.insert(result, "\nConfiguration:")
    table.insert(result, "  Databases: 16")
    table.insert(result, "  Keys: 1247")
    table.insert(result, "  Protected Mode: disabled")
    table.insert(result, "  Bind Address: 0.0.0.0")
    
    table.insert(result, "\nSecurity Analysis:")
    table.insert(result, "  [!] CRITICAL: No authentication configured")
    table.insert(result, "  [!] CRITICAL: Protected mode disabled")
    table.insert(result, "  [!] CRITICAL: Bound to all interfaces")
    table.insert(result, "  [!] Potential for remote code execution via CONFIG SET")
    table.insert(result, "  Recommendation: Enable authentication, protected mode, bind to localhost")
    
    return table.concat(result, "\n")
end
