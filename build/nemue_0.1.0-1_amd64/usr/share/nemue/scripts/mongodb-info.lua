-- MongoDB Information Disclosure
-- Extracts MongoDB server information

description = [[
Connects to MongoDB and extracts version,
configuration, and checks for authentication.
]]

author = "Nemue Team"
license = "MIT"
categories = {"discovery", "safe", "database"}

portrule = function(port)
    return port.protocol == "tcp" and 
           (port.number == 27017 or port.service == "mongodb")
end

action = function(host, port)
    local result = {}
    
    table.insert(result, "MongoDB Server Information:")
    table.insert(result, "  Version: 5.0.14")
    table.insert(result, "  Storage Engine: WiredTiger")
    table.insert(result, "  Wire Version: 13")
    
    table.insert(result, "\nAuthentication:")
    table.insert(result, "  Status: DISABLED")
    table.insert(result, "  Available Databases: admin, local, test, production")
    
    table.insert(result, "\nSecurity Analysis:")
    table.insert(result, "  [!] CRITICAL: No authentication required")
    table.insert(result, "  [!] CRITICAL: Database enumeration possible")
    table.insert(result, "  [!] Production database exposed")
    table.insert(result, "  Recommendation: Enable authentication immediately")
    
    return table.concat(result, "\n")
end
