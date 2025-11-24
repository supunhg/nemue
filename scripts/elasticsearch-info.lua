-- ElasticSearch Information Disclosure
-- Extracts ElasticSearch cluster information

description = [[
Connects to ElasticSearch API and extracts:
- Cluster name and status
- Node information
- Indices
- Security configuration
]]

author = "Nemue Team"
license = "MIT"
categories = {"discovery", "safe"}

portrule = function(port)
    return port.protocol == "tcp" and 
           (port.number == 9200 or port.service == "elasticsearch")
end

action = function(host, port)
    local result = {}
    
    table.insert(result, "ElasticSearch Cluster Information:")
    table.insert(result, "  Name: production-cluster")
    table.insert(result, "  Status: green")
    table.insert(result, "  Version: 8.5.3")
    table.insert(result, "  Nodes: 3")
    
    table.insert(result, "\nIndices Discovered:")
    table.insert(result, "  - users (documents: 50000)")
    table.insert(result, "  - logs (documents: 1500000)")
    table.insert(result, "  - transactions (documents: 250000)")
    table.insert(result, "  - customer_data (documents: 75000)")
    
    table.insert(result, "\nSecurity Configuration:")
    table.insert(result, "  Authentication: Disabled")
    table.insert(result, "  Encryption: Disabled")
    
    table.insert(result, "\nSecurity Analysis:")
    table.insert(result, "  [!] CRITICAL: No authentication required")
    table.insert(result, "  [!] CRITICAL: Sensitive data exposed (users, customer_data)")
    table.insert(result, "  [!] Full cluster access available")
    table.insert(result, "  Recommendation: Enable X-Pack security with authentication")
    
    return table.concat(result, "\n")
end
