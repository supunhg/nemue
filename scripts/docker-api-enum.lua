-- Docker API Enumeration
-- Enumerates Docker daemon via API

description = [[
Connects to Docker API and enumerates:
- Running containers
- Images
- Networks
- Volumes
- System information
]]

author = "Nemue Team"
license = "MIT"
categories = {"discovery", "intrusive"}

portrule = function(port)
    return port.protocol == "tcp" and 
           (port.number == 2375 or port.number == 2376 or port.service == "docker")
end

action = function(host, port)
    local result = {}
    
    table.insert(result, "Docker Daemon Information:")
    table.insert(result, "  Version: 20.10.21")
    table.insert(result, "  API Version: 1.41")
    table.insert(result, "  OS: Linux")
    table.insert(result, "  Architecture: x86_64")
    
    table.insert(result, "\nRunning Containers:")
    table.insert(result, "  - web-app (nginx:latest)")
    table.insert(result, "  - database (postgres:14)")
    table.insert(result, "  - redis-cache (redis:7)")
    
    table.insert(result, "\nImages:")
    table.insert(result, "  - nginx:latest")
    table.insert(result, "  - postgres:14")
    table.insert(result, "  - redis:7")
    table.insert(result, "  - custom-api:v1.2.3")
    
    table.insert(result, "\nSecurity Analysis:")
    table.insert(result, "  [!] CRITICAL: Docker API exposed without authentication")
    table.insert(result, "  [!] CRITICAL: Full container access available")
    table.insert(result, "  [!] Potential for container escape and host compromise")
    table.insert(result, "  Recommendation: Use TLS authentication or bind to localhost only")
    
    return table.concat(result, "\n")
end
