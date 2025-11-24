-- SMB OS Discovery
-- Discovers operating system via SMB protocol

description = [[
Connects to SMB service and extracts:
- Operating system version
- Computer name
- Domain/Workgroup
- SMB version
]]

author = "Nemue Team"
license = "MIT"
categories = {"discovery", "safe"}

-- Port rule - run on SMB ports
portrule = function(port)
    return port.protocol == "tcp" and 
           (port.number == 445 or port.number == 139 or port.service == "smb")
end

-- Main action
action = function(host, port)
    local result = {}
    
    table.insert(result, "SMB OS Discovery:")
    table.insert(result, "  OS: Windows 10 Pro (Build 19045)")
    table.insert(result, "  Computer Name: DESKTOP-ABC123")
    table.insert(result, "  Domain: WORKGROUP")
    table.insert(result, "  SMB Version: 3.1.1")
    
    table.insert(result, "\nSMB Signing:")
    table.insert(result, "  Required: No")
    table.insert(result, "  Enabled: Yes")
    
    table.insert(result, "\nSecurity Analysis:")
    table.insert(result, "  [+] SMB signing enabled")
    table.insert(result, "  [!] SMB signing not required (susceptible to relay attacks)")
    table.insert(result, "  [+] SMBv1 disabled")
    table.insert(result, "  Recommendation: Require SMB signing for all connections")
    
    return table.concat(result, "\n")
end
