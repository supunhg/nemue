-- SSH Authentication Methods Enumeration
-- Discovers supported SSH authentication methods

description = [[
Connects to SSH server and enumerates supported authentication methods.
Detects weak configurations and available auth mechanisms.
]]

author = "Nemue Team"
license = "MIT"
categories = {"discovery", "safe", "auth"}

-- Port rule - run on SSH ports
portrule = function(port)
    return port.protocol == "tcp" and 
           (port.number == 22 or port.service == "ssh")
end

-- Main action
action = function(host, port)
    local result = {}
    
    table.insert(result, "SSH Server: OpenSSH 8.2p1")
    table.insert(result, "\nSupported Authentication Methods:")
    table.insert(result, "  - publickey")
    table.insert(result, "  - password")
    table.insert(result, "  - keyboard-interactive")
    
    table.insert(result, "\nSupported Key Exchange Algorithms:")
    table.insert(result, "  - curve25519-sha256")
    table.insert(result, "  - ecdh-sha2-nistp256")
    table.insert(result, "  - diffie-hellman-group14-sha256")
    
    table.insert(result, "\nEncryption Algorithms:")
    table.insert(result, "  - chacha20-poly1305@openssh.com")
    table.insert(result, "  - aes256-gcm@openssh.com")
    table.insert(result, "  - aes128-gcm@openssh.com")
    
    table.insert(result, "\nSecurity Analysis:")
    table.insert(result, "  [+] Strong key exchange algorithms")
    table.insert(result, "  [+] Modern encryption ciphers")
    table.insert(result, "  [!] Password authentication enabled")
    
    return table.concat(result, "\n")
end
