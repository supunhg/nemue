-- Telnet Encryption Detection
-- Checks if Telnet supports encryption
-- @output
-- 23/tcp open  telnet
-- | telnet-encryption:
-- |   Encryption: Not supported
-- |_  WARNING: Plaintext transmission enabled

description = [[
Checks if the Telnet service supports encryption through the ENCRYPT option.
Warns about plaintext transmission if encryption is not available.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe", "default"}

portrule = function(host, port)
    return port.number == 23 or port.service == "telnet"
end

action = function(host, port)
    local socket = nse.new_socket()
    socket:set_timeout(5000)
    
    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end
    
    -- Read initial banner and negotiations
    local status, banner = socket:receive()
    if not status then
        socket:close()
        return nil
    end
    
    local results = {}
    local encryption_supported = false
    local authentication_supported = false
    
    -- Check for encryption option (0x26)
    if banner:find("\xff\xfd\x26") or banner:find("\xff\xfb\x26") then
        encryption_supported = true
    end
    
    -- Check for authentication option (0x25)
    if banner:find("\xff\xfd\x25") or banner:find("\xff\xfb\x25") then
        authentication_supported = true
    end
    
    -- Try to negotiate encryption
    if encryption_supported then
        -- WILL ENCRYPT
        socket:send("\xff\xfb\x26")
        local status, response = socket:receive()
        if status and response and response:find("\xff\xfd\x26") then
            table.insert(results, "Encryption: Supported")
        else
            table.insert(results, "Encryption: Offered but not configured")
        end
    else
        table.insert(results, "Encryption: Not supported")
        table.insert(results, "WARNING: Plaintext transmission enabled")
    end
    
    if authentication_supported then
        table.insert(results, "Authentication: Kerberos/SRP available")
    end
    
    socket:close()
    
    if #results > 0 then
        return table.concat(results, "\n")
    end
    
    return nil
end
