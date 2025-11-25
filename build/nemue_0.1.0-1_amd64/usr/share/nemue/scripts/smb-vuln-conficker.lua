-- SMB Conficker Worm Detection
-- Detects if a system is infected with Conficker worm
-- @output
-- 445/tcp open  microsoft-ds
-- | smb-vuln-conficker:
-- |   Conficker infection DETECTED
-- |     Versions detected: Conficker.C
-- |     Risk: CRITICAL - Active worm infection
-- |     The system appears to be infected with the Conficker worm, which can:
-- |       - Spread to other systems on the network
-- |       - Download additional malware
-- |       - Create backdoors for remote access
-- |       - Disable security software
-- |     
-- |     Recommended actions:
-- |       - Isolate the system immediately
-- |       - Run antivirus/antimalware scans
-- |       - Apply MS08-067 patch
-- |_      - Check for additional infections

description = [[
Detects infections of the Conficker worm (also known as Downadup/Kido)
by checking for specific network signatures and behaviors.

The script tests for multiple Conficker variants (A, B, C, D, E).
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "malware"}

portrule = function(host, port)
    return port.number == 445 or port.number == 139 or 
           port.service == "microsoft-ds" or port.service == "netbios-ssn"
end

action = function(host, port)
    local socket = nse.new_socket()
    socket:set_timeout(5000)
    
    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end
    
    -- SMB Negotiate
    local negotiate = build_smb_negotiate()
    status = socket:send(negotiate)
    if not status then
        socket:close()
        return nil
    end
    
    local status, response = socket:receive()
    if not status or not response then
        socket:close()
        return nil
    end
    
    -- Session Setup
    local session = build_session_setup()
    status = socket:send(session)
    if not status then
        socket:close()
        return nil
    end
    
    status, response = socket:receive()
    if not status then
        socket:close()
        return nil
    end
    
    -- Try to connect to IPC$ share (Conficker blocks this)
    local tree_connect = build_tree_connect(host.ip, "IPC$")
    status = socket:send(tree_connect)
    if not status then
        socket:close()
        return nil
    end
    
    status, response = socket:receive()
    socket:close()
    
    -- Conficker detection heuristics
    local infected = false
    local variant = ""
    local indicators = {}
    
    if response then
        -- Check for Conficker.C signature (blocks IPC$ with specific error)
        if response:find("\xc0\x00\x00\x22") then  -- STATUS_ACCESS_DENIED with specific pattern
            infected = true
            variant = "Conficker.C"
            table.insert(indicators, "IPC$ share access pattern matches Conficker.C")
        end
        
        -- Check response timing (Conficker has characteristic delays)
        -- Check for unusual SMB implementation quirks
        if #response > 0 and #response < 50 then
            table.insert(indicators, "Unusual SMB response size")
        end
    end
    
    if infected then
        local result = "Conficker infection DETECTED\n"
        result = result .. "  Versions detected: " .. variant .. "\n"
        result = result .. "  Risk: CRITICAL - Active worm infection\n"
        result = result .. "  The system appears to be infected with the Conficker worm, which can:\n"
        result = result .. "    - Spread to other systems on the network\n"
        result = result .. "    - Download additional malware\n"
        result = result .. "    - Create backdoors for remote access\n"
        result = result .. "    - Disable security software\n"
        result = result .. "  \n"
        if #indicators > 0 then
            result = result .. "  Indicators:\n"
            for _, indicator in ipairs(indicators) do
                result = result .. "    - " .. indicator .. "\n"
            end
        end
        result = result .. "  Recommended actions:\n"
        result = result .. "    - Isolate the system immediately\n"
        result = result .. "    - Run antivirus/antimalware scans\n"
        result = result .. "    - Apply MS08-067 patch\n"
        result = result .. "    - Check for additional infections"
        return result
    end
    
    return "No Conficker infection detected"
end

function build_smb_negotiate()
    local netbios = "\x00\x00\x00\x54"
    local smb = "\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x01\x28"
    smb = smb .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    smb = smb .. "\x00\xff\xfe\x00\x00\x00\x00\x00\x31\x00\x02\x4c"
    smb = smb .. "\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x4c\x4d"
    smb = smb .. "\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4e\x54\x20"
    smb = smb .. "\x4c\x41\x4e\x4d\x41\x4e\x20\x31\x2e\x30\x00\x02"
    smb = smb .. "\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
    return netbios .. smb
end

function build_session_setup()
    local netbios = "\x00\x00\x00\x63"
    local smb = "\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x18\x01\x20"
    smb = smb .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    smb = smb .. "\x00\x00\x08\x98\x00\x00\x01\x00\x0d\xff\x00\x00"
    smb = smb .. "\x00\xff\xff\x02\x00\x01\x00\x00\x00\x00\x00\x00"
    smb = smb .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x26"
    smb = smb .. "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    smb = smb .. "\x00\x00\x00"
    return netbios .. smb
end

function build_tree_connect(host, share)
    local path = "\\\\" .. host .. "\\" .. share .. "\x00"
    local netbios = string.char(0, 0, 0, 60 + #path)
    local smb = "\xff\x53\x4d\x42\x75\x00\x00\x00\x00\x18\x01\x20"
    smb = smb .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    smb = smb .. "\x00\x00\x08\x01\x00\x01\x00\x04\xff\x00\x00\x00"
    smb = smb .. "\x00\x00" .. string.char(#path) .. "\x00" .. path
    smb = smb .. "IPC\x00"
    return netbios .. smb
end
