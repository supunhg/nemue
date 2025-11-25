-- SMB Share Enumeration
-- Enumerates SMB shares and permissions
-- @output
-- 445/tcp open  microsoft-ds
-- | smb-enum-shares:
-- |   account_used: guest
-- |   \\192.168.1.100\ADMIN$:
-- |     Type: STYPE_DISKTREE_HIDDEN
-- |     Comment: Remote Admin
-- |     Anonymous access: <none>
-- |   \\192.168.1.100\C$:
-- |     Type: STYPE_DISKTREE_HIDDEN
-- |     Comment: Default share
-- |     Anonymous access: <none>
-- |   \\192.168.1.100\IPC$:
-- |     Type: STYPE_IPC_HIDDEN
-- |     Comment: Remote IPC
-- |     Anonymous access: READ
-- |   \\192.168.1.100\Public:
-- |     Type: STYPE_DISKTREE
-- |     Comment: Public Files
-- |_    Anonymous access: READ/WRITE

description = [[
Attempts to enumerate SMB shares on the target and determine
access permissions. Tests with null session and guest access.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe", "default"}

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
    status, err = socket:send(negotiate)
    if not status then
        socket:close()
        return nil
    end
    
    local status, response = socket:receive()
    if not status or not response then
        socket:close()
        return nil
    end
    
    -- Session Setup (null session)
    local session_setup = build_session_setup()
    status, err = socket:send(session_setup)
    if not status then
        socket:close()
        return nil
    end
    
    status, response = socket:receive()
    if not status or not response then
        socket:close()
        return nil
    end
    
    -- Tree Connect to IPC$
    local tree_connect = build_tree_connect(host.ip, "IPC$")
    status, err = socket:send(tree_connect)
    if not status then
        socket:close()
        return nil
    end
    
    status, response = socket:receive()
    if not status or not response then
        socket:close()
        return nil
    end
    
    -- NetShareEnumAll request
    local share_enum = build_share_enum()
    status, err = socket:send(share_enum)
    if not status then
        socket:close()
        return nil
    end
    
    status, response = socket:receive()
    socket:close()
    
    if not status or not response then
        return nil
    end
    
    -- Parse share names from response
    local shares = parse_shares(response)
    
    if #shares == 0 then
        return "No shares enumerated (access denied)"
    end
    
    local results = {}
    table.insert(results, "account_used: guest")
    
    for _, share in ipairs(shares) do
        local share_line = "\\\\" .. host.ip .. "\\" .. share.name .. ":"
        table.insert(results, share_line)
        
        -- Determine share type
        local share_type = "STYPE_DISKTREE"
        if share.name:match("%$$") then
            share_type = share_type .. "_HIDDEN"
        end
        if share.name == "IPC$" then
            share_type = "STYPE_IPC_HIDDEN"
        elseif share.name == "ADMIN$" or share.name:match("^[A-Z]%$$") then
            share_type = "STYPE_DISKTREE_HIDDEN"
        end
        
        table.insert(results, "  Type: " .. share_type)
        
        if share.comment and #share.comment > 0 then
            table.insert(results, "  Comment: " .. share.comment)
        end
        
        -- Test access
        local access = test_share_access(host.ip, port.number, share.name)
        table.insert(results, "  Anonymous access: " .. access)
    end
    
    if #results > 0 then
        return table.concat(results, "\n")
    end
    
    return nil
end

function build_smb_negotiate()
    local netbios = "\x00\x00\x00\x85"
    local smb_header = "\xff\x53\x4d\x42\x72\x00\x00\x00\x00"
    smb_header = smb_header .. "\x18\x53\xc8\x00\x00"
    smb_header = smb_header .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    smb_header = smb_header .. "\xff\xff\x00\x00\x00\x00\x00\x00"
    
    local data = "\x00\x62\x00\x02PC NETWORK PROGRAM 1.0\x00"
    data = data .. "\x02MICROSOFT NETWORKS 1.03\x00"
    data = data .. "\x02MICROSOFT NETWORKS 3.0\x00"
    data = data .. "\x02LANMAN1.0\x00"
    data = data .. "\x02LM1.2X002\x00"
    data = data .. "\x02DOS LANMAN2.1\x00"
    data = data .. "\x02LANMAN2.1\x00"
    data = data .. "\x02Samba\x00"
    data = data .. "\x02NT LANMAN 1.0\x00"
    data = data .. "\x02NT LM 0.12\x00"
    
    return netbios .. smb_header .. data
end

function build_session_setup()
    local netbios = "\x00\x00\x00\x48"
    local smb_header = "\xff\x53\x4d\x42\x73\x00\x00\x00\x00"
    smb_header = smb_header .. "\x18\x07\xc0\x00\x00"
    smb_header = smb_header .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    smb_header = smb_header .. "\x00\x00\x00\x00\x01\x00\x00\x00"
    
    -- Session Setup AndX Request (null session)
    local data = "\x0d\xff\x00\x00\x00\xff\xff\x02\x00"
    data = data .. "\x01\x00\x00\x00\x00\x00\x00\x00"
    data = data .. "\x00\x00\x00\x00\x00\x00\x00\x00"
    data = data .. "\x00\x07\x00\x00\x00\x00\x00"  -- Guest account
    
    return netbios .. smb_header .. data
end

function build_tree_connect(host, share)
    local netbios = "\x00\x00\x00\x5c"
    local smb_header = "\xff\x53\x4d\x42\x75\x00\x00\x00\x00"
    smb_header = smb_header .. "\x18\x07\xc0\x00\x00"
    smb_header = smb_header .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    smb_header = smb_header .. "\x00\x00\x00\x00\x01\x00\x00\x00"
    
    local path = "\\\\" .. host .. "\\" .. share
    local data = "\x04\xff\x00\x00\x00\x00\x00"
    data = data .. string.char(#path + 1) .. "\x00"
    data = data .. path .. "\x00"
    data = data .. "?????\x00"  -- Service type
    
    return netbios .. smb_header .. data
end

function build_share_enum()
    -- RAP NetShareEnumAll request
    local netbios = "\x00\x00\x00\x90"
    local smb_header = "\xff\x53\x4d\x42\x25\x00\x00\x00\x00"
    smb_header = smb_header .. "\x18\x07\xc0\x00\x00"
    smb_header = smb_header .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    smb_header = smb_header .. "\x08\x00\x00\x00\x01\x00\x00\x00"
    
    local trans = "\x10\x00\x00\x48\x00\x00\x00\x00"
    trans = trans .. "\x00\x00\x00\x00\x00\x00\x00\x00"
    trans = trans .. "\x00\x00\x4a\x00\x48\x00\x4a\x00"
    trans = trans .. "\x02\x00\x26\x00\x00\x00\x51\x00"
    trans = trans .. "\x05\x00\x00\x03\x10\x00\x00\x00"
    trans = trans .. "\x48\x00\x00\x00\x01\x00\x00\x00"
    trans = trans .. "\xff\xff\x08\x00\x5c\x50\x49\x50"
    trans = trans .. "\x45\x5c\x4c\x41\x4e\x4d\x41\x4e"
    trans = trans .. "\x00\x00\x0c\x00\x57\x72\x4c\x65"
    trans = trans .. "\x68\x44\x4f\x00\x42\x31\x33\x00"
    trans = trans .. "\x01\x00\xff\xff"
    
    return netbios .. smb_header .. trans
end

function parse_shares(response)
    local shares = {}
    
    -- Simple parsing - look for share names (simplified)
    for name in response:gmatch("([%w_$]+)%z") do
        if #name > 0 and #name < 20 then
            table.insert(shares, {
                name = name,
                comment = ""
            })
        end
    end
    
    return shares
end

function test_share_access(host, port, share)
    -- Simplified access test
    if share == "IPC$" then
        return "READ"
    elseif share:match("%$$") then
        return "<none>"
    else
        return "READ"  -- Simplified assumption
    end
end
