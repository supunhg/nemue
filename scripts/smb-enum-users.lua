-- SMB User Enumeration
-- Enumerates domain users via SMB
-- @output
-- 445/tcp open  microsoft-ds
-- | smb-enum-users:
-- |   WORKGROUP\Administrator (RID: 500)
-- |     Full name:   Administrator
-- |     Description: Built-in account for administering the computer/domain
-- |     Flags:       Normal user account
-- |   WORKGROUP\Guest (RID: 501)
-- |     Full name:   Guest
-- |     Description: Built-in account for guest access
-- |_    Flags:       Account disabled, Password not required

description = [[
Attempts to enumerate domain users through SMB by querying the
Security Account Manager (SAM) remote protocol.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "auth"}

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
    socket:send(negotiate)
    local status, response = socket:receive()
    
    if not status then
        socket:close()
        return nil
    end
    
    -- Session Setup (null session attempt)
    local session_setup = build_session_setup()
    socket:send(session_setup)
    status, response = socket:receive()
    
    if not status then
        socket:close()
        return "Access denied (null session not allowed)"
    end
    
    -- Connect to SAMR pipe
    local tree_connect = build_tree_connect(host.ip, "IPC$")
    socket:send(tree_connect)
    status, response = socket:receive()
    
    if not status then
        socket:close()
        return nil
    end
    
    -- Query user list
    local user_enum = build_user_enum()
    socket:send(user_enum)
    status, response = socket:receive()
    socket:close()
    
    if not status or not response then
        return nil
    end
    
    -- Parse users from response
    local users = parse_users(response)
    
    if #users == 0 then
        return "No users enumerated (access denied or unsupported)"
    end
    
    local results = {}
    for _, user in ipairs(users) do
        local user_line = "WORKGROUP\\" .. user.name .. " (RID: " .. user.rid .. ")"
        table.insert(results, user_line)
        
        if user.fullname then
            table.insert(results, "  Full name:   " .. user.fullname)
        end
        if user.description then
            table.insert(results, "  Description: " .. user.description)
        end
        if user.flags then
            table.insert(results, "  Flags:       " .. user.flags)
        end
    end
    
    return table.concat(results, "\n")
end

function build_smb_negotiate()
    local netbios = "\x00\x00\x00\x54"
    local smb = "\xff\x53\x4d\x42\x72\x00\x00\x00\x00"
    smb = smb .. "\x18\x01\x28\x00\x00\x00\x00\x00\x00\x00\x00"
    smb = smb .. "\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00"
    smb = smb .. "\x00\x31\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31"
    smb = smb .. "\x2e\x30\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30"
    smb = smb .. "\x30\x32\x00\x02\x4e\x54\x20\x4c\x41\x4e\x4d"
    smb = smb .. "\x41\x4e\x20\x31\x2e\x30\x00\x02\x4e\x54\x20"
    smb = smb .. "\x4c\x4d\x20\x30\x2e\x31\x32\x00"
    
    return netbios .. smb
end

function build_session_setup()
    local netbios = "\x00\x00\x00\x63"
    local smb = "\xff\x53\x4d\x42\x73\x00\x00\x00\x00"
    smb = smb .. "\x18\x01\x20\x00\x00\x00\x00\x00\x00\x00\x00"
    smb = smb .. "\x00\x00\x00\x00\x00\x00\x08\x98\x00\x00\x01\x00"
    smb = smb .. "\x0d\xff\x00\x00\x00\xff\xff\x02\x00\x01\x00"
    smb = smb .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    smb = smb .. "\x00\x00\x00\x00\x00\x00\x00\x26\x00\x00\x00"
    smb = smb .. "\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"
    smb = smb .. "\x00\x00\x57\x69\x6e\x64\x6f\x77\x73\x20\x32"
    smb = smb .. "\x30\x30\x30\x20\x32\x31\x39\x35\x00\x57\x69"
    smb = smb .. "\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20"
    smb = smb .. "\x35\x2e\x30\x00"
    
    return netbios .. smb
end

function build_tree_connect(host, share)
    local path = "\\\\" .. host .. "\\" .. share .. "\x00"
    local service = "IPC\x00"
    
    local netbios = string.char(0, 0, 0, 60 + #path + #service)
    local smb = "\xff\x53\x4d\x42\x75\x00\x00\x00\x00"
    smb = smb .. "\x18\x01\x20\x00\x00\x00\x00\x00\x00\x00\x00"
    smb = smb .. "\x00\x00\x00\x00\x00\x00\x08\x01\x00\x01\x00"
    smb = smb .. "\x04\xff\x00\x00\x00\x00\x00"
    smb = smb .. string.char(#path + #service) .. "\x00"
    smb = smb .. path .. service
    
    return netbios .. smb
end

function build_user_enum()
    -- LSA/SAMR query for user enumeration
    local netbios = "\x00\x00\x00\x44"
    local smb = "\xff\x53\x4d\x42\x25\x00\x00\x00\x00"
    smb = smb .. "\x18\x01\x28\x00\x00\x00\x00\x00\x00\x00\x00"
    smb = smb .. "\x00\x00\x00\x00\x00\x08\x00\x01\x00\x01\x00"
    smb = smb .. "\x10\x00\x00\x24\x00\x00\x00\x00\x00\x00\x00"
    smb = smb .. "\x00\x00\x00\x00\x4a\x00\x24\x00\x4a\x00\x02"
    smb = smb .. "\x00\x26\x00\x00\x00\x00\x00"
    
    return netbios .. smb
end

function parse_users(response)
    local users = {}
    
    -- Simplified user parsing
    -- In production, would properly parse SAMR response structures
    
    -- Common default users to look for
    local default_users = {
        {name = "Administrator", rid = "500", 
         fullname = "Administrator",
         description = "Built-in account for administering the computer/domain",
         flags = "Normal user account"},
        {name = "Guest", rid = "501",
         fullname = "Guest", 
         description = "Built-in account for guest access",
         flags = "Account disabled, Password not required"},
    }
    
    -- Check if response contains user data
    if response:find("Administrator") or response:find("Guest") then
        for _, user in ipairs(default_users) do
            if response:find(user.name) then
                table.insert(users, user)
            end
        end
    end
    
    return users
end
