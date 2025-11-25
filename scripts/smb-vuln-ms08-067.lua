-- SMB MS08-067 Vulnerability Detection
-- Detects if a Windows system is vulnerable to MS08-067 (Conficker worm vector)
-- @output
-- 445/tcp open  microsoft-ds
-- | smb-vuln-ms08-067:
-- |   VULNERABLE:
-- |   Microsoft Windows system vulnerable to remote code execution (MS08-067)
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2008-4250
-- |     Risk factor: HIGH  CVSSv2: 10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)
-- |       The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
-- |       Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
-- |       code via a crafted RPC request that triggers the overflow during path canonicalization.
-- |     
-- |     Disclosure date: 2008-10-23
-- |     References:
-- |       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
-- |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250

description = [[
Detects Microsoft Windows systems vulnerable to the MS08-067 vulnerability,
which was exploited by the Conficker worm.

This vulnerability affects the Server service in Windows 2000, XP, 2003, Vista, and Server 2008.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "safe", "default"}

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
    
    -- Check OS version from SMB response
    local os_version = parse_os_version(response)
    
    -- Session Setup
    local session = build_session_setup()
    status = socket:send(session)
    if not status then
        socket:close()
        return nil
    end
    
    status, response = socket:receive()
    socket:close()
    
    if not status then
        return nil
    end
    
    -- Check for vulnerable Windows versions
    local vulnerable = false
    local vuln_info = ""
    
    if os_version then
        local os_lower = os_version:lower()
        
        -- Windows 2000, XP, 2003, Vista (pre-patch) are vulnerable
        if os_lower:find("windows 2000") or
           os_lower:find("windows xp") or
           os_lower:find("windows 2003") or
           (os_lower:find("windows vista") and not os_lower:find("sp2")) or
           (os_lower:find("windows server 2008") and not os_lower:find("sp2")) then
            vulnerable = true
            vuln_info = "OS: " .. os_version
        end
    end
    
    if vulnerable then
        local result = "VULNERABLE:\n"
        result = result .. "Microsoft Windows system vulnerable to remote code execution (MS08-067)\n"
        result = result .. "  State: VULNERABLE\n"
        result = result .. "  IDs:  CVE:CVE-2008-4250\n"
        result = result .. "  Risk factor: HIGH  CVSSv2: 10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)\n"
        result = result .. "    The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,\n"
        result = result .. "    Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary\n"
        result = result .. "    code via a crafted RPC request that triggers the overflow during path canonicalization.\n"
        result = result .. "  \n"
        if vuln_info ~= "" then
            result = result .. "  " .. vuln_info .. "\n"
        end
        result = result .. "  Disclosure date: 2008-10-23\n"
        result = result .. "  References:\n"
        result = result .. "    https://technet.microsoft.com/en-us/library/security/ms08-067.aspx\n"
        result = result .. "    https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250"
        return result
    end
    
    return "Not vulnerable (patched or unsupported OS version)"
end

function build_smb_negotiate()
    local netbios = "\x00\x00\x00\x85"
    local smb = "\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8"
    smb = smb .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff"
    smb = smb .. "\x00\x00\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43"
    smb = smb .. "\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f"
    smb = smb .. "\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41"
    smb = smb .. "\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e"
    smb = smb .. "\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72"
    smb = smb .. "\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61"
    smb = smb .. "\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00"
    smb = smb .. "\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02"
    smb = smb .. "\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
    return netbios .. smb
end

function build_session_setup()
    local netbios = "\x00\x00\x00\x48"
    local smb = "\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x18\x07\xc0"
    smb = smb .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    smb = smb .. "\x00\x08\x01\x00\x00\x00\x0d\xff\x00\x00\x00\xff"
    smb = smb .. "\xff\x02\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"
    smb = smb .. "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00"
    smb = smb .. "\x00\x00\x00"
    return netbios .. smb
end

function parse_os_version(response)
    -- Extract OS string from SMB negotiate response
    -- Simplified parsing
    if response:find("Windows") then
        local start_pos = response:find("Windows")
        if start_pos then
            local os_str = response:sub(start_pos, start_pos + 50)
            local null_pos = os_str:find("\x00")
            if null_pos then
                return os_str:sub(1, null_pos - 1)
            end
        end
    end
    return nil
end
