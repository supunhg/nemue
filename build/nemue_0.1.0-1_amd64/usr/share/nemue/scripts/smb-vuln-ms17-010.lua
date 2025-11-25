-- SMB EternalBlue Vulnerability Detection (MS17-010)
-- Detects if a Windows system is vulnerable to EternalBlue exploit
-- @output
-- 445/tcp open  microsoft-ds
-- | smb-vuln-ms17-010:
-- |   VULNERABLE:
-- |   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2017-0143  CVE:CVE-2017-0144  CVE:CVE-2017-0145
-- |     Risk factor: HIGH  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
-- |       A critical remote code execution vulnerability exists in Microsoft SMBv1
-- |       servers (ms17-010).
-- |     
-- |     Disclosure date: 2017-03-14
-- |     References:
-- |       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
-- |_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

description = [[
Attempts to detect if a Windows system is vulnerable to the EternalBlue exploit (MS17-010).
This vulnerability affects SMBv1 and was used by the WannaCry ransomware.

The script sends a specially crafted SMB request to check if the system is patched.
Does NOT exploit the vulnerability.
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
    
    -- SMB Negotiate Protocol Request
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
    
    -- Check if SMBv1 is supported
    if not response:find("SMB") then
        socket:close()
        return "SMBv1 not supported (not vulnerable)"
    end
    
    -- Send MS17-010 probe packet
    local probe = build_ms17010_probe()
    status, err = socket:send(probe)
    if not status then
        socket:close()
        return nil
    end
    
    status, response = socket:receive()
    socket:close()
    
    if not status or not response then
        return nil
    end
    
    -- Check response for vulnerability indicators
    local vulnerable = false
    local status_code = nil
    
    if #response > 35 then
        -- Extract NT Status code (offset 0x09-0x0C in SMB header)
        local b1 = string.byte(response, 10) or 0
        local b2 = string.byte(response, 11) or 0
        local b3 = string.byte(response, 12) or 0
        local b4 = string.byte(response, 13) or 0
        
        status_code = b1 + (b2 * 256) + (b3 * 65536) + (b4 * 16777216)
        
        -- STATUS_INSUFF_SERVER_RESOURCES (0xC0000205) or 
        -- STATUS_NOT_SUPPORTED (0xC00000BB) indicates vulnerability
        if status_code == 0xC0000205 or status_code == 0x00000000 then
            vulnerable = true
        end
    end
    
    if vulnerable then
        local result = "VULNERABLE:\n"
        result = result .. "Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)\n"
        result = result .. "  State: VULNERABLE\n"
        result = result .. "  IDs:  CVE:CVE-2017-0143  CVE:CVE-2017-0144  CVE:CVE-2017-0145\n"
        result = result .. "  Risk factor: HIGH  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)\n"
        result = result .. "    A critical remote code execution vulnerability exists in Microsoft SMBv1\n"
        result = result .. "    servers (ms17-010).\n"
        result = result .. "  \n"
        result = result .. "  Disclosure date: 2017-03-14\n"
        result = result .. "  References:\n"
        result = result .. "    https://technet.microsoft.com/en-us/library/security/ms17-010.aspx\n"
        result = result .. "    https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/"
        return result
    end
    
    return "Not vulnerable (patched or SMBv1 disabled)"
end

-- Build SMB Negotiate Protocol Request
function build_smb_negotiate()
    local netbios = "\x00\x00\x00\x85"  -- NetBIOS Session Service
    
    local smb_header = "\xff\x53\x4d\x42"  -- SMB magic
    smb_header = smb_header .. "\x72"      -- SMB_COM_NEGOTIATE
    smb_header = smb_header .. "\x00\x00\x00\x00"  -- NT Status
    smb_header = smb_header .. "\x18"      -- Flags
    smb_header = smb_header .. "\x53\xc8"  -- Flags2
    smb_header = smb_header .. "\x00\x00"  -- PID High
    smb_header = smb_header .. "\x00\x00\x00\x00\x00\x00\x00\x00"  -- Signature
    smb_header = smb_header .. "\x00\x00"  -- Reserved
    smb_header = smb_header .. "\xff\xff"  -- TID
    smb_header = smb_header .. "\x00\x00"  -- PID
    smb_header = smb_header .. "\x00\x00"  -- UID
    smb_header = smb_header .. "\x00\x00"  -- MID
    
    -- Negotiate Protocol Request
    local negotiate_data = "\x00"      -- Word Count
    negotiate_data = negotiate_data .. "\x62\x00"  -- Byte Count
    negotiate_data = negotiate_data .. "\x02"      -- Dialect: PC NETWORK PROGRAM 1.0
    negotiate_data = negotiate_data .. "PC NETWORK PROGRAM 1.0\x00"
    negotiate_data = negotiate_data .. "\x02NT LM 0.12\x00"  -- NT LM 0.12 dialect
    
    return netbios .. smb_header .. negotiate_data
end

-- Build MS17-010 probe packet
function build_ms17010_probe()
    local netbios = "\x00\x00\x00\xa4"
    
    local smb_header = "\xff\x53\x4d\x42"  -- SMB magic
    smb_header = smb_header .. "\x2f"      -- SMB_COM_TRANSACTION (0x25 or 0x2f)
    smb_header = smb_header .. "\x00\x00\x00\x00"
    smb_header = smb_header .. "\x18"
    smb_header = smb_header .. "\x07\xc0"
    smb_header = smb_header .. "\x00\x00"
    smb_header = smb_header .. "\x00\x00\x00\x00\x00\x00\x00\x00"
    smb_header = smb_header .. "\x00\x00"
    smb_header = smb_header .. "\xff\xff"
    smb_header = smb_header .. "\x00\x00"
    smb_header = smb_header .. "\x40\x00"
    smb_header = smb_header .. "\x00\x00"
    
    -- Trans2 request with specific parameters to trigger vuln
    local trans_params = "\x10\x00\x00\x48\x00\x00\x00\x00"
    trans_params = trans_params .. "\x00\x00\x00\x00\x00\x00\x00\x00"
    trans_params = trans_params .. "\x00\x00\x00\x00\x00\x00\x00\x00"
    trans_params = trans_params .. "\x00\x00\x4a\x00\x48\x00\x4a\x00"
    trans_params = trans_params .. "\x02\x00\x26\x00\x00\x40\x5c\x00"
    trans_params = trans_params .. "\x50\x00\x49\x00\x50\x00\x45\x00"
    trans_params = trans_params .. "\x5c\x00\x00\x00\x05\x00\x0b\x03"
    trans_params = trans_params .. "\x10\x00\x00\x00\x48\x00\x00\x00"
    trans_params = trans_params .. "\x00\x00\x00\x00\xd0\x16\xd0\x16"
    trans_params = trans_params .. "\x00\x00\x00\x00\x01\x00\x00\x00"
    trans_params = trans_params .. "\x00\x00\x01\x00"
    
    return netbios .. smb_header .. trans_params
end
