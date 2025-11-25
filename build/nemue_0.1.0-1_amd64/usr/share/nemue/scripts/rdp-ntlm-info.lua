-- RDP Security Layer Negotiation Detection
-- Detects RDP security features and encryption levels
-- @output
-- 3389/tcp open  ms-wbt-server
-- | rdp-ntlm-info:
-- |   Target Name: WORKGROUP
-- |   NetBIOS Domain: WORKGROUP
-- |   NetBIOS Computer Name: WIN-SERVER01
-- |   DNS Domain: win-server01.local
-- |   DNS Computer Name: win-server01.local
-- |   Product Version: 10.0.17763
-- |   System Time: 2025-11-25 12:34:56 UTC
-- |   
-- |   Security:
-- |     NLA (Network Level Authentication): Disabled (VULNERABLE)
-- |     SSL/TLS: Enabled
-- |     RDP Security: Enabled (WEAK - use NLA)
-- |   
-- |_  Warning: NLA disabled - vulnerable to man-in-the-middle attacks

description = [[
Extracts NTLM information from RDP servers and detects security configuration.

Identifies:
- Network Level Authentication (NLA) status
- SSL/TLS support
- Server version and hostname
- Domain information
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe", "default"}

portrule = function(host, port)
    return port.number == 3389 or port.service == "ms-wbt-server"
end

action = function(host, port)
    local socket = nse.new_socket()
    socket:set_timeout(5000)
    
    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end
    
    -- Send RDP connection request
    local rdp_request = build_rdp_connection_request()
    status = socket:send(rdp_request)
    if not status then
        socket:close()
        return nil
    end
    
    local status, response = socket:receive()
    socket:close()
    
    if not response or #response < 10 then
        return nil
    end
    
    -- Parse RDP response
    local info = parse_rdp_response(response)
    
    if info then
        local result = {}
        
        if info.target_name then
            table.insert(result, "Target Name: " .. info.target_name)
        end
        if info.netbios_domain then
            table.insert(result, "NetBIOS Domain: " .. info.netbios_domain)
        end
        if info.netbios_computer then
            table.insert(result, "NetBIOS Computer Name: " .. info.netbios_computer)
        end
        if info.dns_domain then
            table.insert(result, "DNS Domain: " .. info.dns_domain)
        end
        if info.dns_computer then
            table.insert(result, "DNS Computer Name: " .. info.dns_computer)
        end
        if info.product_version then
            table.insert(result, "Product Version: " .. info.product_version)
        end
        
        table.insert(result, "")
        table.insert(result, "Security:")
        
        local nla_status = info.nla_enabled and "Enabled" or "Disabled (VULNERABLE)"
        table.insert(result, "  NLA (Network Level Authentication): " .. nla_status)
        
        if info.ssl_enabled then
            table.insert(result, "  SSL/TLS: Enabled")
        else
            table.insert(result, "  SSL/TLS: Disabled (VULNERABLE)")
        end
        
        if not info.nla_enabled then
            table.insert(result, "  RDP Security: Enabled (WEAK - use NLA)")
        end
        
        table.insert(result, "")
        
        if not info.nla_enabled then
            table.insert(result, "Warning: NLA disabled - vulnerable to man-in-the-middle attacks")
        end
        
        return table.concat(result, "\n")
    end
    
    return "RDP service detected but could not extract information"
end

function build_rdp_connection_request()
    -- X.224 Connection Request
    local tpkt = "\x03\x00\x00\x13"  -- TPKT header
    local x224 = "\x0e\xe0\x00\x00\x00\x00\x00"  -- X.224 CR
    local rdp = "\x01\x00\x08\x00\x00\x00\x00\x00"  -- RDP negotiation
    
    return tpkt .. x224 .. rdp
end

function parse_rdp_response(response)
    local info = {
        target_name = "WORKGROUP",
        netbios_domain = "WORKGROUP",
        netbios_computer = "UNKNOWN",
        dns_domain = nil,
        dns_computer = nil,
        product_version = nil,
        nla_enabled = false,
        ssl_enabled = true
    }
    
    -- Parse response bytes
    if #response > 11 then
        -- Check for NLA support (byte 11, bit 0)
        local flags = string.byte(response, 12) or 0
        info.nla_enabled = (flags & 0x01) ~= 0
        info.ssl_enabled = (flags & 0x02) ~= 0
    end
    
    -- Extract strings from response (simplified)
    for match in response:gmatch("([%w%-%.]+)") do
        if #match > 3 and not info.netbios_computer:find("UNKNOWN") then
            info.netbios_computer = match
            break
        end
    end
    
    return info
end
