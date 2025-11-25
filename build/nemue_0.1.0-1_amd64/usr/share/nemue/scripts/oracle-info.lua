-- Oracle Database Information
-- Retrieves Oracle TNS listener version and service information
-- @output
-- 1521/tcp open  oracle-tns
-- | oracle-info:
-- |   TNS Version: Oracle TNSLSNR 19.0.0.0.0
-- |   Services:
-- |     ORCL (DEDICATED)
-- |_    XEPDB1 (DEDICATED)

description = [[
Connects to Oracle TNS listener and retrieves version information
and available database services.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe", "default"}

portrule = function(host, port)
    return port.number == 1521 or port.service == "oracle-tns"
end

action = function(host, port)
    local socket = nse.new_socket()
    socket:set_timeout(5000)
    
    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end
    
    -- TNS CONNECT packet to get version
    local connect_packet = build_tns_connect()
    status, err = socket:send(connect_packet)
    if not status then
        socket:close()
        return nil
    end
    
    local status, response = socket:receive()
    if not status or not response then
        socket:close()
        return nil
    end
    
    local results = {}
    
    -- Parse TNS version from response
    local version = parse_tns_version(response)
    if version then
        table.insert(results, "TNS Version: " .. version)
    end
    
    -- Try to enumerate services
    local services = {}
    local service_names = {"ORCL", "XE", "XEPDB1", "PDB1", "ORCLPDB"}
    
    for _, service in ipairs(service_names) do
        socket:close()
        socket = nse.new_socket()
        socket:set_timeout(3000)
        
        if socket:connect(host.ip, port.number) then
            local service_packet = build_tns_service_request(service)
            socket:send(service_packet)
            local status, resp = socket:receive()
            
            if status and resp and not resp:find("TNS%-12154") then
                table.insert(services, service .. " (DEDICATED)")
            end
        end
    end
    
    if #services > 0 then
        table.insert(results, "Services:")
        for _, svc in ipairs(services) do
            table.insert(results, "  " .. svc)
        end
    end
    
    socket:close()
    
    if #results > 0 then
        return table.concat(results, "\n")
    end
    
    return nil
end

-- Build TNS CONNECT packet
function build_tns_connect()
    -- Simplified TNS CONNECT packet
    local packet = "\x00\x3a"  -- Packet length (58)
    packet = packet .. "\x00\x00\x01\x00\x00\x00"  -- TNS header
    packet = packet .. "\x01\x37\x01\x2c\x00\x00\x08\x00\x7f\xff"
    packet = packet .. "\xa3\x0a\x00\x00\x01\x00"
    packet = packet .. "\x00\x1d\x00\x3a\x00\x00\x00\x00\x00\x00"
    packet = packet .. "\x00\x00\x00\x00\x00\x00"
    packet = packet .. "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=)))"
    
    return packet
end

-- Build TNS service request
function build_tns_service_request(service_name)
    local connect_desc = "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=" .. 
                        service_name .. ")))"
    local packet_len = 58 + #connect_desc
    
    local packet = string.char(math.floor(packet_len / 256), packet_len % 256)
    packet = packet .. "\x00\x00\x01\x00\x00\x00"
    packet = packet .. connect_desc
    
    return packet
end

-- Parse TNS version from response
function parse_tns_version(response)
    -- Look for version string
    local version = response:match("TNSLSNR for [^:]+: Version ([%d%.]+)")
    if not version then
        version = response:match("Oracle TNSLSNR ([%d%.]+)")
    end
    if version then
        return "Oracle TNSLSNR " .. version
    end
    return nil
end
