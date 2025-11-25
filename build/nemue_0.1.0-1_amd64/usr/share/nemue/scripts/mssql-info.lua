-- Microsoft SQL Server Information
-- Retrieves MS SQL Server version and instance information
-- @output
-- 1433/tcp open  ms-sql-s
-- | mssql-info:
-- |   Instance: MSSQLSERVER
-- |   Version: Microsoft SQL Server 2019 (RTM) - 15.0.2000.5
-- |   Named Pipes: Enabled
-- |_  TCP Port: 1433

description = [[
Connects to Microsoft SQL Server and retrieves version information,
instance name, and configuration details.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe", "default"}

portrule = function(host, port)
    return port.number == 1433 or port.service == "ms-sql-s"
end

action = function(host, port)
    local socket = nse.new_socket()
    socket:set_timeout(5000)
    
    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end
    
    -- SQL Server Browser probe (UDP 1434)
    local browser_socket = nse.new_socket("udp")
    browser_socket:set_timeout(3000)
    
    local browser_info = nil
    if browser_socket:connect(host.ip, 1434) then
        -- CLNT_UCAST_EX request
        browser_socket:send("\x03")
        local status, response = browser_socket:receive()
        if status and response then
            browser_info = parse_browser_response(response)
        end
        browser_socket:close()
    end
    
    -- TDS Pre-Login packet
    local prelogin = build_tds_prelogin()
    status, err = socket:send(prelogin)
    if not status then
        socket:close()
        return nil
    end
    
    local status, response = socket:receive()
    socket:close()
    
    if not status or not response then
        return nil
    end
    
    local results = {}
    
    -- Parse TDS response
    if browser_info then
        if browser_info.InstanceName then
            table.insert(results, "Instance: " .. browser_info.InstanceName)
        end
        if browser_info.Version then
            table.insert(results, "Version: Microsoft SQL Server " .. browser_info.Version)
        end
        if browser_info.tcp then
            table.insert(results, "TCP Port: " .. browser_info.tcp)
        end
        if browser_info.np then
            table.insert(results, "Named Pipes: Enabled")
        end
    else
        -- Parse from TDS response
        local version = parse_tds_version(response)
        if version then
            table.insert(results, "Version: " .. version)
        end
        table.insert(results, "TCP Port: " .. port.number)
    end
    
    if #results > 0 then
        return table.concat(results, "\n")
    end
    
    return "MS SQL Server detected"
end

-- Build TDS Pre-Login packet
function build_tds_prelogin()
    -- TDS 7.4 Pre-Login packet
    local packet = "\x12\x01"  -- Type: Pre-Login, Status
    packet = packet .. "\x00\x2f"  -- Length
    packet = packet .. "\x00\x00"  -- SPID
    packet = packet .. "\x00\x00"  -- Packet ID
    packet = packet .. "\x00"      -- Window
    
    -- Pre-Login options
    packet = packet .. "\x00\x00\x1a\x00\x06"  -- VERSION
    packet = packet .. "\x01\x00\x20\x00\x01"  -- ENCRYPTION
    packet = packet .. "\x02\x00\x21\x00\x01"  -- INSTOPT
    packet = packet .. "\x03\x00\x22\x00\x00"  -- THREADID
    packet = packet .. "\xff"                  -- TERMINATOR
    
    -- Version data (SQL Server 2019)
    packet = packet .. "\x0f\x00\x07\xd0\x00\x00"
    packet = packet .. "\x00"  -- Encryption: ENCRYPT_NOT_SUP
    packet = packet .. "\x00"  -- Instance option
    
    return packet
end

-- Parse SQL Server Browser response
function parse_browser_response(response)
    local info = {}
    
    -- Parse key=value pairs
    for key, value in response:gmatch("([^;]+)=([^;]+)") do
        if key == "InstanceName" then
            info.InstanceName = value
        elseif key == "Version" then
            info.Version = value
        elseif key == "tcp" then
            info.tcp = value
        elseif key == "np" then
            info.np = value
        end
    end
    
    return info
end

-- Parse TDS version from response
function parse_tds_version(response)
    -- Look for version bytes in TDS response
    if #response > 20 then
        local major = string.byte(response, 21)
        local minor = string.byte(response, 22)
        if major and minor then
            return string.format("2019 (15.%d.%d)", major, minor)
        end
    end
    return nil
end
