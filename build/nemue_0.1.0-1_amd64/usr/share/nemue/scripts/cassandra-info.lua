-- Apache Cassandra Information
-- Retrieves Cassandra cluster and version information
-- @output
-- 9042/tcp open  cassandra
-- | cassandra-info:
-- |   Protocol Version: 4
-- |   CQL Version: 3.4.5
-- |   Cluster Name: Test Cluster
-- |_  Data Center: datacenter1

description = [[
Connects to Apache Cassandra CQL native protocol and retrieves
version information, cluster name, and configuration details.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe", "default"}

portrule = function(host, port)
    return port.number == 9042 or port.service == "cassandra"
end

action = function(host, port)
    local socket = nse.new_socket()
    socket:set_timeout(5000)
    
    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end
    
    -- CQL OPTIONS request
    local options_frame = build_cql_options()
    status, err = socket:send(options_frame)
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
    
    -- Parse CQL response
    if #response > 8 then
        local version = string.byte(response, 1)
        table.insert(results, "Protocol Version: " .. (version & 0x7F))
        
        -- Parse SUPPORTED options
        if response:find("CQL_VERSION") then
            local cql_version = response:match("CQL_VERSION.-%[([%d%.]+)%]")
            if cql_version then
                table.insert(results, "CQL Version: " .. cql_version)
            end
        end
    end
    
    -- Try to get system information
    socket:close()
    socket = nse.new_socket()
    socket:set_timeout(3000)
    
    if socket:connect(host.ip, port.number) then
        -- Query system.local table
        local query_frame = build_cql_query("SELECT cluster_name, data_center FROM system.local")
        socket:send(query_frame)
        
        local status, resp = socket:receive()
        if status and resp then
            local cluster_name = resp:match("cluster_name[^%w]*([%w%s]+)")
            if cluster_name then
                table.insert(results, "Cluster Name: " .. cluster_name:gsub("%s+$", ""))
            end
            
            local datacenter = resp:match("data_center[^%w]*([%w]+)")
            if datacenter then
                table.insert(results, "Data Center: " .. datacenter)
            end
        end
    end
    
    socket:close()
    
    if #results > 0 then
        return table.concat(results, "\n")
    end
    
    return "Cassandra server detected"
end

-- Build CQL OPTIONS frame
function build_cql_options()
    -- CQL binary protocol v4 OPTIONS frame
    local frame = "\x04"  -- Version 4
    frame = frame .. "\x00"  -- Flags
    frame = frame .. "\x00\x00"  -- Stream ID
    frame = frame .. "\x05"  -- Opcode: OPTIONS
    frame = frame .. "\x00\x00\x00\x00"  -- Length: 0
    
    return frame
end

-- Build CQL QUERY frame
function build_cql_query(query)
    local frame = "\x04\x00\x00\x00\x07"  -- Version 4, Flags 0, Stream 0, Opcode QUERY
    
    -- Query string (long string: 4-byte length + data)
    local query_len = string.pack(">I4", #query)
    local body = query_len .. query
    
    -- Consistency level (ONE = 0x0001)
    body = body .. "\x00\x01"
    
    -- Flags (no values)
    body = body .. "\x00"
    
    -- Body length
    local body_len = string.pack(">I4", #body)
    frame = frame .. body_len .. body
    
    return frame
end
