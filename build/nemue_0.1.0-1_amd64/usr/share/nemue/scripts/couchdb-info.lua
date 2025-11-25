-- CouchDB Information
-- Retrieves CouchDB version and database list
-- @output
-- 5984/tcp open  couchdb
-- | couchdb-info:
-- |   Version: 3.2.1
-- |   Vendor: The Apache Software Foundation
-- |   Databases:
-- |     _replicator
-- |     _users
-- |_    mydb

description = [[
Connects to CouchDB HTTP API and retrieves version information
and list of accessible databases.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe", "default"}

portrule = function(host, port)
    return port.number == 5984 or port.number == 6984 or 
           port.service == "couchdb"
end

action = function(host, port)
    local socket = nse.new_socket()
    socket:set_timeout(5000)
    
    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end
    
    -- HTTP GET / (server info)
    local request = "GET / HTTP/1.1\r\n"
    request = request .. "Host: " .. host.ip .. "\r\n"
    request = request .. "Connection: close\r\n"
    request = request .. "\r\n"
    
    status, err = socket:send(request)
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
    
    -- Parse JSON response
    local version = response:match('"version"%s*:%s*"([^"]+)"')
    if version then
        table.insert(results, "Version: " .. version)
    end
    
    local vendor = response:match('"vendor"%s*:%s*{[^}]*"name"%s*:%s*"([^"]+)"')
    if vendor then
        table.insert(results, "Vendor: " .. vendor)
    end
    
    local uuid = response:match('"uuid"%s*:%s*"([^"]+)"')
    if uuid then
        table.insert(results, "UUID: " .. uuid)
    end
    
    -- Get database list
    socket = nse.new_socket()
    socket:set_timeout(3000)
    
    if socket:connect(host.ip, port.number) then
        local db_request = "GET /_all_dbs HTTP/1.1\r\n"
        db_request = db_request .. "Host: " .. host.ip .. "\r\n"
        db_request = db_request .. "Connection: close\r\n\r\n"
        
        socket:send(db_request)
        local status, db_response = socket:receive()
        socket:close()
        
        if status and db_response then
            -- Parse database names from JSON array
            local dbs = {}
            for db in db_response:gmatch('"([^"]+)"') do
                table.insert(dbs, db)
            end
            
            if #dbs > 0 then
                table.insert(results, "Databases:")
                for _, db in ipairs(dbs) do
                    table.insert(results, "  " .. db)
                end
            end
        end
    end
    
    if #results > 0 then
        return table.concat(results, "\n")
    end
    
    return "CouchDB server detected"
end
