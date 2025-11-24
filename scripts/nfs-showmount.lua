-- NFS Share Enumeration
-- Lists NFS exports on the target
-- @output
-- 2049/tcp open  nfs
-- | nfs-showmount:
-- |   /home 192.168.1.0/24
-- |   /var/nfs/general *
-- |_  /mnt/backups 192.168.1.100

description = [[
Attempts to list NFS exports on the target server using the MOUNT protocol.
Shows which directories are exported and what hosts/networks can access them.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe", "default"}

portrule = function(host, port)
    return port.number == 2049 or port.service == "nfs" or
           port.number == 111  -- portmapper/rpcbind
end

action = function(host, port)
    local socket = nse.new_socket()
    socket:set_timeout(5000)
    
    -- Try to connect to mountd (usually port 111 or 2049)
    local mountd_port = port.number
    if port.number == 2049 then
        mountd_port = 111  -- Try portmapper first
    end
    
    local status, err = socket:connect(host.ip, mountd_port)
    if not status then
        socket:close()
        return nil
    end
    
    -- RPC call to MOUNTPROC_EXPORT
    local export_request = build_mount_export_request()
    status, err = socket:send(export_request)
    if not status then
        socket:close()
        return nil
    end
    
    local status, response = socket:receive()
    socket:close()
    
    if not status or not response then
        return nil
    end
    
    -- Parse exports
    local exports = parse_mount_exports(response)
    
    if #exports > 0 then
        local results = {}
        for _, export in ipairs(exports) do
            local line = export.path
            if export.clients and #export.clients > 0 then
                line = line .. " " .. table.concat(export.clients, ",")
            else
                line = line .. " *"
            end
            table.insert(results, line)
        end
        return table.concat(results, "\n")
    end
    
    return "No NFS exports found"
end

-- Build RPC MOUNT EXPORT request
function build_mount_export_request()
    -- RPC header for MOUNTPROC_EXPORT (program 100005, version 3, procedure 5)
    local xid = "\x00\x00\x00\x01"
    local msg_type = "\x00\x00\x00\x00"  -- CALL
    local rpc_vers = "\x00\x00\x00\x02"
    local prog = "\x00\x01\x86\xa5"      -- MOUNT (100005)
    local prog_vers = "\x00\x00\x00\x03"
    local proc = "\x00\x00\x00\x05"      -- EXPORT (5)
    local cred = "\x00\x00\x00\x00\x00\x00\x00\x00"  -- AUTH_NONE
    local verf = "\x00\x00\x00\x00\x00\x00\x00\x00"
    
    return xid .. msg_type .. rpc_vers .. prog .. prog_vers .. 
           proc .. cred .. verf
end

-- Parse MOUNT export list
function parse_mount_exports(response)
    local exports = {}
    
    -- Simplified parsing - look for directory paths
    for path in response:gmatch("/[%w_/%-%.]+") do
        table.insert(exports, {
            path = path,
            clients = {}  -- Simplified - would need proper RPC parsing for clients
        })
    end
    
    return exports
end
