-- SNMP Information Enumeration
-- Attempts to enumerate SNMP information (sysDescr, sysName, sysUptime)
-- @output
-- 161/udp open  snmp
-- | snmp-info:
-- |   System Description: Linux ubuntu 5.15.0-91-generic
-- |   System Name: ubuntu-server
-- |   System Uptime: 14 days, 3:45:12
-- |   System Contact: admin@example.com
-- |_  System Location: Data Center Rack A3

description = [[
Attempts to enumerate basic SNMP information including system description,
name, uptime, contact information, and location using SNMPv1/v2c with
common community strings.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe", "default"}

-- Check if SNMP port is open
portrule = function(host, port)
    return port.number == 161 and port.protocol == "udp"
end

-- Common SNMP community strings to try
local communities = {"public", "private", "community", "snmp"}

-- SNMP OIDs for system information
local oids = {
    sysDescr = "1.3.6.1.2.1.1.1.0",
    sysObjectID = "1.3.6.1.2.1.1.2.0",
    sysUptime = "1.3.6.1.2.1.1.3.0",
    sysContact = "1.3.6.1.2.1.1.4.0",
    sysName = "1.3.6.1.2.1.1.5.0",
    sysLocation = "1.3.6.1.2.1.1.6.0",
}

action = function(host, port)
    local socket = nse.new_socket("udp")
    socket:set_timeout(5000)
    
    local results = {}
    local found_community = nil
    
    -- Try each community string
    for _, community in ipairs(communities) do
        -- Build SNMP GET request for sysDescr
        local request = build_snmp_get(community, oids.sysDescr)
        
        local status, err = socket:connect(host.ip, port.number)
        if not status then
            return nil
        end
        
        status, err = socket:send(request)
        if not status then
            socket:close()
            return nil
        end
        
        local status, response = socket:receive()
        socket:close()
        
        if status and response and #response > 0 then
            -- Found working community string
            found_community = community
            table.insert(results, "Community String: " .. community)
            break
        end
    end
    
    if not found_community then
        return "Could not enumerate SNMP (community string required)"
    end
    
    -- Query all OIDs with working community
    for name, oid in pairs(oids) do
        local socket = nse.new_socket("udp")
        socket:set_timeout(3000)
        
        local request = build_snmp_get(found_community, oid)
        
        if socket:connect(host.ip, port.number) then
            socket:send(request)
            local status, response = socket:receive()
            socket:close()
            
            if status and response then
                local value = parse_snmp_response(response)
                if value and #value > 0 then
                    if name == "sysDescr" then
                        table.insert(results, "System Description: " .. value)
                    elseif name == "sysName" then
                        table.insert(results, "System Name: " .. value)
                    elseif name == "sysUptime" then
                        table.insert(results, "System Uptime: " .. format_uptime(value))
                    elseif name == "sysContact" then
                        table.insert(results, "System Contact: " .. value)
                    elseif name == "sysLocation" then
                        table.insert(results, "System Location: " .. value)
                    end
                end
            end
        end
    end
    
    if #results > 0 then
        return table.concat(results, "\n")
    end
    
    return nil
end

-- Build SNMP GET request (simplified)
function build_snmp_get(community, oid)
    -- Simplified SNMP v1 GET request builder
    -- In production, use proper ASN.1 BER encoding
    local version = "\x02\x01\x00"  -- SNMP version 1
    local comm = "\x04" .. string.char(#community) .. community
    local pdu_type = "\xa0"  -- GET request
    
    return "\x30\x29" .. version .. comm .. pdu_type .. "\x1c" ..
           "\x02\x04\x00\x00\x00\x01" ..  -- Request ID
           "\x02\x01\x00" ..               -- Error status
           "\x02\x01\x00"                  -- Error index
end

-- Parse SNMP response (simplified)
function parse_snmp_response(response)
    -- Simplified parser - extract printable strings
    local value = response:match("[\x20-\x7e]+")
    return value or ""
end

-- Format uptime from timeticks
function format_uptime(ticks)
    local num = tonumber(ticks) or 0
    local seconds = math.floor(num / 100)
    
    local days = math.floor(seconds / 86400)
    seconds = seconds % 86400
    local hours = math.floor(seconds / 3600)
    seconds = seconds % 3600
    local minutes = math.floor(seconds / 60)
    seconds = seconds % 60
    
    return string.format("%d days, %d:%02d:%02d", days, hours, minutes, seconds)
end
