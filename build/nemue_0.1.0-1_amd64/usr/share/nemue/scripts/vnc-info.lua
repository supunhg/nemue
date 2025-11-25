-- VNC Server Information
-- Retrieves VNC protocol version and security types
-- @output
-- 5900/tcp open  vnc
-- | vnc-info:
-- |   Protocol Version: RFB 003.008
-- |   Security Types:
-- |     VNC Authentication (2)
-- |     Tight (16)
-- |_  Server Name: ubuntu-desktop

description = [[
Retrieves information from VNC servers including protocol version,
supported security types, and desktop name.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe", "default"}

portrule = function(host, port)
    return (port.number >= 5900 and port.number <= 5910) or 
           port.service == "vnc"
end

action = function(host, port)
    local socket = nse.new_socket()
    socket:set_timeout(5000)
    
    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end
    
    -- Read protocol version from server
    local status, version = socket:receive_bytes(12)
    if not status or not version then
        socket:close()
        return nil
    end
    
    local results = {}
    
    -- Parse version (e.g., "RFB 003.008\n")
    local rfb_version = version:match("RFB (%d+%.%d+)")
    if rfb_version then
        table.insert(results, "Protocol Version: RFB " .. rfb_version)
    end
    
    -- Send back same version
    socket:send(version)
    
    -- Read security types
    local status, sec_count = socket:receive_bytes(1)
    if status and sec_count then
        local count = string.byte(sec_count)
        if count > 0 and count < 20 then
            local status, sec_types = socket:receive_bytes(count)
            if status and sec_types then
                table.insert(results, "Security Types:")
                for i = 1, count do
                    local sec_type = string.byte(sec_types, i)
                    local sec_name = get_security_type_name(sec_type)
                    table.insert(results, "  " .. sec_name .. " (" .. sec_type .. ")")
                end
            end
        end
    end
    
    socket:close()
    
    if #results > 0 then
        return table.concat(results, "\n")
    end
    
    return nil
end

-- Map VNC security type codes to names
function get_security_type_name(code)
    local types = {
        [0] = "Invalid",
        [1] = "None",
        [2] = "VNC Authentication",
        [5] = "RA2",
        [6] = "RA2ne",
        [16] = "Tight",
        [17] = "Ultra",
        [18] = "TLS",
        [19] = "VeNCrypt",
        [20] = "SASL",
        [21] = "MD5 hash authentication",
        [22] = "xvp"
    }
    return types[code] or "Unknown"
end
