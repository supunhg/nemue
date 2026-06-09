local nmap = require("nmap")
local stdnse = require("stdnse")
local bin = require("bin")

description = [[
Checks RDP server encryption level and supported security protocols.
Detects weak encryption configurations that could expose RDP sessions.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 3389 or port.service == "ms-wbt-server")
end

action = function(host, port)
    local output = {}
    local issues = {}

    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host, port)
    if not status then
        return stdnse.format_output(false, "Could not connect: " .. err)
    end

    local x224_conn = bin.pack("H", "030000130e" ..
        "e00000000000436f6f6b69653a" ..
        "206d737473686173683d" ..
        "746573740d0a")

    status = socket:send(x224_conn)
    if not status then
        socket:close()
        return stdnse.format_output(false, "Failed to send connection request")
    end

    local response
    status, response = socket:receive()
    socket:close()

    if not status or not response then
        return stdnse.format_output(false, "No RDP response received")
    end

    table.insert(output, "RDP Encryption Check:")

    if #response >= 12 then
        local proto = string.byte(response, 6)
        if proto then
            if proto == 0x01 then
                table.insert(output, "  Protocol: Standard RDP Security")
                table.insert(issues, "Using legacy RDP security protocol")
            elseif proto == 0x02 then
                table.insert(output, "  Protocol: Enhanced Security (TLS)")
            elseif proto == 0x03 then
                table.insert(output, "  Protocol: CredSSP/NLA")
                table.insert(output, "  NLA: Enabled (recommended)")
            end
        end
    end

    table.insert(output, "\nRecommendations:")
    table.insert(output, "  - Use Network Level Authentication (NLA)")
    table.insert(output, "  - Enforce TLS 1.2+ encryption")
    table.insert(output, "  - Disable legacy RDP security")

    if #issues > 0 then
        table.insert(output, "\nIssues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    end

    return stdnse.format_output(true, output)
end
