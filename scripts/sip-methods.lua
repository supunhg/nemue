local nmap = require("nmap")
local stdnse = require("stdnse")
local bin = require("bin")

description = [[
Enumerates supported SIP methods by sending OPTIONS requests
and analyzing the Allow header in responses.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "udp" and
           (port.number == 5060 or port.number == 5061 or port.service == "sip")
end

action = function(host, port)
    local output = {}
    local issues = {}

    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host, port, "udp")
    if not status then
        return stdnse.format_output(false, "Could not connect: " .. err)
    end

    local sip_options = "OPTIONS sip:" .. host.ip .. " SIP/2.0\r\n" ..
        "Via: SIP/2.0/UDP " .. host.ip .. ";branch=z9hG4bK-test\r\n" ..
        "From: <sip:test@" .. host.ip .. ">;tag=test\r\n" ..
        "To: <sip:" .. host.ip .. ">\r\n" ..
        "Call-ID: test@" .. host.ip .. "\r\n" ..
        "CSeq: 1 OPTIONS\r\n" ..
        "Contact: <sip:test@" .. host.ip .. ">\r\n" ..
        "Content-Length: 0\r\n\r\n"

    status = socket:send(sip_options)
    if not status then
        socket:close()
        return stdnse.format_output(false, "Failed to send SIP OPTIONS")
    end

    local response
    status, response = socket:receive()
    socket:close()

    if not status or not response then
        return stdnse.format_output(false, "No SIP response received")
    end

    table.insert(output, "SIP Server Response:")

    local status_line = response:match("^([^\r\n]+)")
    if status_line then
        table.insert(output, "  Status: " .. status_line)
    end

    local allow = response:match("Allow:%s*([^\r\n]+)")
    if allow then
        table.insert(output, "  Allowed Methods: " .. allow)

        local dangerous = {"REGISTER", "SUBSCRIBE", "NOTIFY", "PUBLISH"}
        for _, method in ipairs(dangerous) do
            if allow:upper():find(method) then
                table.insert(issues, "Potentially dangerous method: " .. method)
            end
        end
    else
        table.insert(output, "  No Allow header found")
    end

    local server = response:match("Server:%s*([^\r\n]+)")
    if server then
        table.insert(output, "  Server: " .. server)
    end

    if #issues > 0 then
        table.insert(output, "\nIssues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    end

    return stdnse.format_output(true, output)
end
