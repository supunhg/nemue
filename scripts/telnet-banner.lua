-- Telnet Banner Grabbing
-- Gets telnet banner and identifies OS

local nmap = require("nmap")
local stdnse = require("stdnse")

description = [[
Connects to telnet service and grabs the banner.
Parses the banner for OS indicators and service information.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 23 or port.service == "telnet")
end

action = function(host, port)
    local output = {}

    local socket = nmap.new_socket()
    local status, err = socket:connect(host, port)

    if not status then
        return stdnse.format_output(false, "Could not connect: " .. err)
    end

    local banner_lines = {}
    local timeout = 5000
    socket:set_timeout(timeout)

    for i = 1, 10 do
        local line
        status, line = socket:receive_lines(1)
        if not status then
            break
        end
        if line and #line > 0 then
            table.insert(banner_lines, line)
        end
    end

    socket:close()

    if #banner_lines > 0 then
        table.insert(output, "Telnet Banner:")
        for _, line in ipairs(banner_lines) do
            table.insert(output, "  " .. line)
        end

        local banner_text = table.concat(banner_lines, " "):lower()

        table.insert(output, "\nOS Detection:")
        if banner_text:find("linux") or banner_text:find("ubuntu") or banner_text:find("debian") then
            table.insert(output, "  OS: Linux")
        elseif banner_text:find("windows") or banner_text:find("microsoft") then
            table.insert(output, "  OS: Windows")
        elseif banner_text:find("cisco") then
            table.insert(output, "  OS: Cisco IOS")
        elseif banner_text:find("freebsd") or banner_text:find("openbsd") then
            table.insert(output, "  OS: BSD")
        else
            table.insert(output, "  OS: Unknown")
        end

        if banner_text:find("login:") or banner_text:find("username:") then
            table.insert(output, "  Authentication: Required")
        end
    else
        table.insert(output, "No banner received")
    end

    return stdnse.format_output(true, output)
end
