-- FTP Version Detection
-- Gets detailed FTP server version and OS info

local nmap = require("nmap")
local stdnse = require("stdnse")

description = [[
Connects to FTP server and retrieves detailed version information
by reading the banner, sending SYST and FEAT commands.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 21 or port.service == "ftp")
end

action = function(host, port)
    local output = {}

    local socket = nmap.new_socket()
    local status, err = socket:connect(host, port)

    if not status then
        return stdnse.format_output(false, "Could not connect: " .. err)
    end

    local banner
    status, banner = socket:receive_lines(1)
    if status and banner then
        table.insert(output, "FTP Banner: " .. banner)
    end

    socket:send("SYST\r\n")
    local syst_resp
    status, syst_resp = socket:receive_lines(1)
    if status and syst_resp then
        table.insert(output, "System Type: " .. syst_resp)
    end

    socket:send("FEAT\r\n")
    local feat_lines = {}
    local line
    while true do
        status, line = socket:receive_lines(1)
        if not status or line:sub(1, 1) == " " or line == "211 End" then
            break
        end
        table.insert(feat_lines, line)
    end

    if #feat_lines > 0 then
        table.insert(output, "\nSupported Features:")
        for _, feat in ipairs(feat_lines) do
            table.insert(output, "  " .. feat)
        end
    end

    socket:close()

    return stdnse.format_output(true, output)
end
