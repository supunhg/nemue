-- FTP Banner Grabbing
-- Retrieves and analyzes FTP server banners for version info

local nmap = require("nmap")
local stdnse = require("stdnse")

description = [[
Connects to an FTP server and grabs the banner, then sends
additional commands (HELP, SYST) to gather more information
about the server software and capabilities.
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
        table.insert(output, "Banner: " .. banner)

        if banner:match("vsftpd") then
            local ver = banner:match("vsftpd (.+)")
            table.insert(output, "Server: vsftpd " .. (ver or "unknown"))
            if ver and ver == "2.3.4" then
                table.insert(output, "WARNING: vsftpd 2.3.4 backdoor (CVE-2011-2523)")
            end
        elseif banner:match("ProFTPD") then
            table.insert(output, "Server: ProFTPD")
            if banner:match("1%.3%.[0-5]") then
                table.insert(output, "WARNING: Old ProFTPD version may have known vulnerabilities")
            end
        elseif banner:match("Pure%-FTPd") then
            table.insert(output, "Server: Pure-FTPd")
        elseif banner:match("FileZilla") then
            table.insert(output, "Server: FileZilla Server")
        elseif banner:match("WU%-FTPD") or banner:match("wuftpd") then
            table.insert(output, "Server: WU-FTPD")
            table.insert(output, "WARNING: WU-FTPD has multiple known vulnerabilities")
        end
    end

    socket:send("SYST\r\n")
    local syst
    status, syst = socket:receive_lines(1)
    if status and syst then
        table.insert(output, "System: " .. syst)
    end

    socket:send("HELP\r\n")
    local help_lines = {}
    local line
    while true do
        status, line = socket:receive_lines(1)
        if not status then break end
        table.insert(help_lines, line)
        if line:match("^214 ") or line:match("^211 ") then break end
    end

    if #help_lines > 0 then
        table.insert(output, "\nHelp response:")
        for _, l in ipairs(help_lines) do
            table.insert(output, "  " .. l)
        end
    end

    socket:close()

    return stdnse.format_output(true, output)
end
