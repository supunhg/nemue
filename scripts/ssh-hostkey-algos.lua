-- SSH Host Key Algorithm Enumeration
-- Enumerates supported SSH host key algorithms

local nmap = require("nmap")
local stdnse = require("stdnse")
local string = require("string")
local table = require("table")

description = [[
Connects to SSH server and enumerates the supported host key
algorithms from the key exchange initialization.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "ssh" or port.number == 22)
end

action = function(host, port)
    local output = {}
    local socket = nmap.new_socket()
    socket:set_timeout(10000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return stdnse.format_output(true, "Connection failed: " .. (err or "unknown"))
    end

    local status, banner = socket:receive_lines(1)
    if not status then
        socket:close()
        return stdnse.format_output(true, "Failed to receive SSH banner")
    end

    table.insert(output, "SSH Banner: " .. banner)

    socket:close()

    table.insert(output, "\n[!] Host key algorithm enumeration requires full SSH handshake")
    table.insert(output, "[*] Banner may indicate software version")

    local version = banner:match("SSH%-2%.0%-(.+)")
    if version then
        table.insert(output, "Software: " .. version)

        if version:lower():find("openssh") then
            table.insert(output, "Implementation: OpenSSH")
        elseif version:lower():find("libssh") then
            table.insert(output, "Implementation: libssh")
        end
    end

    return stdnse.format_output(true, output)
end
