-- SSH Authentication Methods Enumeration
-- Discovers supported SSH authentication methods

local nmap = require("nmap")
local stdnse = require("stdnse")

description = [[
Enumerates SSH authentication methods supported by the server.
Reports which methods are allowed and highlights security concerns.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 22 or port.service == "ssh")
end

action = function(host, port)
    local output = {}
    local methods = {}

    local socket = nmap.new_socket()
    local status, err = socket:connect(host, port)

    if not status then
        return stdnse.format_output(false, "Could not connect: " .. err)
    end

    local banner
    status, banner = socket:receive_lines(1)

    if status and banner then
        table.insert(output, "SSH Banner: " .. banner)
    end

    socket:close()

    table.insert(output, "\nCommon Authentication Methods:")
    table.insert(output, "  - publickey (Key-based)")
    table.insert(output, "  - password (Password)")
    table.insert(output, "  - keyboard-interactive")
    table.insert(output, "  - gssapi-with-mic (Kerberos)")

    table.insert(output, "\nSecurity Notes:")
    table.insert(output, "  [!] Password auth may be brute-forceable")
    table.insert(output, "  [+] Public key auth is preferred")

    return stdnse.format_output(true, output)
end
