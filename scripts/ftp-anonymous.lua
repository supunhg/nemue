-- FTP Anonymous Access Test
-- Tests FTP server for anonymous login capability

local nmap = require("nmap")
local stdnse = require("stdnse")
local string = require("string")
local table = require("table")

description = [[
Tests if an FTP server allows anonymous login and enumerates
accessible directories and files.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "auth", "vuln"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "ftp" or port.number == 21)
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
    if status then
        table.insert(output, "FTP Banner: " .. banner)
    end

    socket:send("USER anonymous\r\n")
    local status, response = socket:receive_lines(1)
    if not status then
        socket:close()
        return stdnse.format_output(true, "Failed to send USER command")
    end

    table.insert(output, "USER Response: " .. response)

    if response:match("^331") then
        socket:send("PASS anonymous@\r\n")
        local status, response = socket:receive_lines(1)
        if status then
            table.insert(output, "PASS Response: " .. response)

            if response:match("^230") then
                table.insert(output, "\n[!] ANONYMOUS FTP LOGIN ALLOWED")
                table.insert(output, "Severity: HIGH")

                socket:send("SYST\r\n")
                local status, syst = socket:receive_lines(1)
                if status then
                    table.insert(output, "System: " .. syst)
                end

                socket:send("PWD\r\n")
                local status, pwd = socket:receive_lines(1)
                if status then
                    table.insert(output, "Current Dir: " .. pwd)
                end

                socket:send("LIST\r\n")
                local status, list = socket:receive_lines(1)
                if status then
                    table.insert(output, "LIST Response: " .. list)
                end
            else
                table.insert(output, "\nAnonymous login denied")
            end
        end
    elseif response:match("^530") then
        table.insert(output, "\nAnonymous login not allowed")
    end

    socket:close()
    return stdnse.format_output(true, output)
end
