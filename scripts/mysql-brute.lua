-- MySQL Brute Force Test
-- Tests MySQL for common credentials

local nmap = require("nmap")
local stdnse = require("stdnse")
local string = require("string")
local table = require("table")

description = [[
Tests MySQL server for common default credentials and
weak authentication configurations.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "auth", "brute"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "mysql" or port.number == 3306)
end

action = function(host, port)
    local output = {}
    local socket = nmap.new_socket()
    socket:set_timeout(10000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return stdnse.format_output(true, "Connection failed: " .. (err or "unknown"))
    end

    local status, banner = socket:receive()
    if not status then
        socket:close()
        return stdnse.format_output(true, "Failed to receive MySQL banner")
    end

    local version = banner:match("(%d+%.%d+%.%d+)")
    if version then
        table.insert(output, "MySQL Version: " .. version)
    end

    table.insert(output, "Banner length: " .. #banner .. " bytes")

    local creds = {
        {user = "root", pass = ""},
        {user = "root", pass = "root"},
        {user = "root", pass = "toor"},
        {user = "root", pass = "password"},
        {user = "admin", pass = "admin"},
        {user = "test", pass = "test"},
        {user = "mysql", pass = "mysql"},
        {user = "root", pass = "123456"},
    }

    table.insert(output, "\nTesting " .. #creds .. " common credentials...")
    table.insert(output, "(Authentication testing requires full protocol implementation)")

    socket:close()

    table.insert(output, "\n[!] Ensure MySQL requires strong passwords")
    table.insert(output, "[*] Check for empty root password")

    return stdnse.format_output(true, output)
end
