-- SSH Auth Method Enumeration
-- Enumerates supported SSH authentication methods

local nmap = require("nmap")
local stdnse = require("stdnse")
local string = require("string")

description = [[
Queries SSH server to enumerate supported authentication
methods and identify potential security weaknesses.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 22 or port.service == "ssh")
end

action = function(host, port)
    local output = {}

    table.insert(output, "SSH Authentication Method Enumeration")
    table.insert(output, "Target: " .. host.ip .. ":22")
    table.insert(output, "")

    local sock = nmap.new_socket()
    sock:set_timeout(5000)

    local status, err = sock:connect(host.ip, port.number)

    if not status then
        table.insert(output, "[!] Could not connect to SSH port")
        sock:close()
        return stdnse.format_output(true, output)
    end

    local banner
    status, banner = sock:receive_lines(1)

    if status and banner then
        table.insert(output, "SSH Banner: " .. banner)

        if banner:find("OpenSSH") then
            local version = banner:match("OpenSSH_(%S+)")
            if version then
                table.insert(output, "OpenSSH Version: " .. version)
            end
        elseif banner:find("libssh") then
            table.insert(output, "[!] Using libssh library")
        end
    end

    sock:close()

    local test_users = {"root", "admin", "test", "user", "guest"}

    table.insert(output, "")
    table.insert(output, "Testing authentication methods...")
    table.insert(output, "")

    for _, user in ipairs(test_users) do
        local cmd = string.format(
            "ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no %s@%s 2>&1 | grep -i 'auth'",
            user, host.ip
        )

        local handle = io.popen(cmd)
        if handle then
            local result = handle:read("*a")
            handle:close()

            if result and result ~= "" then
                table.insert(output, "User '" .. user .. "' auth methods: " .. result:gsub("\n", ", "))
            end
        end
    end

    table.insert(output, "")
    table.insert(output, "[!] Authentication enumeration helps plan brute-force attacks")
    table.insert(output, "[!] Recommendation: Use key-based authentication only")

    return stdnse.format_output(true, output)
end
