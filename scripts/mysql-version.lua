-- MySQL Version Detection
-- Gets MySQL server version and configuration

local nmap = require("nmap")
local stdnse = require("stdnse")

description = [[
Connects to MySQL server and extracts version information,
server capabilities, and security configuration.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 3306 or port.service == "mysql")
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
        table.insert(output, "MySQL Server Information:")
        table.insert(output, "  Banner: " .. banner)

        local version = banner:match("(%d+%.%d+%.%d+)")
        if version then
            table.insert(output, "  Version: " .. version)
        end

        local major = tonumber(banner:match("^(%d+)"))
        if major then
            table.insert(output, "  Major Version: " .. major)

            if major < 5 then
                table.insert(output, "\n[!] CRITICAL: Very old MySQL version")
            elseif major == 5 then
                local minor = tonumber(banner:match("^%d+%.(%d+)"))
                if minor and minor < 7 then
                    table.insert(output, "\n[!] WARNING: Old MySQL version")
                end
            end
        end

        if banner:find("MariaDB") then
            table.insert(output, "  Variant: MariaDB")
        elseif banner:find("Percona") then
            table.insert(output, "  Variant: Percona Server")
        else
            table.insert(output, "  Variant: MySQL")
        end
    end

    socket:close()

    return stdnse.format_output(true, output)
end
