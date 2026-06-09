-- VNC Authentication Check
-- Checks VNC authentication type and security

local nmap = require("nmap")
local stdnse = require("stdnse")

description = [[
Connects to VNC server and identifies the authentication type.
Reports if no authentication is available.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 5900 or port.number == 5901 or port.service == "vnc")
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
        table.insert(output, "VNC Protocol Version: " .. banner)

        local version = banner:match("RFB (%d+%.%d+)")
        if version then
            table.insert(output, "Version: " .. version)
        end
    end

    if version and tonumber(version) >= 3.7 then
        local sec_types
        status, sec_types = socket:receive_buf("\n", true)

        if status and sec_types then
            local num_types = sec_types:byte(1)
            table.insert(output, "\nSecurity Types (" .. num_types .. "):")

            for i = 2, num_types + 1 do
                local sec_type = sec_types:byte(i)
                local type_name = "Unknown"

                if sec_type == 0 then type_name = "Invalid"
                elseif sec_type == 1 then type_name = "None (No Authentication)"
                elseif sec_type == 2 then type_name = "VNC Authentication"
                elseif sec_type == 5 then type_name = "RA2"
                elseif sec_type == 6 then type_name = "RA2ne"
                elseif sec_type == 16 then type_name = "Tight"
                elseif sec_type == 17 then type_name = "Ultra"
                elseif sec_type == 18 then type_name = "TLS"
                end

                table.insert(output, "  " .. sec_type .. ": " .. type_name)

                if sec_type == 1 then
                    table.insert(output, "\n[!] CRITICAL: No authentication required!")
                    table.insert(output, "  Anyone can connect without credentials")
                end
            end
        end
    end

    socket:close()

    return stdnse.format_output(true, output)
end
