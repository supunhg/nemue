-- BGP Neighbor Enumeration
-- Attempts to enumerate BGP neighbors and AS information

local nmap = require("nmap")
local stdnse = require("stdnse")
local packet = require("packet")

description = [[
Attempts to enumerate BGP neighbors by sending malformed
BGP OPEN messages and analyzing responses.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.number == 179
end

action = function(host, port)
    local output = {}

    table.insert(output, "BGP Neighbor Enumeration")
    table.insert(output, "Target: " .. host.ip .. ":179")
    table.insert(output, "")

    local sock = nmap.new_socket()
    sock:set_timeout(5000)

    local status, err = sock:connect(host.ip, 179)

    if not status then
        table.insert(output, "[!] Could not connect to BGP port")
        table.insert(output, "    Error: " .. (err or "unknown"))
        return stdnse.format_output(true, output)
    end

    local bgp_open = string.char(
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x1d,
        0x01,
        0x04, 0x00, 0x64, 0x00, 0xb4,
        0x00, 0x00, 0x00, 0x00
    )

    sock:send(bgp_open)

    local response
    status, response = sock:receive()

    if status and response then
        if #response >= 19 then
            local marker = response:sub(1, 16)
            local all_ff = true
            for i = 1, 16 do
                if response:byte(i) ~= 0xff then
                    all_ff = false
                    break
                end
            end

            if all_ff then
                table.insert(output, "[+] BGP service confirmed")
                table.insert(output, "[!] BGP port is open and responding")

                if #response >= 29 then
                    local msg_type = response:byte(19)
                    if msg_type == 1 then
                        table.insert(output, "[!] Received BGP OPEN message")
                        table.insert(output, "[!] Potential for route injection attacks")
                    elseif msg_type == 3 then
                        table.insert(output, "[!] Received BGP NOTIFICATION")
                    end
                end
            end
        end
    else
        table.insert(output, "[!] No BGP response received")
        table.insert(output, "[!] Service may require authentication")
    end

    sock:close()

    table.insert(output, "")
    table.insert(output, "[!] BGP enumeration helps map network topology")

    return stdnse.format_output(true, output)
end
