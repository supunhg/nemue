-- DHCP Information Gathering
-- Collects DHCP server information and configuration

local nmap = require("nmap")
local stdnse = require("stdnse")
local string = require("string")

description = [[
Sends DHCP INFORM requests to gather DHCP server
configuration and network information.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "udp" and
           (port.number == 67 or port.number == 68 or
            port.service == "dhcp")
end

action = function(host, port)
    local output = {}

    table.insert(output, "DHCP Information Gathering")
    table.insert(output, "Target: " .. host.ip)
    table.insert(output, "")

    local sock = nmap.new_socket("udp")
    sock:set_timeout(5000)

    local xid = math.random(0, 0xFFFFFFFF)

    local dhcp_packet = string.char(
        0x01, 0x01, 0x06, 0x00,
        bit.rshift(bit.band(xid, 0xFF000000), 24),
        bit.rshift(bit.band(xid, 0x00FF0000), 16),
        bit.rshift(bit.band(xid, 0x0000FF00), 8),
        bit.band(xid, 0x000000FF),
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x63, 0x82, 0x53, 0x63,
        0x35, 0x01, 0x08,
        0xff
    )

    local status, err = sock:sendto(host.ip, 67, dhcp_packet)

    if not status then
        table.insert(output, "[!] Failed to send DHCP request")
        sock:close()
        return stdnse.format_output(true, output)
    end

    local response
    status, response = sock:receive()

    if status and response then
        table.insert(output, "[+] DHCP server responded")

        if #response >= 240 then
            local yiaddr = string.format("%d.%d.%d.%d",
                response:byte(16), response:byte(17),
                response:byte(18), response:byte(19))
            table.insert(output, "Offered IP: " .. yiaddr)

            local siaddr = string.format("%d.%d.%d.%d",
                response:byte(20), response:byte(21),
                response:byte(22), response:byte(23))
            table.insert(output, "DHCP Server: " .. siaddr)

            local giaddr = string.format("%d.%d.%d.%d",
                response:byte(24), response:byte(25),
                response:byte(26), response:byte(27))
            if giaddr ~= "0.0.0.0" then
                table.insert(output, "Gateway: " .. giaddr)
            end
        end

        table.insert(output, "[!] DHCP server information disclosed")
    else
        table.insert(output, "[!] No DHCP response received")
    end

    sock:close()
    return stdnse.format_output(true, output)
end
