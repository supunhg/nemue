-- NTP Monlist Amplification
-- Tests for NTP monlist amplification vulnerability

local nmap = require("nmap")
local stdnse = require("stdnse")
local string = require("string")

description = [[
Tests NTP servers for monlist amplification vulnerability
which can be used for DDoS amplification attacks.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "vuln"}

portrule = function(host, port)
    return port.protocol == "udp" and
           (port.number == 123 or port.service == "ntp")
end

action = function(host, port)
    local output = {}

    table.insert(output, "NTP Monlist Amplification Test")
    table.insert(output, "Target: " .. host.ip .. ":123")
    table.insert(output, "")

    local sock = nmap.new_socket("udp")
    sock:set_timeout(5000)

    local ntp_monlist = string.char(
        0x17, 0x00, 0x03, 0x2a,
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
        0x00, 0x00, 0x00, 0x00
    )

    local status, err = sock:sendto(host.ip, 123, ntp_monlist)

    if not status then
        table.insert(output, "[!] Failed to send NTP request")
        sock:close()
        return stdnse.format_output(true, output)
    end

    local response
    status, response = sock:receive()

    if status and response then
        if #response > 48 then
            local entries = math.floor((#response - 48) / 72)
            table.insert(output, "[!] VULNERABLE: NTP monlist enabled")
            table.insert(output, "    Response size: " .. #response .. " bytes")
            table.insert(output, "    Monlist entries: " .. entries)
            table.insert(output, "")
            table.insert(output, "[!] Amplification factor: " .. math.floor(#response / 48) .. "x")
            table.insert(output, "[!] Can be used for DDoS amplification attacks")
            table.insert(output, "[!] Recommendation: Disable monlist in ntp.conf")
        else
            table.insert(output, "[+] NTP responded but monlist may be disabled")
            table.insert(output, "    Response size: " .. #response .. " bytes")
        end
    else
        table.insert(output, "[+] No response to monlist request")
        table.insert(output, "[+] Server may not be vulnerable")
    end

    sock:close()
    return stdnse.format_output(true, output)
end
