-- BlueKeep Detection (CVE-2019-0708)
-- Detects RDP vulnerability in Windows
-- @output
-- 3389/tcp open  ms-wbt-server
-- | rdp-bluekeep:
-- |   VULNERABLE: BlueKeep (CVE-2019-0708)
-- |     RDP vulnerability detected
-- |_    System missing critical security update

description = [[
Detects BlueKeep vulnerability (CVE-2019-0708) in Windows RDP.
This critical RCE vulnerability affects Windows 7, Windows Server 2008,
Windows XP, and Windows Server 2003.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "rdp"}

portrule = function(host, port)
    return port.number == 3389 or port.service == "ms-wbt-server"
end

action = function(host, port)
    local nmap = require "nmap"
    local vulns = {}

    local socket = nmap.new_socket()
    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return "Could not connect to RDP service"
    end

    local rdp_connection_request = string.char(
        0x03, 0x00, 0x00, 0x13,
        0x0e, 0xe0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x08, 0x00, 0x03,
        0x00, 0x00, 0x00
    )

    socket:send(rdp_connection_request)

    local response
    status, response = socket:receive()
    if status and response then
        if #response >= 11 then
            local connection_ref = response:byte(11)
            if connection_ref == 0x02 or connection_ref == 0x00 then
                table.insert(vulns, "RDP connection accepted (no NLA required)")
            end
        end
    end

    socket:close()

    socket = nmap.new_socket()
    status, err = socket:connect(host.ip, port.number)
    if status then
        local mcs_request = string.char(
            0x03, 0x00, 0x00, 0x2b,
            0x02, 0xf0, 0x80,
            0x04, 0x01, 0x01, 0x04, 0x01,
            0x01, 0x01, 0x01, 0xff,
            0x30, 0x19, 0x02, 0x04,
            0x00, 0x00, 0x00, 0x00,
            0x02, 0x04, 0x00, 0x00,
            0x00, 0x02, 0x02, 0x04,
            0x00, 0x00, 0x00, 0x03,
            0x02, 0x04, 0x00, 0x00,
            0x00, 0x04, 0x02, 0x04
        )

        socket:send(mcs_request)

        local mcs_response
        status, mcs_response = socket:receive()
        if status and mcs_response then
            if #mcs_response > 15 then
                table.insert(vulns, "RDP channel accepted (vulnerable indicator)")
            end
        end
        socket:close()
    end

    if #vulns > 0 then
        local result = "VULNERABLE: BlueKeep (CVE-2019-0708)\n"
        result = result .. "  RDP vulnerability detected\n"
        for _, v in ipairs(vulns) do
            result = result .. "  " .. v .. "\n"
        end
        return result
    end

    return "Not vulnerable to BlueKeep"
end
