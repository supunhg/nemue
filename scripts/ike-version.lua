local nmap = require("nmap")
local stdnse = require("stdnse")
local bin = require("bin")

description = [[
Detects IKE/IPSec version and supported authentication methods
by sending IKE phase 1 proposals.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "udp" and port.number == 500
end

action = function(host, port)
    local output = {}
    local issues = {}

    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host, port, "udp")
    if not status then
        return stdnse.format_output(false, "Could not connect: " .. err)
    end

    local ike_sa = bin.pack("H",
        "00000000" ..
        "00000000" ..
        "00000000" ..
        "00000000" ..
        "00000000" ..
        "00000000" ..
        "00000000" ..
        "00000000" ..
        "00112233" ..
        "0110" ..
        "0000000000000000" ..
        "0000000000000000" ..
        "00000001" ..
        "00000001" ..
        "0000000000000000"
    )

    status = socket:send(ike_sa)
    if not status then
        socket:close()
        return stdnse.format_output(false, "Failed to send IKE proposal")
    end

    local response
    status, response = socket:receive()
    socket:close()

    if not status or not response then
        table.insert(output, "No IKE response received (port may not be IKE)")
        return stdnse.format_output(true, output)
    end

    if #response < 28 then
        return stdnse.format_output(false, "Invalid IKE response")
    end

    table.insert(output, "IKE/IPSec Information:")

    local next_payload = string.byte(response, 19)
    local version = string.byte(response, 20)
    local exchange_type = string.byte(response, 21)

    table.insert(output, "  IKE Version: " .. (version == 0x10 and "IKEv1" or "IKEv2 (0x" .. string.format("%02x", version) .. ")"))

    local exchange_types = {
        [2] = "Identity Protection (Main Mode)",
        [4] = "Aggressive Mode",
        [5] = "Informational",
        [34] = "IKEv2 (SA_INIT)",
    }
    table.insert(output, "  Exchange Type: " .. (exchange_types[exchange_type] or "Unknown (" .. exchange_type .. ")"))

    if exchange_type == 4 then
        table.insert(issues, "Aggressive mode detected - may expose PSK hash")
    end

    local flags = string.byte(response, 22)
    if bit.band(flags, 0x01) == 0x01 then
        table.insert(output, "  Encryption: Enabled")
    end

    table.insert(output, "\nRecommendations:")
    table.insert(output, "  - Use IKEv2 with strong proposals")
    table.insert(output, "  - Avoid aggressive mode")
    table.insert(output, "  - Use certificate-based authentication")

    if #issues > 0 then
        table.insert(output, "\nIssues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    end

    return stdnse.format_output(true, output)
end
