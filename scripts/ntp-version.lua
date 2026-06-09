local nmap = require("nmap")
local stdnse = require("stdnse")
local bin = require("bin")

description = [[
Queries NTP server for version and configuration information using
the NTP monlist or standard NTP queries.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "udp" and port.number == 123
end

action = function(host, port)
    local output = {}
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host, port, "udp")
    if not status then
        return stdnse.format_output(false, "Could not connect: " .. err)
    end

    local ntp_request = bin.pack("H", "1b000000000000000000000000000000" ..
        "00000000000000000000000000000000" ..
        "00000000000000000000000000000000" ..
        "0000000000000000")

    status = socket:send(ntp_request)
    if not status then
        socket:close()
        return stdnse.format_output(false, "Failed to send NTP request")
    end

    local response
    status, response = socket:receive()
    socket:close()

    if not status or not response then
        return stdnse.format_output(false, "No NTP response received")
    end

    if #response < 48 then
        return stdnse.format_output(false, "Invalid NTP response")
    end

    local stratum = string.byte(response, 2)
    local version = bit.rshift(string.byte(response, 1), 3) % 8

    table.insert(output, "NTP Server Information:")
    table.insert(output, "  Version: NTPv" .. version)
    table.insert(output, "  Stratum: " .. stratum)

    if stratum == 0 then
        table.insert(output, "  Type: Kiss-o'-Death (unspecified)")
    elseif stratum == 1 then
        table.insert(output, "  Type: Primary reference")
    elseif stratum <= 15 then
        table.insert(output, "  Type: Secondary reference")
    else
        table.insert(output, "  Type: Reserved/Unsynchronized")
    end

    local precision = string.byte(response, 4)
    if precision > 128 then
        precision = precision - 256
    end
    table.insert(output, "  Precision: 2^" .. precision .. " seconds")

    return stdnse.format_output(true, output)
end
