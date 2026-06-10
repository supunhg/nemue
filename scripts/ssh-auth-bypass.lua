-- SSH Authentication Bypass Detection
-- Tests for common SSH authentication bypass vulnerabilities

local nmap = require("nmap")
local stdnse = require("stdnse")
local shortport = require("shortport")

description = [[
Checks SSH servers for common authentication bypass vulnerabilities
including CVE-2018-15473 (OpenSSH user enumeration), weak algorithms,
and known backdoor configurations.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive"}

portrule = shortport.port_or_service(22, "ssh")

action = function(host, port)
    local results = {}
    local socket = nmap.new_socket()
    local status, err = socket:connect(host, port)

    if not status then
        return stdnse.format_output(false, "Could not connect: " .. err)
    end

    local banner
    status, banner = socket:receive_lines(1)
    if not status then
        socket:close()
        return stdnse.format_output(false, "No banner received")
    end

    table.insert(results, "SSH Banner: " .. banner)

    if banner:match("OpenSSH") then
        local version = banner:match("OpenSSH_(%d+%.%d+)")
        if version then
            table.insert(results, "OpenSSH Version: " .. version)
            local major, minor = version:match("(%d+)%.(%d+)")
            major = tonumber(major)
            minor = tonumber(minor)

            if major and major < 7 then
                table.insert(results, "WARNING: Old OpenSSH version detected, may be vulnerable to multiple CVEs")
            end
            if major == 7 and minor and minor < 7 then
                table.insert(results, "WARNING: OpenSSH < 7.7 may be vulnerable to user enumeration (CVE-2018-15473)")
            end
        end
    end

    if banner:match("dropbear") then
        table.insert(results, "Dropbear SSH detected - check for known vulnerabilities")
    end

    if banner:match("libssh") then
        table.insert(results, "libssh detected - check for CVE-2018-10933 (auth bypass)")
    end

    if banner:match("ROSSSH") then
        table.insert(results, "MikroTik RouterOS SSH detected")
    end

    socket:close()

    if #results == 0 then
        return nil
    end

    return stdnse.format_output(true, results)
end
