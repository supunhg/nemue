local nmap = require("nmap")
local stdnse = require("stdnse")

description = [[
Detects SSH servers using weak or deprecated algorithms for
key exchange, encryption, and MAC.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 22 or port.service == "ssh")
end

local weak_kex = {
    "diffie%-hellman%-group1%-sha1",
    "diffie%-hellman%-group14%-sha1",
    "diffie%-hellman%-group%-exchange%-sha1",
}

local weak_cipher = {
    "3des%-cbc",
    "arcfour",
    "blowfish%-cbc",
    "cast128%-cbc",
    "rc4",
}

local weak_mac = {
    "hmac%-md5",
    "hmac%-sha1%-96",
    "hmac%-md5%-96",
    "hmac%-ripemd160",
}

action = function(host, port)
    local output = {}
    local issues = {}

    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host, port)
    if not status then
        return stdnse.format_output(false, "Could not connect: " .. err)
    end

    local response
    status, response = socket:receive_lines(1)
    socket:close()

    if not status or not response then
        return stdnse.format_output(false, "No SSH banner received")
    end

    table.insert(output, "SSH Weak Algorithm Check:")
    table.insert(output, "  Banner: " .. response:gsub("\r?\n$", ""))

    local version = response:match("SSH%-([%.%d]+)")
    if version then
        table.insert(output, "  Protocol Version: " .. version)
        if version == "1.0" or version == "1.5" or version == "1.99" then
            table.insert(issues, "CRITICAL: SSHv1 protocol detected")
        end
    end

    local banner_lower = response:lower()

    for _, kex in ipairs(weak_kex) do
        if banner_lower:find(kex) then
            table.insert(issues, "Weak key exchange algorithm: " .. kex)
        end
    end

    table.insert(output, "\nNote: Full algorithm enumeration requires Nmap NSE")
    table.insert(output, "ssh2-enum-algos script for complete analysis.")

    table.insert(output, "\nRecommendations:")
    table.insert(output, "  - Disable SSHv1")
    table.insert(output, "  - Use curve25519-sha256 key exchange")
    table.insert(output, "  - Use aes256-gcm encryption")
    table.insert(output, "  - Use hmac-sha2-256 MAC")

    if #issues > 0 then
        table.insert(output, "\nIssues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    end

    return stdnse.format_output(true, output)
end
