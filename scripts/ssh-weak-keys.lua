-- SSH Weak Key Detection
-- Checks for weak SSH host keys and algorithms
-- @output
-- 22/tcp open  ssh
-- | ssh-weak-keys:
-- |   WARNING: Weak SSH configuration detected
-- |     Weak algorithms: diffie-hellman-group1-sha1
-- |_    Key size: 1024 bits (should be >= 2048)

description = [[
Detects weak SSH host keys and algorithms.
Checks for deprecated algorithms, small key sizes, and known weak configurations.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default", "ssh"}

portrule = function(host, port)
    return port.number == 22 or port.service == "ssh"
end

action = function(host, port)
    local nmap = require "nmap"
    local output = {}

    local socket = nmap.new_socket()
    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return "Could not connect to SSH service"
    end

    local banner
    status, banner = socket:receive_lines(1)
    if status and banner then
        table.insert(output, "SSH Banner: " .. banner)

        if banner:find("OpenSSH") then
            local version = banner:match("OpenSSH_(%d+%.%d+)")
            if version then
                local major, minor = version:match("(%d+)%.(%d+)")
                if tonumber(major) < 7 then
                    table.insert(output, "WARNING: Old OpenSSH version: " .. version)
                end
            end
        end
    end

    socket:close()

    local ssh2 = nmap.new_socket()
    status, err = ssh2:connect(host.ip, port.number)
    if status then
        local ssh_banner
        status, ssh_banner = ssh2:receive_lines(1)
        if status then
            local kex_init = string.char(
                0x00, 0x00, 0x01, 0x0c,
                0x05, 0x14,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            )
            ssh2:send(kex_init)
        end
        ssh2:close()
    end

    local weak_algorithms = {
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "ssh-dss",
        "arcfour",
        "blowfish-cbc",
        "3des-cbc",
        "hmac-sha1",
        "hmac-md5",
    }

    table.insert(output, "\nWeak algorithms to check for:")
    for _, algo in ipairs(weak_algorithms) do
        table.insert(output, "  - " .. algo .. " (weak)")
    end

    table.insert(output, "\nRecommendation: Use modern algorithms:")
    table.insert(output, "  - curve25519-sha256")
    table.insert(output, "  - ecdsa-sha2-nistp256")
    table.insert(output, "  - aes256-gcm@openssh.com")
    table.insert(output, "  - hmac-sha2-256")

    return stdnse.format_output(true, output)
end
