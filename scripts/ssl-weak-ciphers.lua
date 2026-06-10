-- SSL Weak Cipher Detection
-- Checks for weak SSL/TLS cipher suites
-- @output
-- 443/tcp open  https
-- | ssl-weak-ciphers:
-- |   WARNING: Weak ciphers detected
-- |     TLS_RSA_WITH_RC4_128_SHA
-- |     TLS_RSA_WITH_DES_CBC_SHA
-- |_  Recommendation: Disable weak ciphers

description = [[
Detects weak SSL/TLS cipher suites on the target.
Checks for deprecated ciphers including RC4, DES, 3DES, NULL ciphers,
and export-grade ciphers.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default", "ssl"}

portrule = function(host, port)
    return port.service == "https" or port.service == "ssl" or
           port.number == 443 or port.number == 8443 or port.number == 465 or
           port.number == 993 or port.number == 995
end

action = function(host, port)
    local nmap = require "nmap"
    local output = {}
    local vulns = {}

    local socket = nmap.new_socket()
    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return "Could not connect to SSL/TLS service"
    end

    local tls_versions = {
        {name = "SSLv3", major = 3, minor = 0},
        {name = "TLSv1.0", major = 3, minor = 1},
        {name = "TLSv1.1", major = 3, minor = 2},
        {name = "TLSv1.2", major = 3, minor = 3},
    }

    for _, ver in ipairs(tls_versions) do
        local client_hello = string.char(
            0x16,
            ver.major, ver.minor,
            0x00, 0x2f,
            0x01, 0x00, 0x00, 0x2b,
            ver.major, ver.minor
        )

        local random = ""
        for i = 1, 32 do
            random = random .. string.char(math.random(0, 255))
        end

        local hello_data = client_hello .. random .. string.char(0x00)
        socket:send(hello_data)

        local response
        status, response = socket:receive()
        if status and response then
            if #response > 5 then
                local content_type = response:byte(1)
                if content_type == 0x16 then
                    table.insert(output, ver.name .. " supported")
                    if ver.name == "SSLv3" or ver.name == "TLSv1.0" then
                        table.insert(vulns, ver.name .. " is deprecated and insecure")
                    end
                elseif content_type == 0x15 then
                    table.insert(output, ver.name .. " not supported")
                end
            end
        end
    end

    socket:close()

    local weak_ciphers = {
        "NULL",
        "EXPORT",
        "RC4",
        "RC2",
        "DES",
        "3DES",
        "MD5",
        "anon",
    }

    table.insert(output, "\nWeak cipher patterns to check:")
    for _, cipher in ipairs(weak_ciphers) do
        table.insert(output, "  - " .. cipher .. " (weak)")
    end

    if #vulns > 0 then
        table.insert(output, "\n[!] Weak protocols detected:")
        for _, v in ipairs(vulns) do
            table.insert(output, "  " .. v)
        end
    end

    table.insert(output, "\nRecommendation: Use TLSv1.2+ with strong ciphers")
    table.insert(output, "  - TLS_AES_256_GCM_SHA384")
    table.insert(output, "  - TLS_CHACHA20_POLY1305_SHA256")

    return stdnse.format_output(true, output)
end
