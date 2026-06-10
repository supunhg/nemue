-- Missing Security Headers
-- Checks for missing HTTP security headers

local http = require("http")
local stdnse = require("stdnse")

description = [[
Analyzes HTTP responses for missing security headers
that could leave the application vulnerable.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "web"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080 or port.number == 8443)
end

action = function(host, port)
    local output = {}
    local response = http.get(host.ip, port, "/")

    if not response or not response.header then
        return "No HTTP response received"
    end

    local headers = response.header

    local security_headers = {
        {"Strict-Transport-Security", "HSTS not set - vulnerable to downgrade attacks"},
        {"X-Content-Type-Options", "Missing - allows MIME type sniffing"},
        {"X-Frame-Options", "Missing - vulnerable to clickjacking"},
        {"X-XSS-Protection", "Missing - no XSS filter in older browsers"},
        {"Content-Security-Policy", "Missing - no CSP protection"},
        {"Referrer-Policy", "Missing - may leak referrer information"},
        {"Permissions-Policy", "Missing - no feature policy restrictions"},
        {"Cross-Origin-Embedder-Policy", "Missing - no COEP protection"},
        {"Cross-Origin-Opener-Policy", "Missing - no COOP protection"},
        {"Cross-Origin-Resource-Policy", "Missing - no CORP protection"}
    }

    table.insert(output, "Security Headers Analysis")
    table.insert(output, "")

    local missing = 0

    for _, header in ipairs(security_headers) do
        local name = header[1]
        local desc = header[2]

        if headers[name:lower()] then
            table.insert(output, "[+] " .. name .. ": Present")
        else
            table.insert(output, "[!] " .. name .. ": Missing - " .. desc)
            missing = missing + 1
        end
    end

    table.insert(output, "")
    table.insert(output, "Missing Headers: " .. missing .. "/" .. #security_headers)

    if missing > 0 then
        table.insert(output, "[!] Application lacks important security headers")
    else
        table.insert(output, "[+] All security headers are present")
    end

    return stdnse.format_output(true, output)
end
