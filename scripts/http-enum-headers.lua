-- HTTP Header Enumeration
-- Analyzes all HTTP response headers for information

local http = require("http")
local stdnse = require("stdnse")

description = [[
Enumerates and analyzes all HTTP response headers for security
issues, technology disclosure, and configuration problems.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080)
end

action = function(host, port)
    local output = {}
    local response = http.get(host.ip, port, "/")

    if not response or not response.header then
        return "No HTTP response received"
    end

    table.insert(output, "HTTP Header Enumeration")
    table.insert(output, "")

    local security_headers = {
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "x-xss-protection",
        "referrer-policy",
        "permissions-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "cross-origin-embedder-policy",
    }

    local disclosure_headers = {
        "server", "x-powered-by", "x-aspnet-version",
        "x-aspnetmvc-version", "x-runtime", "x-generator",
        "x-drupal-cache", "x-varnish", "via",
    }

    table.insert(output, "Security Headers:")
    for _, h in ipairs(security_headers) do
        local value = response.header[h]
        if value then
            table.insert(output, "  [+] " .. h .. ": " .. value)
        else
            table.insert(output, "  [-] " .. h .. ": NOT SET")
        end
    end

    table.insert(output, "")
    table.insert(output, "Disclosure Headers:")
    for _, h in ipairs(disclosure_headers) do
        local value = response.header[h]
        if value then
            table.insert(output, "  [!] " .. h .. ": " .. value)
        end
    end

    table.insert(output, "")
    table.insert(output, "All Headers:")
    for k, v in pairs(response.header) do
        table.insert(output, "  " .. k .. ": " .. v)
    end

    return stdnse.format_output(true, output)
end
