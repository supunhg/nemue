-- CSP Bypass Techniques
-- Analyzes Content-Security-Policy headers for bypass opportunities

local http = require("http")
local stdnse = require("stdnse")
local string = require("string")

description = [[
Analyzes Content-Security-Policy headers to identify potential
bypass techniques and misconfigurations.
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

    local csp = response.header["content-security-policy"]
    local csp_report = response.header["content-security-policy-report-only"]

    if not csp and not csp_report then
        table.insert(output, "No CSP header found")
        table.insert(output, "[!] Application is vulnerable to XSS without CSP protection")
        return stdnse.format_output(true, output)
    end

    local policy = csp or csp_report
    table.insert(output, "CSP Policy Found:")
    table.insert(output, policy)

    local bypasses = {}

    if policy:find("unsafe%-inline") then
        table.insert(bypasses, "unsafe-inline allows inline script execution")
    end

    if policy:find("unsafe%-eval") then
        table.insert(bypasses, "unsafe-eval allows eval() execution")
    end

    if policy:find("%*") then
        table.insert(bypasses, "Wildcard source allows any origin")
    end

    if policy:find("data:") then
        table.insert(bypasses, "data: URIs can be used to inject content")
    end

    if policy:find("blob:") then
        table.insert(bypasses, "blob: URIs can bypass CSP restrictions")
    end

    if policy:find("filesystem:") then
        table.insert(bypasses, "filesystem: URIs allow local file access")
    end

    if not policy:find("base%-uri") then
        table.insert(bypasses, "Missing base-uri directive allows base tag injection")
    end

    if not policy:find("object%-src") then
        table.insert(bypasses, "Missing object-src allows plugin-based attacks")
    end

    if not policy:find("frame%-ancestors") then
        table.insert(bypasses, "Missing frame-ancestors allows clickjacking")
    end

    if #bypasses > 0 then
        table.insert(output, "\n[!] CSP Bypass Opportunities:")
        for _, bypass in ipairs(bypasses) do
            table.insert(output, "  * " .. bypass)
        end
    else
        table.insert(output, "\n[+] CSP policy appears well-configured")
    end

    return stdnse.format_output(true, output)
end
