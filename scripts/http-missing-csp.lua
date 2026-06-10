-- Missing Content-Security-Policy Detection
-- Checks for missing CSP header

local http = require("http")
local stdnse = require("stdnse")

description = [[
Checks for missing Content-Security-Policy (CSP) header which
is essential for preventing XSS and data injection attacks.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "web"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080)
end

action = function(host, port)
    local output = {}
    local response = http.get(host.ip, port, "/")

    if not response then
        return "No HTTP response received"
    end

    table.insert(output, "Content-Security-Policy Check")
    table.insert(output, "")

    local csp = response.header and response.header["content-security-policy"]
    local csp_report = response.header and response.header["content-security-policy-report-only"]

    if csp then
        table.insert(output, "[+] CSP Header Present: " .. csp)
        return stdnse.format_output(true, output)
    end

    if csp_report then
        table.insert(output, "[!] CSP Report-Only (not enforcing): " .. csp_report)
        table.insert(output, "")
        table.insert(output, "[!] MEDIUM: CSP is in report-only mode, not enforcing")
        return stdnse.format_output(true, output)
    end

    local x_webkit = response.header and response.header["x-webkit-csp"]
    if x_webkit then
        table.insert(output, "[!] Legacy X-WebKit-CSP: " .. x_webkit)
        return stdnse.format_output(true, output)
    end

    table.insert(output, "[-] Content-Security-Policy: MISSING")
    table.insert(output, "")
    table.insert(output, "[!] MEDIUM: No CSP header configured")
    table.insert(output, "[!] Add CSP to prevent XSS and data injection attacks")

    return stdnse.format_output(true, output)
end
