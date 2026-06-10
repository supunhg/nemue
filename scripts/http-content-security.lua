local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Analyzes Content-Security-Policy (CSP) header for common misconfigurations,
weak directives, and missing protections.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or port.number == 8080)
end

local dangerous_sources = {
    "'unsafe%-inline'",
    "'unsafe%-eval'",
    "%*",
    "data:",
    "http://",
}

action = function(host, port)
    local output = {}
    local issues = {}

    local response = http.get(host, port, "/")

    if not response or not response.header then
        return stdnse.format_output(false, "Could not retrieve HTTP response")
    end

    local csp = response.header["content-security-policy"]
    local csp_report = response.header["content-security-policy-report-only"]

    if not csp and not csp_report then
        table.insert(issues, "CRITICAL: No Content-Security-Policy header found")
    else
        local policy = csp or csp_report
        if csp_report and not csp then
            table.insert(output, "CSP is report-only (not enforced)")
        end

        table.insert(output, "CSP Policy: " .. policy)

        for _, source in ipairs(dangerous_sources) do
            if policy:find(source) then
                table.insert(issues, "Dangerous source found: " .. source)
            end
        end

        if not policy:lower():find("default%-src") and not policy:lower():find("script%-src") then
            table.insert(issues, "Missing default-src and script-src directives")
        end

        if not policy:lower():find("frame%-ancestors") then
            table.insert(issues, "Missing frame-ancestors directive (clickjacking protection)")
        end

        if not policy:lower():find("base%-uri") then
            table.insert(issues, "Missing base-uri directive")
        end
    end

    if #issues > 0 then
        table.insert(output, "\nCSP Issues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    else
        table.insert(output, "\nCSP appears properly configured")
    end

    return stdnse.format_output(true, output)
end
